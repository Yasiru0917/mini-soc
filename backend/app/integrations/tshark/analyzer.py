"""Summarise a packet capture with TShark (Wireshark's command-line engine).

We ask TShark for a few fields per packet and do the statistics in Python:
protocol mix, top talkers, conversations, DNS queries, and TCP SYN packets
for port-scan detection (rule R-006).

SAFETY - a pcap is untrusted input parsed by complex dissector code:
  * -n            : no name resolution, so analysing a file never triggers
                    DNS lookups to attacker-chosen domains.
  * -c LIMIT      : read at most N packets.
  * timeout       : the process is killed if it takes too long.
  * isolated profile: WIRESHARK_CONFIG_DIR points at an empty temp folder, so
                    no personal Wireshark plugins/Lua scripts are loaded.
  * argument list, no shell, as with Nmap.
"""

import os
import subprocess  # noqa: S404
import tempfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from app.detection.events import Detection
from app.detection.rules import RULES
from app.integrations.base import resolve_binary

MAX_PACKETS = 500_000
PORT_SCAN_THRESHOLD = 20

FIELDS = ["frame.time_epoch", "ip.src", "ip.dst", "_ws.col.Protocol", "tcp.dstport", "udp.dstport",
          "tcp.flags.syn", "tcp.flags.ack", "dns.qry.name", "dns.flags.response", "frame.len",
          "ipv6.src", "ipv6.dst"]


class TsharkError(RuntimeError):
    pass


def build_command(tshark_path: str, pcap: Path) -> list[str]:
    exe = resolve_binary(tshark_path)
    if exe is None:
        raise TsharkError(f"TShark not found ('{tshark_path}'). Install Wireshark or set TSHARK_PATH in .env.")
    cmd = [exe, "-n", "-r", str(pcap), "-c", str(MAX_PACKETS), "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    return cmd


def run_tshark(cmd: list[str], timeout: int) -> str:
    with tempfile.TemporaryDirectory(prefix="minisoc-ws-") as profile_dir:
        env = {**os.environ, "WIRESHARK_CONFIG_DIR": profile_dir}
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",  # noqa: S603
                                    timeout=timeout, check=False, env=env)
        except subprocess.TimeoutExpired:
            raise TsharkError(f"TShark timed out after {timeout} seconds.") from None
        except OSError as exc:
            raise TsharkError(f"Could not start TShark: {exc.strerror or exc}") from None
    if result.returncode != 0 and not result.stdout:
        raise TsharkError(f"TShark failed (code {result.returncode}): {result.stderr.strip()[-400:]}")
    return result.stdout


def _flag(value: str) -> bool:
    return value in ("1", "True", "true")


def summarise(tsv: str) -> tuple[dict, list[Detection]]:
    protocols: Counter = Counter()
    talkers_pkts: Counter = Counter()
    talkers_bytes: Counter = Counter()
    conversations: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    dns_queries: Counter = Counter()
    syn_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    syn_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    packets = total_bytes = 0
    first = last = None

    for line in tsv.splitlines():
        cols = line.split("\t")
        if len(cols) < len(FIELDS):
            cols += [""] * (len(FIELDS) - len(cols))
        epoch, src, dst, proto, tport, uport, syn, ack, qname, is_resp, length, src6, dst6 = cols[:13]
        src, dst = src or src6, dst or dst6
        packets += 1
        size = int(length) if length.isdigit() else 0
        total_bytes += size
        try:
            t = float(epoch)
            first = t if first is None else min(first, t)
            last = t if last is None else max(last, t)
        except ValueError:
            t = None
        protocols[proto or "unknown"] += 1
        if src:
            talkers_pkts[src] += 1
            talkers_bytes[src] += size
        if src and dst:
            conv = conversations[tuple(sorted((src, dst)))]
            conv[0] += 1
            conv[1] += size
        if qname and not _flag(is_resp):
            dns_queries[qname.lower()[:253]] += 1
        if src and dst and tport.isdigit() and _flag(syn) and not _flag(ack):
            syn_ports[(src, dst)].add(int(tport))
            if t is not None:
                syn_times[(src, dst)].append(t)

    def ts(epoch_value):
        return datetime.fromtimestamp(epoch_value, UTC).isoformat() if epoch_value is not None else None

    summary = {
        "packets": packets,
        "bytes": total_bytes,
        "first_packet": ts(first),
        "last_packet": ts(last),
        "duration_seconds": round(last - first, 3) if first is not None and last is not None else None,
        "truncated": packets >= MAX_PACKETS,
        "protocols": protocols.most_common(10),
        "top_talkers": [{"ip": ip, "packets": n, "bytes": talkers_bytes[ip]} for ip, n in talkers_pkts.most_common(10)],
        "conversations": [{"a": a, "b": b, "packets": c[0], "bytes": c[1]}
                          for (a, b), c in sorted(conversations.items(), key=lambda kv: -kv[1][0])[:10]],
        "dns_queries": dns_queries.most_common(20),
    }

    detections = []
    info = RULES["R-006"]
    for (src, dst), ports in syn_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            times = syn_times[(src, dst)]
            sample = sorted(ports)[:15]
            detections.append(Detection(
                rule_id="R-006", title=f"Port scan from {src} against {dst}", severity=info.severity,
                mitre=info.mitre, src_ip=src, dst_ip=dst, count=len(ports),
                first_seen=datetime.fromtimestamp(min(times), UTC) if times else None,
                last_seen=datetime.fromtimestamp(max(times), UTC) if times else None,
                details=f"SYN packets to {len(ports)} distinct ports (e.g. {', '.join(map(str, sample))}).",
            ))
    return summary, detections
