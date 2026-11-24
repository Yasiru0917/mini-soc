"""Build a small synthetic packet capture (samples/sample-portscan.pcap).

It contains:
  * a TCP SYN port scan from 203.0.113.50 (documentation range) against the
    lab host 192.168.56.101, ports 1-40 (ports 22 and 80 answer SYN-ACK,
    the rest answer RST, like a real host would),
  * one DNS query from the lab host for example.com.

Writing the bytes by hand is also a nice way to see what is inside a packet:
pcap header -> Ethernet header -> IPv4 header -> TCP/UDP header -> payload.

Usage (backend folder):  python -m scripts.make_sample_pcap [output_path]
"""

import socket
import struct
import sys
from pathlib import Path

SCANNER, TARGET, RESOLVER = "203.0.113.50", "192.168.56.101", "192.168.56.1"
MAC_A, MAC_B = bytes.fromhex("080027aaaaaa"), bytes.fromhex("080027bbbbbb")
START = 1795593600  # 2026-11-24 00:00:00 UTC


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def _tcp(sport: int, dport: int, flags: int, seq: int, ack: int = 0) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns_query(name: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def build_packets() -> list[tuple[float, bytes]]:
    SYN, SYN_ACK, RST_ACK = 0x02, 0x12, 0x14
    packets, t, ident = [], float(START + 10 * 3600), 1
    for port in range(1, 41):
        probe = _tcp(50000 + port, port, SYN, port)
        packets.append((t, MAC_B + MAC_A + b"\x08\x00" + _ipv4(SCANNER, TARGET, 6, probe, ident)))
        reply = SYN_ACK if port in (22, 80) else RST_ACK
        packets.append((t + 0.0005, MAC_A + MAC_B + b"\x08\x00"
                        + _ipv4(TARGET, SCANNER, 6, _tcp(port, 50000 + port, reply, 9000, port + 1), ident + 1)))
        t += 0.01
        ident += 2
    packets.append((t + 1, MAC_A + MAC_B + b"\x08\x00"
                    + _ipv4(TARGET, RESOLVER, 17, _udp(53000, 53, _dns_query("example.com")), ident)))
    return packets


def write_pcap(path: Path) -> Path:
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # global header, Ethernet
        for ts, frame in build_packets():
            sec, usec = int(ts), int(round((ts - int(ts)) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
    return path


if __name__ == "__main__":
    default = Path(__file__).resolve().parents[2] / "samples" / "sample-portscan.pcap"
    out = write_pcap(Path(sys.argv[1]) if len(sys.argv) > 1 else default)
    print(f"Wrote {out} ({out.stat().st_size} bytes)")
