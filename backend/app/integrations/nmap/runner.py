"""Run Nmap safely and parse its XML output.

SAFETY
  * Users choose a PRESET profile; they can never pass their own flags.
  * The command is an argument LIST run without a shell, so characters like
    `;`, `&` or `|` in input can't start other commands (command injection).
  * The target is re-generated from a validated ipaddress object, so it can
    only ever be something like "192.168.56.0/24".
  * The XML output is parsed with defusedxml, which blocks malicious XML
    tricks (external entities / "billion laughs").

WHY -sT (TCP connect) and not -sS (SYN scan)?
  -sS sends raw packets and needs Administrator/root. -sT uses the normal
  operating system connect() call, so it works for a regular user.
"""

import subprocess  # noqa: S404  (argument list, no shell)
from dataclasses import dataclass, field

from defusedxml import DefusedXmlException, ElementTree

from app.integrations.base import resolve_binary


@dataclass(frozen=True)
class Profile:
    id: str
    label: str
    args: tuple[str, ...]
    description: str


PROFILES: dict[str, Profile] = {
    p.id: p
    for p in (
        Profile("discovery", "Host discovery", ("-sn",), "Which hosts are up? No port scan."),
        Profile("quick", "Quick TCP (top 100 ports)", ("-sT", "--top-ports", "100", "-T4"),
                "Fast check of the most common ports."),
        Profile("service", "Service & version detection", ("-sT", "-sV", "--top-ports", "1000", "-T4"),
                "Identify software and versions on open ports (slower)."),
    )
}

COMMON_ARGS = ("--host-timeout", "5m", "-oX", "-")  # XML to stdout


class NmapError(RuntimeError):
    pass


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class HostResult:
    ip: str
    state: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    ports: list[PortResult] = field(default_factory=list)


def build_command(nmap_path: str, profile_id: str, target: str) -> list[str]:
    exe = resolve_binary(nmap_path)
    if exe is None:
        raise NmapError(f"Nmap not found ('{nmap_path}'). Install it or set NMAP_PATH in .env.")
    profile = PROFILES[profile_id]  # KeyError impossible: validated by the API schema
    return [exe, *profile.args, *COMMON_ARGS, target]


def run_nmap(command: list[str], timeout: int) -> str:
    """Execute Nmap and return its XML output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
    except subprocess.TimeoutExpired:
        raise NmapError(f"Scan timed out after {timeout} seconds.") from None
    except OSError as exc:
        raise NmapError(f"Could not start Nmap: {exc.strerror or exc}") from None
    if result.returncode != 0 or "<nmaprun" not in result.stdout:
        tail = (result.stderr or result.stdout).strip()[-500:]
        raise NmapError(f"Nmap exited with code {result.returncode}: {tail}")
    return result.stdout


def parse_xml(xml_text: str) -> list[HostResult]:
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise NmapError(f"Could not parse Nmap XML output: {exc}") from None
    except DefusedXmlException:
        raise NmapError("Refused to parse XML containing entity declarations (possible XML attack).") from None

    hosts: list[HostResult] = []
    for host in root.findall("host"):
        status = host.find("status")
        ip = mac = vendor = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac, vendor = addr.get("addr"), addr.get("vendor")
        if ip is None:
            continue
        hostname_el = host.find("hostnames/hostname")
        result = HostResult(
            ip=ip,
            state=status.get("state", "unknown") if status is not None else "unknown",
            hostname=hostname_el.get("name") if hostname_el is not None else None,
            mac=mac,
            vendor=vendor,
        )
        for port in host.findall("ports/port"):
            state_el, svc = port.find("state"), port.find("service")
            result.ports.append(PortResult(
                port=int(port.get("portid")),
                protocol=port.get("protocol", "tcp"),
                state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                service=svc.get("name") if svc is not None else None,
                product=svc.get("product") if svc is not None else None,
                version=svc.get("version") if svc is not None else None,
            ))
        hosts.append(result)
    return hosts
