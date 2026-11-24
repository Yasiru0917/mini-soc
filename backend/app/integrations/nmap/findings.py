"""Turn scan results into alerts - a simple, transparent "exposure policy".

These are real detections in the sense that matters: each alert is produced
by a rule applied to actual scan output, and the alert records the rule ID
and the scan it came from. They describe EXPOSURE (a risky service is
reachable), not an attack in progress.

NMAP-RISKY-PORT
    An open port runs a service that is commonly abused (cleartext
    protocols, remote desktop, databases, unauthenticated admin APIs).
NMAP-NEW-DEVICE
    A host appeared that was not in the inventory before. Only raised once a
    baseline exists (the very first scan just builds the inventory).
"""

from dataclasses import dataclass

from app.models.enums import Severity

RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    21: ("FTP", Severity.MEDIUM, "Sends credentials in cleartext. Prefer SFTP/FTPS."),
    23: ("Telnet", Severity.HIGH, "Cleartext remote shell. Replace with SSH."),
    139: ("NetBIOS session service", Severity.LOW, "Legacy Windows file sharing; restrict to trusted hosts."),
    445: ("SMB", Severity.LOW, "File sharing; common ransomware/worm vector. Restrict exposure."),
    512: ("rexec", Severity.HIGH, "Legacy remote execution without encryption."),
    513: ("rlogin", Severity.HIGH, "Legacy remote login without encryption."),
    514: ("rsh", Severity.HIGH, "Legacy remote shell without encryption."),
    1433: ("Microsoft SQL Server", Severity.MEDIUM, "Database reachable over the network."),
    2375: ("Docker API (no TLS)", Severity.CRITICAL, "Unauthenticated Docker API gives full host control."),
    3306: ("MySQL", Severity.MEDIUM, "Database reachable over the network."),
    3389: ("RDP", Severity.MEDIUM, "Remote Desktop is a frequent brute-force target."),
    5432: ("PostgreSQL", Severity.MEDIUM, "Database reachable over the network."),
    5900: ("VNC", Severity.HIGH, "Remote desktop often protected by weak or no passwords."),
    6379: ("Redis", Severity.HIGH, "Often deployed without authentication."),
    27017: ("MongoDB", Severity.HIGH, "Often deployed without authentication."),
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    host_ip: str
    description: str


def risky_port_findings(host_ip: str, open_ports: list[tuple[int, str, str | None]]) -> list[Finding]:
    """open_ports: (port, protocol, detected service name)."""
    findings = []
    for port, protocol, service in open_ports:
        if protocol != "tcp" or port not in RISKY_PORTS:
            continue
        name, severity, advice = RISKY_PORTS[port]
        findings.append(Finding(
            rule_id="NMAP-RISKY-PORT",
            title=f"{name} exposed on {host_ip}:{port}",
            severity=severity,
            host_ip=host_ip,
            description=f"Port {port}/tcp is open (service: {service or 'unknown'}). {advice}",
        ))
    return findings


def new_device_finding(host_ip: str, hostname: str | None) -> Finding:
    label = f"{host_ip} ({hostname})" if hostname else host_ip
    return Finding(
        rule_id="NMAP-NEW-DEVICE",
        title=f"New device discovered: {label}",
        severity=Severity.LOW,
        host_ip=host_ip,
        description="A host not previously in the inventory responded to a scan. Verify it is authorized.",
    )
