"""Authorized scanning scope - the most important safety control of the scanner.

Scanning a network you don't own can be illegal and is always unethical.
These checks run on the SERVER for every scan request:

  * Targets must be IP addresses or CIDR ranges. Hostnames are refused
    (a hostname could resolve to anything, including an outside system).
  * A target range may be at most a /24 (256 addresses).
  * EVERY address in the target must lie inside one of the scope networks.
  * Scope networks themselves are limited to private (RFC 1918) ranges
    unless an admin explicitly confirms a public range they are authorized for.
"""

import ipaddress
from ipaddress import IPv4Network, IPv6Network

Network = IPv4Network | IPv6Network

MAX_TARGET_PREFIX = {4: 24, 6: 120}  # largest target: /24 (IPv4), /120 (IPv6)
MAX_SCOPE_PREFIX = {4: 16, 6: 112}   # largest scope entry an admin may add


class ScopeError(ValueError):
    """A target or scope entry was rejected. The message is safe to show users."""


def parse_network(text: str) -> Network:
    text = (text or "").strip()
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ScopeError(
            f"'{text[:64]}' is not a valid IP address or CIDR range (hostnames are not accepted)"
        ) from None


def parse_target(text: str) -> Network:
    net = parse_network(text)
    if net.prefixlen < MAX_TARGET_PREFIX[net.version]:
        raise ScopeError(f"Target range too large. Maximum is /{MAX_TARGET_PREFIX[net.version]} per scan.")
    if net.is_multicast or net.is_unspecified or net.is_reserved:
        raise ScopeError("Multicast, unspecified and reserved addresses cannot be scanned.")
    return net


def ensure_in_scope(target: Network, scope: list[Network]) -> None:
    if not any(target.version == s.version and target.subnet_of(s) for s in scope):
        allowed = ", ".join(str(s) for s in scope) or "(empty)"
        raise ScopeError(f"Target {target} is outside the authorized scope ({allowed}).")


def validate_scope(entries: list[str], allow_public: bool) -> list[Network]:
    """Validate an admin's new scope list."""
    if not entries:
        raise ScopeError("Scope must contain at least one network.")
    networks: list[Network] = []
    for entry in entries:
        net = parse_network(entry)
        if net.prefixlen < MAX_SCOPE_PREFIX[net.version]:
            raise ScopeError(f"{net} is too large. Scope entries may be at most /{MAX_SCOPE_PREFIX[net.version]}.")
        # Stricter than "is_global": anything that is not a private range
        # (incl. carrier-grade NAT 100.64.0.0/10) needs explicit confirmation.
        if not net.is_private and not allow_public:
            raise ScopeError(f"{net} is not a private network range. Only add it if you have written "
                             "permission, and confirm with allow_public=true.")
        if net.is_multicast or net.is_unspecified:
            raise ScopeError(f"{net} cannot be used as a scan scope.")
        networks.append(net)
    return networks
