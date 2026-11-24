"""Shared helpers for integrations."""

import shutil
import subprocess  # noqa: S404  (used safely: argument lists, no shell)
from dataclasses import asdict, dataclass, field


@dataclass
class IntegrationStatus:
    name: str
    # "available" | "not_installed" | "not_configured" | "unreachable" | "error"
    state: str
    detail: str = ""
    version: str | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def resolve_binary(path_or_name: str) -> str | None:
    """Return the full path of an executable, or None if it can't be found."""
    return shutil.which(path_or_name)


def binary_version(name: str, path_or_name: str, version_args: list[str]) -> IntegrationStatus:
    """Check that a command-line tool exists and report its version line."""
    exe = resolve_binary(path_or_name)
    if exe is None:
        return IntegrationStatus(name, "not_installed", f"'{path_or_name}' not found. Set its path in .env.")
    try:
        result = subprocess.run([exe, *version_args], capture_output=True, text=True, timeout=10, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        return IntegrationStatus(name, "error", f"Could not run {exe}: {exc.__class__.__name__}")
    first_line = (result.stdout or result.stderr).strip().splitlines()[0] if (result.stdout or result.stderr) else ""
    return IntegrationStatus(name, "available", exe, version=first_line[:120])
