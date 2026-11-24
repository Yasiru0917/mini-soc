"""Shared schema helpers."""

from ipaddress import ip_address
from typing import Annotated

from pydantic import AfterValidator, BaseModel


def _valid_ip(value: str | None) -> str | None:
    """Accept only real IPv4/IPv6 addresses, normalised (e.g. strips spaces)."""
    if value is None or value == "":
        return None
    return str(ip_address(value.strip()))


OptionalIP = Annotated[str | None, AfterValidator(_valid_ip)]


class Page[T](BaseModel):
    """A page of results plus the total count (for pagination)."""

    items: list[T]
    total: int
