"""Read/write runtime settings stored in the app_settings table (JSON values)."""

import ipaddress
import json
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import AppSetting, User

SCAN_SCOPE_KEY = "scan_scope"


def get_value(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(AppSetting, key)
    return json.loads(row.value) if row else default


def set_value(db: Session, key: str, value: Any, user: User | None = None) -> AppSetting:
    row = db.get(AppSetting, key) or AppSetting(key=key)
    row.value = json.dumps(value)
    row.updated_by_id = user.id if user else None
    db.add(row)
    db.commit()
    return row


def get_scan_scope(db: Session) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    cidrs = get_value(db, SCAN_SCOPE_KEY, get_settings().default_scan_scope)
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]
