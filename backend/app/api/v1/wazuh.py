"""Wazuh endpoints: connection test, agents, alert sync."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.core.config import get_settings
from app.db.session import get_db
from app.integrations.wazuh.client import WazuhError
from app.models import User
from app.models.enums import Role
from app.services import audit, settings_store, wazuh_sync

router = APIRouter(prefix="/wazuh", tags=["wazuh"])


@router.get("/status")
def wazuh_status(db: Session = Depends(get_db), _user: User = Depends(require_role(Role.VIEWER))) -> dict:
    s = get_settings()
    result = {
        "configured": bool(s.wazuh_api_url),
        "indexer_configured": bool(s.wazuh_indexer_url),
        "tls_verification": "ca_cert" if s.wazuh_ca_cert else ("on" if s.wazuh_verify_tls else "OFF"),
        "min_rule_level": s.wazuh_min_rule_level,
        "last_sync_cursor": settings_store.get_value(db, wazuh_sync.CURSOR_KEY),
        "reachable": False,
        "manager_version": None,
        "agents_total": None,
        "error": None,
    }
    if not s.wazuh_api_url:
        result["error"] = "Not configured. Set WAZUH_API_URL and credentials in backend/.env (see docs/LAB_SETUP.md)."
        return result
    try:
        with wazuh_sync.client_factory(s) as client:
            result["manager_version"] = client.manager_info().get("version")
            result["agents_total"] = len(client.agents())
            result["reachable"] = True
    except WazuhError as exc:
        result["error"] = str(exc)
    return result


@router.get("/agents")
def wazuh_agents(_user: User = Depends(require_role(Role.VIEWER))) -> list[dict]:
    try:
        with wazuh_sync.client_factory(get_settings()) as client:
            return client.agents()
    except WazuhError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from None


@router.post("/sync")
def wazuh_sync_now(request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_role(Role.ANALYST))) -> dict:
    try:
        result = wazuh_sync.sync_alerts(db)
    except WazuhError as exc:
        audit.record(db, action="wazuh.sync", outcome="failure", user=user, detail=str(exc),
                     client_ip=client_ip(request))
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from None
    audit.record(db, action="wazuh.sync", outcome="success", user=user,
                 detail=f"fetched={result['fetched']} created={result['created']}", client_ip=client_ip(request))
    return result
