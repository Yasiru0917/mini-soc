"""Threat-intelligence lookups with caching."""

import json
from datetime import timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require_role
from app.core.config import get_settings
from app.db.session import get_db, utcnow
from app.integrations.threatintel import providers
from app.models import IocLookup, User
from app.models.enums import Role
from app.services import audit

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

VERDICT_RANK = {"unknown": 0, "harmless": 1, "suspicious": 2, "malicious": 3}


class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=255)
    force_refresh: bool = False


@router.post("/lookup")
def lookup(body: LookupRequest, request: Request, db: Session = Depends(get_db),
           user: User = Depends(require_role(Role.ANALYST))) -> dict:
    try:
        kind, value = providers.classify(body.indicator)
    except providers.IndicatorError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None

    s = get_settings()
    fresh_after = utcnow() - timedelta(hours=s.threat_intel_cache_hours)
    results, external_calls = [], 0

    for name, fn in providers.PROVIDERS:
        cached = None if body.force_refresh else db.scalar(
            select(IocLookup).where(IocLookup.indicator == value, IocLookup.provider == name,
                                    IocLookup.queried_at >= fresh_after).order_by(IocLookup.queried_at.desc()))
        if cached:
            result = json.loads(cached.result_json) | {"cached": True}
        else:
            try:
                result = fn(kind, value, s)
            except httpx.HTTPError:
                result = providers.make_result(name, "error", error="Could not reach the provider (network error).")
            if result["status"] == "ok":
                external_calls += 1
                db.add(IocLookup(indicator=value, indicator_type=kind, provider=name, verdict=result["verdict"],
                                 result_json=json.dumps(result), queried_by_id=user.id))
        results.append(result)
    db.commit()

    answered = [r for r in results if r["status"] == "ok"]
    overall = max((r["verdict"] for r in answered), key=VERDICT_RANK.__getitem__, default=None)
    audit.record(db, action="threatintel.lookup", outcome="success", user=user, target=value,
                 detail=f"type={kind} external_calls={external_calls} overall={overall}", client_ip=client_ip(request))
    return {
        "indicator": value,
        "type": kind,
        "results": results,
        "overall_verdict": overall,
        "providers_answered": len(answered),
        "note": ("No provider is configured: add API keys to backend/.env." if not answered and
                 all(r["status"] == "not_configured" for r in results) else
                 "The overall verdict is the most severe opinion among providers that answered. "
                 "Treat it as a lead to investigate, not proof."),
    }


@router.get("/history")
def history(limit: int = Query(30, ge=1, le=200), db: Session = Depends(get_db),
            _user: User = Depends(require_role(Role.VIEWER))) -> list[dict]:
    rows = db.scalars(select(IocLookup).order_by(IocLookup.queried_at.desc()).limit(limit)).all()
    names = dict(db.execute(select(User.id, User.username)).all())
    return [{"indicator": r.indicator, "type": r.indicator_type, "provider": r.provider, "verdict": r.verdict,
             "queried_at": r.queried_at.isoformat(), "queried_by": names.get(r.queried_by_id)} for r in rows]
