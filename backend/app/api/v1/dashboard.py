"""Dashboard summary: real counts straight from the database.

These numbers are honest: they are whatever is stored. Until detection
sources exist (Phases 4-7) the counts will legitimately be zero.
Demo records are counted separately so they can be shown or excluded.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.db.session import get_db, utcnow
from app.models import Alert, Incident, User
from app.models.enums import OPEN_INCIDENT_STATUSES, IncidentStatus, Role, Severity
from app.schemas.dashboard import AlertCounts, DashboardSummary, IncidentCounts, RecentAlert

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(
    include_simulated: bool = Query(True, description="Include demo (simulated) records"),
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(Role.VIEWER)),
):
    alert_filter = [] if include_simulated else [Alert.is_simulated.is_(False)]
    incident_filter = [] if include_simulated else [Incident.is_simulated.is_(False)]

    # GROUP BY severity -> {"high": 3, ...}; then fill in zeros for missing levels.
    sev_rows = db.execute(
        select(Alert.severity, func.count()).where(*alert_filter).group_by(Alert.severity)
    ).all()
    by_severity = {s: 0 for s in Severity} | {sev: n for sev, n in sev_rows}

    simulated = db.scalar(select(func.count()).select_from(Alert).where(Alert.is_simulated.is_(True))) or 0

    status_rows = db.execute(
        select(Incident.status, func.count()).where(*incident_filter).group_by(Incident.status)
    ).all()
    by_status = {s: 0 for s in IncidentStatus} | {st: n for st, n in status_rows}

    recent = db.scalars(
        select(Alert).where(*alert_filter).order_by(Alert.detected_at.desc()).limit(10)
    ).all()

    return DashboardSummary(
        alerts=AlertCounts(
            total=sum(by_severity.values()),
            by_severity=by_severity,
            simulated=simulated if include_simulated else 0,
        ),
        incidents=IncidentCounts(
            total=sum(by_status.values()),
            open=sum(by_status[s] for s in OPEN_INCIDENT_STATUSES),
            by_status=by_status,
        ),
        recent_alerts=[RecentAlert.model_validate(a) for a in recent],
        includes_simulated=include_simulated,
        generated_at=utcnow(),
    )
