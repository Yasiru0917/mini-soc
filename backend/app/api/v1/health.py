"""Health check: lets the frontend (and you) see whether the API and DB are up.

Public on purpose (no login needed), so it reveals nothing sensitive:
no library versions, paths or configuration.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.db.session import get_db, utcnow

router = APIRouter(tags=["health"])


@router.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except SQLAlchemyError:
        database = "unavailable"

    healthy = database == "ok"
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            "status": "ok" if healthy else "degraded",
            "database": database,
            "version": __version__,
            "time": utcnow().isoformat(),
        },
    )
