"""FastAPI application entry point.

Run (from the backend folder, with the venv active):
    uvicorn app.main:app --reload --port 8000
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app import (
    __version__,
    models,  # noqa: F401  (registers all tables on Base.metadata)
)
from app.api.router import api_router
from app.core.config import get_settings
from app.db.session import Base, engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

settings = get_settings()

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Create any missing tables at startup. (Phase 9 replaces this with
    # Alembic migrations, which can also change existing tables safely.)
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Mini SOC API",
    version=__version__,
    lifespan=lifespan,
    # Interactive API docs only in development: no need to publish a map of
    # every endpoint in production.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)


@app.middleware("http")
async def origin_check(request: Request, call_next):
    """CSRF defence in depth (the SameSite=Strict cookie is the first layer).

    Browsers always send an Origin header on cross-site POST/PUT/PATCH/DELETE.
    If it is present and not one of ours, refuse the request.
    Requests without Origin (curl, scripts, tests) can't carry a victim's
    browser cookie, so they are not a CSRF risk.
    """
    origin = request.headers.get("origin")
    if request.method in UNSAFE_METHODS and origin and origin not in settings.allowed_origins:
        return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"  # don't guess content types
    response.headers["X-Frame-Options"] = "DENY"            # no embedding (clickjacking)
    response.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith(DOCS_PATHS):
        # The API only returns JSON, so it needs no scripts/styles at all.
        # (Swagger UI at /docs needs its own scripts, so it is excluded.)
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"  # don't cache security data
    return response


app.include_router(api_router)
