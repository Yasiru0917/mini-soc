"""Collects every v1 router under the /api/v1 prefix."""

from fastapi import APIRouter

from app.api.v1 import auth, dashboard, health, users

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(users.router)
