"""Collects every v1 router under the /api/v1 prefix."""

from fastapi import APIRouter

from app.api.v1 import alerts, auth, dashboard, health, incidents, integrations, logs, network, users, wazuh

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(incidents.assign_router)  # /users/assignable (before /users/{id})
api_router.include_router(users.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(incidents.evidence_router)
api_router.include_router(network.router)
api_router.include_router(integrations.router)
api_router.include_router(logs.router)
api_router.include_router(wazuh.router)
