"""Honest status of every integration, for the Settings page."""

from fastapi import APIRouter, Depends

from app.api.deps import require_role
from app.core.config import get_settings
from app.integrations.base import IntegrationStatus, binary_version
from app.models import User
from app.models.enums import Role

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/status")
def integration_status(_user: User = Depends(require_role(Role.VIEWER))) -> list[dict]:
    s = get_settings()
    statuses: list[IntegrationStatus] = [
        binary_version("Nmap", s.nmap_path, ["--version"]),
        binary_version("TShark (Wireshark)", s.tshark_path, ["--version"]),
    ]

    # Wazuh: only "configured / not configured" here; live reachability is
    # checked on demand by GET /wazuh/status (it involves a network call).
    statuses.append(IntegrationStatus(
        "Wazuh", "available" if s.wazuh_api_url else "not_configured",
        "Connection details set; use 'Test connection' to verify." if s.wazuh_api_url
        else "Set WAZUH_API_URL and credentials in backend/.env",
    ))

    for name, key in (("AbuseIPDB", s.abuseipdb_api_key), ("VirusTotal", s.virustotal_api_key),
                      ("AlienVault OTX", s.otx_api_key)):
        statuses.append(IntegrationStatus(
            name, "available" if key else "not_configured",
            "API key set" if key else "No API key in backend/.env",  # never reveal the key itself
        ))
    return [st.to_dict() for st in statuses]
