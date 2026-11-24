# Mini SOC: Architecture

> Status: all 9 phases complete. See [TESTING.md](TESTING.md) for how to run and verify each module.

## 1. Purpose

Mini SOC is a web application for a small, **lab-only** Security Operations Center. It covers:

- discovering devices on an authorized network,
- raising and triaging security alerts,
- investigating incidents,
- analysing logs and packet captures with transparent detection rules,
- enriching indicators with threat intelligence,
- reporting on what happened.

The design rule that overrides everything else:

> **No record may claim to be a detection unless a real detection mechanism produced it.**
> Every alert stores *what* produced it, and simulated data is always flagged and visibly badged.

## 2. High-level design

```
Browser ── React 19 + Vite + Tailwind v4 (single-page app)
   │  same-origin requests to /api/v1/...   (Vite proxy → FastAPI in development)
   ▼
FastAPI (Python 3.13)
   ├── middleware        upload/body size guard · Origin check (CSRF) · security headers
   ├── api/v1 routers    HTTP only: validate (Pydantic), authenticate, authorize (RBAC)
   ├── services          alerts/incidents logic, scans, log analysis, Wazuh sync, uploads, audit
   ├── detection         parsers (auth / access / JSONL) + rules R-001…R-005
   ├── integrations      nmap · tshark (R-006) · wazuh · threatintel (AbuseIPDB, VirusTotal, OTX)
   ├── reports           PDF (ReportLab) · CSV (injection-safe)
   └── models ──► SQLAlchemy 2 ──► SQLite (backend/data/soc.db), schema via Alembic
                                     files: backend/data/uploads/{evidence,logs}/<uuid>

External tools: Nmap (subprocess) · TShark (subprocess) · Wazuh server API :55000 + indexer :9200 (HTTPS)
Lab network: VirtualBox host-only 192.168.56.0/24 (the default authorized scan scope)
```

### Why these layers?

- **Routers** only deal with HTTP: "is this request valid, and is this user allowed to make it?".
- **Services** hold the logic, so it can be tested without a web server.
- **Integrations** each live in their own package and report an honest status (`available`, `not_configured`, `not_installed`, `unreachable`). Adding a new tool means adding a folder.
- **Detection** is pure Python: `lines → events → rules → detections`. No database or HTTP is involved, so every rule is unit-tested directly.

## 3. Technology decisions

| Decision | Choice | Reason |
|---|---|---|
| Python | 3.13 in `backend/.venv` | The system `python` command is 2.7; 3.14 is too new for some compiled wheels |
| Frontend | Vite 8, React 19, React Router 7 | Fast tooling, real URLs per module |
| Styling | Tailwind CSS v4 (`@theme` tokens in `src/styles/index.css`) | One place for the colour system |
| Database | SQLite + SQLAlchemy 2 + Alembic | Zero install; migrations make schema changes safe |
| Auth | Argon2id (`pwdlib`) + JWT (`PyJWT`) in an HttpOnly cookie | See [SECURITY.md](SECURITY.md) |
| Nmap / TShark | `subprocess` with argument lists, no shell | Prevents command injection |
| XML | `defusedxml` | Blocks XXE and "billion laughs" attacks in Nmap output |
| HTTP client | `httpx` (with `MockTransport` in tests) | Wazuh and threat intel are tested without real servers |
| PDF | ReportLab | Pure pip install on Windows |
| Background work | FastAPI `BackgroundTasks` (scans), CLI loop (Wazuh sync) | Enough for one lab instance; no Redis or Celery |
| Charts | Simple CSS bars | No chart library needed for the small amount of data |

## 4. Data provenance model

Every `alert` row carries:

| Field | Meaning | Examples |
|---|---|---|
| `source` | Mechanism that created it | `nmap`, `log_rule`, `pcap`, `wazuh`, `manual`, `demo` |
| `detection_rule_id` | Rule that fired | `R-001`, `NMAP-RISKY-PORT`, `WZ-5712` |
| `raw_reference` | Pointer back to the evidence | `upload:3:lines:4-11`, `scan:1`, `wazuh:<doc id>`, `manual:user:sara` |
| `is_simulated` | `true` only for demo seed data | Purple **DEMO** badge in the UI |
| `detected_at` | When the activity happened (log time), not when it was analysed | |

Further rules:
- Analysts can create alerts manually, but the server **forces** `source="manual"`, so nobody can impersonate a detector.
- Incidents built from demo alerts are themselves marked simulated (the "taint" rule).
- Demo data comes only from `scripts/seed_demo_data.py`. It uses RFC 5737 documentation IP addresses, and `--remove` deletes it.

## 5. Backend layout

```
backend/
├── alembic.ini, migrations/       schema migrations (applied automatically at start-up)
├── app/
│   ├── main.py                    app + middleware
│   ├── core/                      config (.env), security (Argon2, JWT), rate_limit
│   ├── db/                        session (engine, UTCDateTime type), migrate (Alembic runner)
│   ├── models/                    user, alert, incident(+note, evidence), network(scan, device, port,
│   │                              app_setting), logs(upload, event), intel(ioc_lookup, report), audit_log
│   ├── schemas/                   Pydantic request/response models
│   ├── api/deps.py                get_current_user, require_role
│   ├── api/v1/                    health, auth, users(+audit-log), dashboard, alerts, incidents,
│   │                              network, logs, integrations, wazuh, threatintel, reports
│   ├── services/                  audit, uploads, scans, log_analysis, wazuh_sync, settings_store
│   ├── detection/                 events, parsers, rules
│   ├── integrations/              base, nmap/, tshark/, wazuh/, threatintel/
│   └── reports/                   pdf, csv_export
├── scripts/                       create_admin, seed_demo_data, wazuh_sync, make_sample_pcap
└── tests/                         120+ pytest tests (fixtures/ holds sample Nmap XML)
```

## 6. API overview (`/api/v1`)

| Area | Endpoints | Minimum role |
|---|---|---|
| Health | `GET /health` | public |
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/change-password` | public / signed in |
| Users | `GET/POST /users`, `PATCH /users/{id}`, `POST /users/{id}/reset-password`, `GET /users/audit-log` | admin |
| | `GET /users/assignable` | analyst |
| Dashboard | `GET /dashboard/summary` | viewer |
| Alerts | `GET /alerts`, `GET /alerts/{id}` | viewer |
| | `POST /alerts`, `PATCH /alerts/{id}` | analyst |
| Incidents | `GET /incidents`, `GET /incidents/{id}` | viewer |
| | `POST /incidents`, `PATCH /incidents/{id}`, `POST/DELETE …/alerts`, `POST …/notes`, `POST …/evidence`, `GET /evidence/{id}/download` | analyst |
| Network | `GET /settings/scan-scope`, `GET /scans/profiles`, `GET /scans`, `GET /scans/{id}`, `GET /devices` | viewer |
| | `POST /scans` | analyst |
| | `PUT /settings/scan-scope` | admin |
| Logs | `GET /logs`, `GET /logs/{id}`, `GET /logs/{id}/events`, `GET /logs/rules` | viewer |
| | `POST /logs/upload` | analyst |
| Integrations | `GET /integrations/status`, `GET /wazuh/status`, `GET /wazuh/agents` | viewer |
| | `POST /wazuh/sync` | analyst |
| Threat intel | `GET /threat-intel/history` | viewer |
| | `POST /threat-intel/lookup` | analyst |
| Reports | `GET /reports`, `GET /reports/incidents/{id}.pdf`, `GET /reports/incidents/{id}.csv`, `GET /reports/alerts.csv` | viewer |

Interactive documentation: `http://127.0.0.1:8000/docs` (development mode only).

## 7. Frontend layout

```
frontend/src/
├── main.jsx, App.jsx          entry point + routes (all pages behind <RequireAuth>)
├── api/client.js              fetch wrapper: same-origin cookies, readable errors, 401 → sign-in
├── auth/                      AuthContext (who am I, login/logout, hasRole), RequireAuth
├── hooks/                     useApi (loading/error/reload), useDebounce
├── config/                    navigation (menu), workflow (allowed status changes)
├── layouts/                   AppLayout, Sidebar (drawer on mobile), Topbar (live API health)
├── components/                Card, DataTable, badges, Pagination, ErrorPanel, InfoNotice,
│                              UserManagement, ChangePassword, AuditLog, ScopeEditor,
│                              IntegrationStatus, WazuhPanel
├── pages/                     Dashboard, Network, Alerts(+detail), Incidents(+detail),
│                              Logs(+upload detail), ThreatIntel, Reports, Settings, Login, NotFound
└── utils/                     format (dates, bytes, source labels), cidr (scope hint)
```

UI conventions:
- Severity colours are used only for severity.
- Empty data shows "—", never a misleading 0.
- Demo data is always purple-badged.
- Errors are shown, never hidden.
- Tables scroll inside their card, so the page never scrolls sideways on phones.

## 8. Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Environment check, architecture | ✅ |
| 2 | Frontend shell, navigation, design system | ✅ |
| 3 | FastAPI, SQLite, Argon2 + HttpOnly JWT auth, RBAC, live dashboard | ✅ |
| 4 | Alerts, incidents, notes, evidence uploads, demo seed | ✅ |
| 5 | Nmap scanning with server-enforced scope, inventory, exposure alerts | ✅ |
| 6 | Log parsers, rules R-001…R-006, TShark pcap analysis | ✅ |
| 7 | Wazuh integration, automation scripts | ✅ (tested against a simulated Wazuh) |
| 8 | Threat intelligence, PDF/CSV reports | ✅ (tested against simulated providers) |
| 9 | Alembic, security review and fixes, dependency audit, docs | ✅ |

Possible next steps: live Wazuh verification in the lab VM, scheduled scans, PostgreSQL, Sigma-rule import, and frontend unit tests (Vitest).
