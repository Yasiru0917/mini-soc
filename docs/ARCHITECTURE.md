# Mini SOC: Architecture

> Status: Phase 2 complete (frontend shell). This document is updated at the end of every phase.

## 1. Purpose

Mini SOC is a web application for a small, **lab-only** Security Operations Center:

- discover devices on an authorized network,
- raise and triage security alerts,
- investigate incidents,
- analyse logs with transparent detection rules,
- report on what happened.

It is a learning and portfolio project. The design rule that overrides everything else:

> **No record may claim to be a detection unless a real detection mechanism produced it.**
> Every alert stores *what* produced it, and simulated data is always flagged and visibly badged.

## 2. Scope and priorities

| Priority | Modules |
|---|---|
| **MVP** | Dashboard, Network Scanning (Nmap), Alerts, Incidents, Log Analysis |
| Later | Wazuh integration, Threat Intelligence, Reports (PDF/CSV) |
| Supporting | Authentication and RBAC, Settings, audit log |

## 3. High-level design

```
Browser ── React + Vite + Tailwind (SPA)
   │  same-origin requests to /api/v1/...  (Vite dev proxy → FastAPI)
   ▼
FastAPI
   ├── api/v1 routers      HTTP only: parse, validate (Pydantic), authorize
   ├── services            business logic (alerts, incidents, scans, uploads)
   ├── detection           log parsers + rules (each rule maps to MITRE ATT&CK)
   ├── integrations        plugin per external tool: nmap, tshark, wazuh, threatintel
   └── models (SQLAlchemy) ──► SQLite (backend/data/soc.db)
```

### Why these layers?

- **Routers** only deal with HTTP: "is this request valid, and is this user allowed to make it?".
- **Services** contain the actual logic, so it can be tested without a web server.
- **Models** describe the tables. Moving from SQLite to PostgreSQL later only changes the connection string.
- **Integrations** share one small interface (`is_configured()`, `health_check()`, plus tool-specific actions). Adding a new tool means adding a folder, not editing the whole app.

## 4. Technology decisions

| Decision | Choice | Reason |
|---|---|---|
| Python version | 3.13 in a `.venv` | The system `python` command is 2.7; 3.14 is too new for some compiled wheels |
| Frontend build | Vite 8 + React 19 | Fast dev server, standard tooling |
| Styling | Tailwind CSS v4 (`@tailwindcss/vite`) | Design tokens live in `src/styles/index.css` (`@theme`); no `tailwind.config.js` |
| Routing | React Router 7 | Real URLs for each module |
| Icons | lucide-react | Consistent outline icon set |
| Charts | Recharts, **added only when real data exists** (Phase 3/4) | Avoid unneeded dependencies |
| Database | SQLite + SQLAlchemy 2 | Zero-install; easy to migrate later |
| Nmap access | `subprocess` with argument list + XML output, parsed with `defusedxml` | No shell → no command injection; safe XML parsing |
| PDF | ReportLab | Pure pip install on Windows (WeasyPrint needs GTK) |
| Background jobs | FastAPI `BackgroundTasks` | Enough for a single-user lab; no Redis/Celery |

## 5. Frontend structure (Phase 2)

```
frontend/src/
├── main.jsx            entry point; mounts <App/> inside <BrowserRouter>
├── App.jsx             route table
├── config/
│   ├── navigation.js   single source of truth for menu items + their phase
│   └── appConfig.js    display-only config (default scan scope)
├── layouts/            AppLayout (shell), Sidebar, Topbar
├── components/         PageHeader, Card, StatCard, DataTable, EmptyState,
│                       PlaceholderNotice, Badges (Severity/Status/Demo/Planned)
├── pages/              one file per module + Login + NotFound
└── styles/index.css    Tailwind import + theme tokens + shared classes
```

UI conventions:

- **Severity colours are only used for severity.** Red always means critical risk.
- **A dash (—) is shown when no data source exists; 0 is not.** "0 alerts" claims that someone looked and found nothing.
- **`PlaceholderNotice`** marks every unimplemented module with the phase that will deliver it.
- **`DemoBadge`** (purple, a colour no severity uses) marks simulated records.
- **Responsive design:** the sidebar is fixed at ≥1024px and becomes a drawer below that. Tables scroll inside their card, so the page never scrolls sideways.

## 6. Data provenance model (Phase 3+)

Every `alert` and `event` row will carry:

| Field | Meaning |
|---|---|
| `source` | `nmap` · `log_rule` · `pcap` · `wazuh` · `threat_intel` · `manual` · `demo` |
| `is_simulated` | `true` only for demo seed data |
| `detection_rule_id` | Rule that fired (for `log_rule`), e.g. `R-001` |
| `raw_reference` | Pointer to the evidence: upload ID + line number, scan ID, or Wazuh alert ID |

Demo data can only be created by `backend/scripts/seed_demo_data.py`. It sets `source="demo"` and `is_simulated=true`, and the dashboard can exclude it.

## 7. Planned backend layout (Phase 3)

```
backend/
├── app/
│   ├── main.py
│   ├── core/          config.py, security.py, logging.py
│   ├── db/            session.py, base.py
│   ├── models/        user, device, scan, alert, incident, note, evidence,
│   │                  log_upload, log_event, ioc_lookup, audit_log, setting
│   ├── schemas/       Pydantic request/response models
│   ├── api/v1/        auth, dashboard, devices, scans, alerts, incidents, logs, settings
│   ├── services/
│   ├── detection/     parsers/, rules/
│   ├── integrations/  base.py, nmap/, tshark/, wazuh/, threatintel/
│   └── reports/
├── scripts/           create_admin.py, seed_demo_data.py
├── tests/             pytest + sample log fixtures
└── data/              (git-ignored) soc.db, uploads/
```

## 8. Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Environment check, architecture | ✅ |
| 2 | Frontend shell, navigation, design system, docs | ✅ |
| 3 | FastAPI + SQLite, auth (Argon2 + HttpOnly cookie JWT), RBAC, health check, dashboard API | ⏳ |
| 4 | Alerts and incidents (notes, evidence, resolution), demo seed script | |
| 5 | Nmap integration with scope enforcement and audit log | |
| 6 | Secure uploads, log parsers, detection rules, TShark pcap summaries | |
| 7 | Wazuh integration (lab VM) | |
| 8 | Threat intelligence, PDF/CSV reports | |
| 9 | Tests, security review, Alembic, final docs | |

See also [SECURITY.md](SECURITY.md) and [LAB_SETUP.md](LAB_SETUP.md).
