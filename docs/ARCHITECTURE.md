# Mini SOC: Architecture

> Status: Phase 3 complete (FastAPI backend, SQLite, authentication, RBAC, live dashboard). This document is updated at the end of every phase.

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

## 7. Backend layout

As built in Phase 3. Folders marked *(later)* arrive in the phase noted.

```
backend/
├── .env.example        config template (copy to .env, which is git-ignored)
├── requirements*.txt   pinned dependencies
├── pyproject.toml      pytest + ruff (incl. bandit security rules) config
├── app/
│   ├── main.py         app factory, security-header + origin-check middleware
│   ├── core/           config.py (settings), security.py (Argon2, JWT),
│   │                   rate_limit.py (login brute-force protection)
│   ├── db/session.py   engine, sessions, UTCDateTime column type
│   ├── models/         user, alert, incident, audit_log, enums
│   ├── schemas/        Pydantic request/response models
│   ├── api/
│   │   ├── deps.py     get_current_user, require_role(...)
│   │   ├── router.py   mounts everything under /api/v1
│   │   └── v1/         health, auth, dashboard, users
│   ├── services/       audit.py
│   ├── detection/      (later: Phase 6)
│   ├── integrations/   (later: Phases 5–8)
│   └── reports/        (later: Phase 8)
├── scripts/create_admin.py
├── tests/              pytest: auth, RBAC, CSRF, headers, dashboard
└── data/               (git-ignored) soc.db, later uploads/
```

### API endpoints (Phase 3)

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/api/v1/health` | public | API + database status |
| POST | `/api/v1/auth/login` | public (rate-limited) | Sign in, sets HttpOnly cookie |
| POST | `/api/v1/auth/logout` | signed in | Revokes token, clears cookie |
| GET | `/api/v1/auth/me` | signed in | Current user |
| GET | `/api/v1/dashboard/summary` | viewer+ | Live alert/incident counts (`?include_simulated=`) |
| GET | `/api/v1/users` | admin | List users |
| POST | `/api/v1/users` | admin | Create user |
| PATCH | `/api/v1/users/{id}` | admin | Change role / enable / disable |

Interactive docs: `http://127.0.0.1:8000/docs` (development only).

### Frontend additions (Phase 3)

- `api/client.js`: fetch wrapper (same-origin cookies, readable errors, 401 → `auth:expired` event).
- `auth/AuthContext.jsx`: who is signed in (via `/auth/me`), plus login, logout and `hasRole`.
- `auth/RequireAuth.jsx`: route guard that redirects to `/login`.
- `hooks/useApi.js`: loading/error/reload for GET requests.
- Vite proxy: `/api` → `http://127.0.0.1:8000`, so the browser sees a single origin.

## 8. Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Environment check, architecture | ✅ |
| 2 | Frontend shell, navigation, design system, docs | ✅ |
| 3 | FastAPI + SQLite, auth (Argon2 + HttpOnly cookie JWT), RBAC, health check, dashboard API | ✅ |
| 4 | Alerts and incidents (notes, evidence, resolution), demo seed script | ⏳ |
| 5 | Nmap integration with scope enforcement and audit log | |
| 6 | Secure uploads, log parsers, detection rules, TShark pcap summaries | |
| 7 | Wazuh integration (lab VM) | |
| 8 | Threat intelligence, PDF/CSV reports | |
| 9 | Tests, security review, Alembic, final docs | |

See also [SECURITY.md](SECURITY.md) and [LAB_SETUP.md](LAB_SETUP.md).
