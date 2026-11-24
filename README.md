# Mini SOC

A lab-scale **Security Operations Center** web app: network discovery with Nmap, alert triage, incident management, log analysis with transparent detection rules, and reporting.

> **Status: Phase 3 of 9.** The backend, database, secure sign-in and role-based access are working, and the dashboard shows live database counts. Unbuilt features are clearly labelled in the UI. No detections are simulated.

## Tech stack

React 19 · Vite · Tailwind CSS v4 · Python 3.13 · FastAPI · SQLAlchemy · SQLite · Argon2 · JWT (HttpOnly cookie) · Nmap · TShark · Wazuh

## Quick start (Windows / PowerShell)

Prerequisites: Node.js 20+ and Python 3.13. On Windows, use `py -3.13`, because plain `python` may be an older version.

### 1. Backend (terminal 1)

```powershell
cd backend
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# One-time configuration
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste the output as SECRET_KEY in .env

# Create the first admin account (prompts for a password, 12+ chars)
python -m scripts.create_admin

uvicorn app.main:app --reload --port 8000
```

API docs: http://127.0.0.1:8000/docs

### 2. Frontend (terminal 2)

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and sign in.

### Tests

```powershell
cd backend
.venv\Scripts\Activate.ps1
pytest          # automated tests
ruff check .    # lint + security rules
```

## Project layout

```
frontend/   React single-page app
backend/    FastAPI service, SQLite database, tests
docs/       Architecture, security design, lab setup
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security design](docs/SECURITY.md)
- [Lab setup and Wazuh VM](docs/LAB_SETUP.md)

## Ethics and scope

Scanning is restricted to the VirtualBox host-only lab network (`192.168.56.0/24`) by default. Only scan systems you own or have explicit written permission to test.
