# Mini SOC

A lab-scale **Security Operations Center** web app: network discovery with Nmap, alert triage, incident management, log analysis with transparent detection rules, and reporting.

> **Status: Phase 2 of 9.** The frontend shell is complete; the backend arrives in Phase 3. Unbuilt features are clearly labelled in the UI. No detections are simulated.

## Tech stack

React 19 + Vite + Tailwind CSS v4 · Python 3.13 + FastAPI · SQLite · Nmap · TShark · Wazuh

## Run the frontend

Requires Node.js 20+.

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

## Project layout

```
frontend/   React single-page app (see docs/ARCHITECTURE.md)
backend/    FastAPI service (Phase 3)
docs/       Architecture, security design, lab setup
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security design](docs/SECURITY.md)
- [Lab setup and Wazuh VM](docs/LAB_SETUP.md)

## Ethics and scope

Scanning is restricted to the VirtualBox host-only lab network (`192.168.56.0/24`) by default. Only scan systems you own or have explicit written permission to test.
