# Running and Testing Mini SOC

## 1. Automated tests

```powershell
cd backend
.venv\Scripts\Activate.ps1
pytest                    # 120+ tests; uses a temporary database, never your real one
ruff check .              # lint + bandit security rules
pip-audit -r requirements-dev.txt
cd ..\frontend; npm audit; npm run build
```

Optional live scan test (scans **your own PC** at `192.168.56.1`):

```powershell
$env:RUN_NMAP_TESTS = "1"; pytest tests/test_network.py
```

| Test file | Covers |
|---|---|
| `test_auth.py` | Argon2 hashing, cookie flags, generic errors, rate limit, forged / `alg=none` tokens, logout revocation, log injection |
| `test_access_control.py` | RBAC, user management, CSRF origin check, security headers, dashboard |
| `test_alerts_incidents.py` | Alert workflow, forced `manual` source, incidents, notes, evidence hashing, disguised-file rejection |
| `test_network.py` | Scope enforcement, injection attempts, XML attacks, Nmap parsing, inventory, exposure alerts |
| `test_logs.py` | Parsers, every rule's threshold, uploads, duplicates, real TShark pcap analysis |
| `test_wazuh.py` | Simulated Wazuh server: login, agents, import, severity mapping, dedup, errors |
| `test_intel_reports.py` | Indicator validation, simulated providers, caching, PDF escaping, CSV injection |
| `test_phase9.py` | Password change/reset, audit log, body-size limit, rate-limiter memory, migrations |

## 2. Start the app

Terminal 1:
```powershell
cd backend; .venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```

Terminal 2:
```powershell
cd frontend; npm run dev
```

Then open http://localhost:5173. Alternatively, `bash automation/bash/start-dev.sh` in Git Bash starts both.

First time only, create your admin account: `python -m scripts.create_admin`.

## 3. Manual test checklist per module

### Authentication and roles
1. Visit any page while signed out: you're redirected to the sign-in page.
2. Enter a wrong password 5 times: "Too many failed login attempts".
3. In **Settings**, create an `analyst` and a `viewer`. Sign in as the viewer: the New alert, Start scan and Upload buttons are absent, and calling the API directly returns 403.
4. In DevTools → Application → Cookies, `soc_session` is **HttpOnly**. `document.cookie` in the Console doesn't show it.
5. In **Settings → My account**, change your password. Your other browsers are signed out.

### Dashboard
1. Run `python -m scripts.seed_demo_data`. Purple DEMO alerts appear, and "Total alerts" shows "8 demo".
2. Untick **Include demo data**: the counts drop back to real data only.
3. Remove the demo data with `python -m scripts.seed_demo_data --remove`.

### Network scanning
1. **Network Scanning** → target `192.168.56.1` (your PC), profile *Quick TCP*, then **Start scan**. Status goes from Queued to Running to Completed.
2. The device inventory shows your PC's open ports. Risky services (e.g. SMB) create alerts with **Detected by: Nmap scan**.
3. Try target `8.8.8.8`: it's refused with "outside the authorized scope". Then, as admin, open **Settings → Audit log** and filter on `scan`: the refused request is listed as `denied`.
4. Try `scanme.nmap.org` or `192.168.56.1; calc`: refused as an invalid target.

### Log analysis
1. **Log Analysis**: upload `samples/sample-auth.log` → 2 alerts (R-001, R-002).
2. Upload `samples/sample-access.log` → 3 alerts (R-003, R-004, R-005).
3. Upload `samples/sample-portscan.pcap` → R-006 plus traffic statistics: protocols, talkers, conversations, DNS.
4. Upload the same file again → "already analysed".
5. Rename any `.exe` to `.log` and upload it → rejected.
6. Open an alert: provenance shows the rule, `upload:N:lines:a-b`, and the file's SHA-256.

### Alerts and incidents
1. **Alerts**: tick the two brute-force alerts → **Create incident**.
2. On the incident page:
   - set the assignee;
   - move it to *Investigating*;
   - add a note;
   - upload `sample-auth.log` as evidence (check its SHA-256);
   - try **Resolved**. It's blocked until you save a resolution.
3. Write the resolution and recommendations, then move through *Resolved* to *Closed*.

### Threat intelligence
1. Without API keys, look up `8.8.8.8`: every provider says "Not configured". Nothing fake is shown.
2. Look up `192.168.56.101`: refused (private address, never sent out).
3. Add a free AbuseIPDB key to `backend/.env`, restart the backend, and look up a public IP. The result shows the provider, query time, score meaning and reliability note. A repeat lookup is marked "(cached)".

### Reports
1. **Reports** → **PDF** for your incident. The PDF has a timeline, evidence hashes and the resolution.
2. Download the alerts CSV and open it in Excel. Cells beginning with `=` show as text (`'=`).
3. **Generated reports** lists every file with its SHA-256.

### Wazuh (needs the lab VM; see LAB_SETUP.md)
1. Fill in the `WAZUH_*` settings in `.env` and restart. In **Settings → Wazuh SIEM**, click **Test connection**: it shows the version and agent count, or a clear error.
2. Trigger failed SSH logins against a monitored agent, then click **Sync alerts now**. Alerts appear with **Detected by: Wazuh**.
3. For continuous import: `bash automation/bash/wazuh-sync-loop.sh 300`.
