# Mini SOC: Security Design and Review

## 1. Threat model

| Asset | Threat | Control (implemented) |
|---|---|---|
| User accounts | Password guessing, stolen hashes | Argon2id hashing; 12+ character passwords; rate limiting; generic login errors |
| Sessions | Token theft through XSS | JWT in an **HttpOnly** cookie that JavaScript can't read |
| State-changing requests | CSRF | `SameSite=Strict` cookie, same-origin API, server-side Origin check |
| Data and actions | Users exceeding their role | Server-side RBAC on every endpoint; role read from the database on every request |
| Scanner | Being pointed at systems we don't own | Server-enforced CIDR scope, no hostnames, max /24, preset profiles, audited |
| Server | Command injection | `subprocess` argument lists, no shell, targets rebuilt from `ipaddress` objects |
| Server | Malicious XML from tools | `defusedxml` (no entities / XXE) |
| Storage | Malicious uploads | Extension allowlist, magic-byte and UTF-8 checks, size limits, UUID names outside the web root, served only as `attachment` |
| Analysts | Reports weaponised by attacker text | PDF markup escaping; CSV formula neutralisation |
| Network privacy | Leaking internal indicators | Private/internal IPs and domains are never sent to threat-intel providers |
| Packet analysis | Malicious pcap | TShark with `-n` (no DNS), packet cap, timeout, isolated Wireshark profile |
| Secrets | API keys in git | `.env` only (git-ignored); keys never sent to the browser |
| Trust in data | Fake detections | Provenance fields, DEMO badges, `source` forced on manual alerts |
| Accountability | Misuse of the tool | Audit log of logins, scans (including refused ones), uploads, lookups, changes, reports |

## 2. Authentication and sessions

- **Passwords:** Argon2id (`pwdlib`), at least 12 characters (NIST SP 800-63B: length over complexity rules). There's no default account; the first admin is created with `scripts/create_admin.py`.
- **Login:**
  - one generic error message for every failure;
  - unknown usernames still run a dummy hash, so response timing doesn't reveal which usernames exist;
  - 5 failures per username or IP within 15 minutes → HTTP 429.
- **Token:** JWT signed with HS256 using `SECRET_KEY` (≥ 32 characters; the app refuses to start without it). It expires after 30 minutes. Only HS256 is accepted, so `alg=none` tokens are rejected.
- **Cookie:** `soc_session`, with `HttpOnly; SameSite=Strict; Path=/api`, plus `Secure` in production or when `COOKIE_SECURE=true`.
- **Revocation:** each user has a `token_version`. Logout, password change, password reset, a role change or deactivation increments it, which invalidates every existing token.
- **Password management:**
  - Users change their own password, which requires the current one.
  - Admins can reset other users' passwords. An admin can't demote, disable or reset their own account.

## 3. Authorization (RBAC)

| Action | Admin | Analyst | Viewer |
|---|:-:|:-:|:-:|
| View dashboard, alerts, incidents, scans, logs, reports | ✓ | ✓ | ✓ |
| Triage alerts, manage incidents, add or download evidence | ✓ | ✓ | |
| Run scans, upload logs, threat-intel lookups, Wazuh sync | ✓ | ✓ | |
| Change scan scope, manage users, view the audit log | ✓ | | |

## 4. Scanning safety

- **Default scope:** `192.168.56.0/24`. It's stored server-side and only admins can change it.
- **Non-private ranges** (including carrier-grade NAT, `100.64.0.0/10`) need explicit `allow_public` confirmation.
- **Targets:** IPs or CIDRs only (no hostnames), at most `/24`, and every address must be inside the scope. Multicast and reserved addresses are refused.
- **Profiles:** preset only (`-sn`, `-sT --top-ports 100`, `-sT -sV --top-ports 1000`). There are no user-supplied flags.
- **Limits:** one scan at a time. A per-host timeout and an overall timeout apply. Scans interrupted by a restart are marked failed.
- **Audit:** every request is logged, including refused ones.

## 5. Uploads

| Type | Limit | Allowed | Content check |
|---|---|---|---|
| Evidence | 20 MB | text, pcap, PNG, JPEG, PDF | magic bytes / UTF-8 |
| Logs | 10 MB | `.log .txt .json .jsonl` | strict UTF-8, no NUL bytes |
| Packet captures | 50 MB | `.pcap .pcapng .cap` | pcap/pcapng magic bytes |

- Oversized requests are refused **before** the body is read (`Content-Length` check). Uploads also need a `Content-Length` header.
- Files are streamed in 64 KB chunks and hashed with SHA-256. Rejected or partial files are deleted.
- Stored names are random UUIDs under `backend/data/uploads/`. The user's filename is kept only as sanitised metadata, and path resolution refuses anything that escapes the folder.
- Downloads use `Content-Type: application/octet-stream` plus `Content-Disposition: attachment`, so the browser never renders uploaded content.

## 6. Web hardening

- **Security headers:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a strict API CSP (`default-src 'none'`), and `Cache-Control: no-store`.
- **Body size:** JSON bodies over 1 MB are refused.
- **Input validation:** Pydantic validates every request (types, lengths, enums, IP addresses). SQL is parameterised through the SQLAlchemy ORM, and `LIKE` searches escape `%` and `_`.
- **Output:** React escapes output by default, and `dangerouslySetInnerHTML` is never used. External links use `rel="noopener noreferrer"`.
- **Logging:** the audit logger strips control characters, which prevents log injection. Passwords, tokens and API keys are never logged.
- **API docs:** `/docs` and `/openapi.json` are disabled when `APP_ENV=production`.

## 7. Security review (Phase 9)

The review method was:
- a manual walk-through of every endpoint against the threat model above;
- `ruff` with bandit security rules (`S`);
- `pip-audit` and `npm audit`;
- attack-style tests in `backend/tests/`.

### Findings and fixes

| # | Finding | Risk | Fix |
|---|---|---|---|
| 1 | Users couldn't change their password, and admins couldn't reset one | Compromised or forgotten passwords stay in use | `POST /auth/change-password` (needs the current password; revokes other sessions) and `POST /users/{id}/reset-password` |
| 2 | JSON request bodies had no size limit | Memory exhaustion (DoS) | 1 MB limit in middleware |
| 3 | The login rate limiter's memory grew with every new username tried | Slow memory DoS | Expired entries are pruned once more than 10,000 keys exist |
| 4 | The audit log had no viewer | Misuse goes unnoticed | Admin audit-log view with filters |
| 5 | Scope rule used `is_global`, which let documentation and CGNAT ranges through without confirmation | Accidental out-of-lab scanning | Rule changed to "anything not private needs confirmation" (found by a test in Phase 5) |
| 6 | XML entity attack produced a generic error | Confusing failure | Explicit `NmapError` ("possible XML attack") |

### Automated checks (at the end of Phase 9)

- `pytest`: 120 passed, plus 1 opt-in live-scan test (`RUN_NMAP_TESTS=1`), which also passed against this PC.
- `ruff check .`: no findings, including the bandit `S` rules.
- `pip-audit`: no known vulnerabilities.
- `npm audit`: 0 vulnerabilities.

### Accepted limitations

These are acceptable for a single-user lab; production would need more.

- Rate-limit counters live in memory. They reset on restart and aren't shared between processes.
- Logout revokes **all** of a user's sessions, not just one.
- There's no multi-factor authentication.
- SQLite isn't encrypted at rest. Protect `backend/data/` and backups (`automation/bash/backup-db.sh`).
- Evidence has no retention or deletion policy yet.
- In production, serve the frontend behind a reverse proxy over HTTPS with its own Content-Security-Policy, and set `APP_ENV=production` and `COOKIE_SECURE=true`.
- The Wazuh integration supports disabling TLS verification for the lab's self-signed certificate. The UI warns about this; prefer `WAZUH_CA_CERT`.
