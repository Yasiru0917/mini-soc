# Mini SOC: Security Design

This document records the security decisions for the application **before** they are implemented, so the implementation can be checked against them.

## 1. Threat model (short)

| Asset | Threat | Main control |
|---|---|---|
| User accounts | Password guessing, stolen passwords | Argon2 hashing, login rate limiting, generic error messages |
| Session tokens | Theft through XSS | Token in an **HttpOnly** cookie that JavaScript cannot read |
| State-changing requests | CSRF | `SameSite=Strict` cookie, same-origin API, Origin header check |
| Data and actions | Users exceeding their role | Server-side RBAC on every endpoint |
| Scanner | Being used against systems we don't own | Server-enforced CIDR allowlist, preset profiles, audit log |
| Server | Command injection through scan input | No shell, argument list only, strict IP/CIDR validation |
| Server/storage | Malicious uploads | Size limits, content validation, random filenames, no execution |
| Secrets | Leaking API keys via git | `.env` only (git-ignored); `.env.example` has no values |
| Analysts | Trusting fake data | Provenance fields + DEMO badge; no invented detections |

## 2. Authentication (implemented in Phase 3)

Covered by automated tests in `backend/tests/` (24 tests): hashing, cookie flags, generic errors, rate limiting, forged and `alg=none` tokens, logout revocation, role enforcement, immediate demotion, cross-site origin blocking, security headers, and audit-log injection.

Known limitations (accepted for a single-instance lab app):
- Login failure counters are kept in memory. They reset when the server restarts and aren't shared between multiple server processes.
- Logout increments `token_version`, which signs the user out of **all** their sessions, not just the current browser.
- The client IP comes from `X-Forwarded-For` only when the request arrives from the local Vite proxy (127.0.0.1). This is uvicorn's default trusted-proxy behaviour.

### Passwords
- Passwords are hashed with **Argon2id** (`pwdlib[argon2]`). Argon2 is deliberately slow and memory-hard, which makes offline cracking expensive. Plain passwords are never stored or logged.
- Minimum length is 12 characters. Length is checked, but there are no composition rules (this follows NIST SP 800-63B).
- Login failures return one generic message ("Invalid username or password"), so attackers can't find out which usernames exist.
- **Rate limiting:** after 5 failed attempts for a username or IP within 15 minutes, further attempts are temporarily refused.
- The first admin is created with a CLI script (`scripts/create_admin.py`) that prompts for the password. There is no default `admin/admin` account.

### Tokens
- On login, the server issues a **JWT** signed with HS256, using a random secret (`SECRET_KEY`, ≥ 32 bytes) loaded from `.env`.
- Claims: `sub` (user ID), `role`, `exp` (**30 minutes**), `iat`, `jti`, `ver`.
- The token is set as a cookie with `HttpOnly; SameSite=Strict; Path=/api`, plus `Secure` when served over HTTPS.
  - *HttpOnly:* injected JavaScript cannot read the token. That's why we don't use `localStorage`.
  - *SameSite=Strict:* the browser won't send the cookie on requests started by other sites, which blocks CSRF.
- **Logout and revocation:** each user has a `token_version`. Logging out, changing the password or disabling the account increments it. Any token whose `ver` doesn't match is rejected.
- The frontend never sees or stores the token. It calls `GET /api/v1/auth/me` to learn who is signed in.

### Authorization (RBAC)
| Action | Admin | Analyst | Viewer |
|---|:-:|:-:|:-:|
| View dashboard, alerts, incidents | ✓ | ✓ | ✓ |
| Triage alerts, manage incidents | ✓ | ✓ | |
| Upload logs, run authorized scans | ✓ | ✓ | |
| Change scan scope and integrations | ✓ | | |
| Manage users and roles | ✓ | | |

- Every protected endpoint declares its required role through a FastAPI dependency, for example `Depends(require_role("analyst"))`.
- **Hiding a button in the UI is never treated as access control.** The server checks every time.

## 3. Network scanning safety (Phase 5)

1. **Authorized scope.** The default is `192.168.56.0/24` (VirtualBox host-only network). It's stored server-side, and only admins can change it.
2. **Target validation.**
   - Targets are parsed with Python's `ipaddress` module. Hostnames are not accepted, which prevents DNS tricks.
   - Every address in a requested CIDR must fall inside the scope.
   - The largest allowed range is `/24`.
3. **Public addresses.** Any target where `ipaddress` reports `is_global` is refused unless an admin has explicitly added it to the scope.
4. **No user-supplied flags.** Users pick a preset profile (`discovery`, `quick`, `service`), and the server maps it to a fixed argument list.
5. **Execution.** Nmap runs with `subprocess.run([...], shell=False, timeout=...)`, using the path from `NMAP_PATH`. Output is XML on stdout, parsed with `defusedxml`.
6. **Audit log.** Every request (user, target, profile, time, allowed or denied) is recorded, including rejected ones.
7. **No admin-only scan types by default.** `-sS` and `-O` are not offered.

## 4. File uploads (Phase 6)

| Control | Implementation |
|---|---|
| Size limit | Logs **10 MB**, pcap **50 MB**. The stream is read in chunks and aborted when the limit is exceeded, so a large file is never fully loaded into memory. |
| Type allowlist | Extensions `.log .txt .json .jsonl .pcap .pcapng` only |
| Content validation | Text logs must decode as UTF-8 (with a small error tolerance) and contain no NUL bytes. Pcap files must start with valid magic bytes (`d4c3b2a1`, `a1b2c3d4`, `4d3cb2a1`, `a1b23c4d`, or pcapng `0a0d0d0a`). A mismatched extension is rejected. |
| Filename handling | The original name is stored only as metadata (sanitized). Files on disk get a random UUID name, which prevents path traversal and overwrites. |
| Storage location | `backend/data/uploads/` is outside any web-served folder and git-ignored. Files are never executed or served back directly. |
| Integrity | A SHA-256 hash is computed at upload and stored, so the file can be used as incident evidence. |
| Parsing safety | Parsers read line by line, enforce a maximum line length, and use regex patterns without catastrophic backtracking. TShark runs with `shell=False` and a timeout. |
| Permissions | Uploading requires the `analyst` role or higher. |

## 5. Secrets and configuration

- All secrets come from environment variables or `.env`, loaded with `pydantic-settings`. Examples: `SECRET_KEY`, `WAZUH_API_PASSWORD`, `ABUSEIPDB_API_KEY`.
- `.env` is git-ignored. `.env.example` lists the variable names with empty values.
- The app **refuses to start** if `SECRET_KEY` is missing or too short.
- Secrets are never sent to the frontend, never logged, and are masked in the Settings UI.
- Threat-intel lookups never send private or lab addresses (RFC 1918) to external services.

## 6. General web security

- **Input validation:** Pydantic schemas validate all request bodies, with types, lengths and enums.
- **Database access:** SQLAlchemy ORM with parameterized queries, so no SQL is built from strings.
- **Output encoding:** React escapes output by default. `dangerouslySetInnerHTML` is not used.
- **Errors:** generic error responses. Stack traces only appear in server logs, and only in debug mode.
- **CORS:** in development the frontend uses a Vite proxy, so requests are same-origin and CORS can stay locked down.
- **Security headers:** `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, and a basic `Content-Security-Policy`.
- **Dependencies:** audited with `npm audit` and `pip-audit` in Phase 9.

## 7. Honesty rules (data integrity)

1. Never display fabricated detections. Empty means empty.
2. Every alert records its `source` and, where applicable, the rule and evidence that produced it.
3. Simulated data uses `source="demo"` and `is_simulated=true`, and always shows a **DEMO** badge.
4. Integration status shows what is actually true ("Not configured", "Unreachable", "Connected") and is never optimistic.
5. Threat-intel verdicts show the provider, query time and the provider's own confidence. They are opinions, not proof.
