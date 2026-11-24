# Detection Rules

All rules live in `backend/app/detection/rules.py` and `backend/app/integrations/tshark/analyzer.py` (R-006). Exposure rules are in `backend/app/integrations/nmap/findings.py`.

Every alert a rule raises records:
- the rule ID,
- the source file and its SHA-256 hash,
- the line numbers of the matching events,
- up to 5 sample lines,
- the MITRE ATT&CK technique.

## Log rules

| ID | Name | Logic | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| R-001 | SSH brute force | ≥ 5 `auth_failure` events from one IP within a **2-minute sliding window** | High | T1110 Brute Force |
| R-002 | Successful login after brute force | An `auth_success` from an IP with ≥ 5 failures in the **previous 10 minutes** | Critical | T1110 / T1078 Valid Accounts |
| R-003 | Web path traversal | URL (decoded **twice**, which defeats `%252e` double encoding) contains `../` or `..\` | High | T1190 Exploit Public-Facing Application |
| R-004 | SQL injection pattern | Decoded URL matches `UNION SELECT`, `' OR '1'='1`, `OR 1=1`, `SLEEP(`, `BENCHMARK(`, `information_schema`, `; DROP TABLE`, `'--` | High | T1190 |
| R-005 | Web enumeration | ≥ 20 HTTP **404** responses to one IP within 1 minute | Medium | T1595.003 Wordlist Scanning |

## Packet-capture rule

| ID | Name | Logic | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| R-006 | Port scan | One source sends TCP SYN (without ACK) to ≥ 20 **distinct** destination ports on one host | Medium | T1046 Network Service Discovery |

## Nmap exposure rules

| ID | Logic | Severity |
|---|---|---|
| NMAP-RISKY-PORT | Open TCP port from a list of commonly abused services, set per service in `findings.py` | Low to Critical |
| NMAP-NEW-DEVICE | A host that wasn't in the inventory responds. Only raised once a baseline exists; the first scan just builds the inventory. | Low |

Risky-port severities by service:
- **Critical:** Docker API without TLS (2375)
- **High:** Telnet (23), rexec/rlogin/rsh (512–514), VNC (5900), Redis (6379), MongoDB (27017)
- **Medium:** FTP (21), RDP (3389), MySQL (3306), PostgreSQL (5432), MSSQL (1433)
- **Low:** NetBIOS (139), SMB (445)

These describe **exposure** (a risky service is reachable), not an attack in progress. Open exposure alerts are not duplicated by repeat scans.

## Wazuh alerts

Imported alerts keep Wazuh's rule ID (`WZ-<id>`) and MITRE tags. Wazuh rule levels (0–15) map to severities:

| Wazuh level | Severity |
|---|---|
| 12–15 | Critical |
| 10–11 | High |
| 7–9 | Medium |
| 4–6 | Low |
| 0–3 | Info |

Only levels ≥ `WAZUH_MIN_RULE_LEVEL` (default 7) are imported.

## Known limitations (honest notes)

- Classic syslog lines have **no year and no time zone**. The parser assumes the current year (or last year, if that would put the line in the future) and UTC.
- Thresholds are fixed and simple. They will miss slow, distributed attacks and can flag noisy legitimate clients, such as a misconfigured backup job retrying SSH.
- R-003 and R-004 detect **attempts**. A `2xx` response *may* mean success, which needs checking on the server.
- Text logs must be UTF-8. Files over 200,000 lines are truncated, and the skipped count is reported.
- Uploading the same file twice is refused (matched by SHA-256), so alerts aren't duplicated.
