# AutoPwn AI — Security Assessment

**Run:** `sample-20261122`  ·  **Generated:** 2026-11-22 12:58 UTC  ·  **Profile:** safe
**Targets:** 127.0.0.1 (demo)
**Objective:** Assess the demo web app for injection and misconfig

## Summary

**6 verified finding(s)** — 1 critical · 1 high · 4 medium · 0 low · 0 info.

| # | Priority | Severity | CVSS | Finding | Location |
|---|---|---|---|---|---|
| 1 | P1 | critical | 9.8 | SQL Injection | http://127.0.0.1:34447/item?id=1 (`id`) |
| 2 | P2 | high | 7.5 | Sensitive File Exposure | http://127.0.0.1:34447/.env |
| 3 | P3 | medium | 6.1 | Reflected Cross-Site Scripting | http://127.0.0.1:34447/search?q=hi (`q`) |
| 4 | P3 | medium | 4.3 | Security Misconfiguration (missing headers) | http://127.0.0.1:34447/item?id=1 |
| 5 | P3 | medium | 4.3 | Security Misconfiguration (missing headers) | http://127.0.0.1:34447/search?q=hi |
| 6 | P3 | medium | 4.3 | Insecure Cookie Flags | http://127.0.0.1:34447/search?q=hi (`sid`) |

## Findings

### 1. SQL Injection  — CRITICAL (CVSS 9.8, P1)

- **Target:** http://127.0.0.1:34447/item?id=1 · param `id`
- **Mapping:** A03:2021-Injection · CWE-89
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Status:** verified · confidence 95%
- **Safe proof:** boolean differential confirmed (true~1.00, false~0.60)
- **Request:** `GET http://127.0.0.1:34447/item?id=1 [id= TRUE vs FALSE]`
- **Response (excerpt):**
  ```
  true-len=19 false-len=21
  ```
- **Steps:** send AND 1=1 (true) and AND 1=2 (false) → true response matches baseline; false diverges
- 🔵 **Detection (blue team):** Alert on DB errors in responses, anomalous query latency, and WAF rules matching tautologies/UNION in parameters; review ORM/raw-SQL usage.
- 🔵 **Remediation:** Use parameterized queries / prepared statements; validate and allow-list input; least-privilege DB accounts; disable verbose SQL errors.

### 2. Sensitive File Exposure  — HIGH (CVSS 7.5, P2)

- **Target:** http://127.0.0.1:34447/.env
- **Mapping:** A05:2021-Security Misconfiguration · CWE-538
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Status:** verified · confidence 95%
- **Safe proof:** exposed /.env
- **Request:** `GET http://127.0.0.1:34447/.env`
- **Response (excerpt):**
  ```
  SECRET_KEY=abc DB_PASS=hunter2
  ```
- **Steps:** request /.env → content matches expected signature
- 🔵 **Detection (blue team):** Alert on access to dotfiles/backups (/.env, /.git, *.bak) in web logs; file-integrity monitoring on the web root.
- 🔵 **Remediation:** Remove secrets/backups from the web root; block dotfiles and archive extensions at the server; rotate any exposed secret.

### 3. Reflected Cross-Site Scripting  — MEDIUM (CVSS 6.1, P3)

- **Target:** http://127.0.0.1:34447/search?q=hi · param `q`
- **Mapping:** A03:2021-Injection · CWE-79
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- **Status:** verified · confidence 95%
- **Safe proof:** marker reflected unencoded in HTML context
- **Request:** `GET http://127.0.0.1:34447/search?q=hi [q=apx46a7f976"><svg/onload=1>]`
- **Response (excerpt):**
  ```
  <body>q: apx46a7f976"><svg/onload=1></body>
  ```
- **Steps:** inject unique marker with tag-breakout → marker reflected verbatim (not entity-encoded)
- 🔵 **Detection (blue team):** Monitor for script-like payloads reflected in responses; CSP violation reports; WAF signatures for <script>/onerror in parameters.
- 🔵 **Remediation:** Context-aware output encoding; a strict Content-Security-Policy; validate input; use framework auto-escaping.

### 4. Security Misconfiguration (missing headers)  — MEDIUM (CVSS 4.3, P3)

- **Target:** http://127.0.0.1:34447/item?id=1
- **Mapping:** A05:2021-Security Misconfiguration · CWE-16
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
- **Status:** verified · confidence 95%
- **Safe proof:** missing: content-security-policy, strict-transport-security, x-frame-options, x-content-type-options, referrer-policy, permissions-policy
- **Request:** `GET http://127.0.0.1:34447/item?id=1`
- **Response (excerpt):**
  ```
  response headers: content-type, date, server
  ```
- **Steps:** fetch the page → compare against expected security headers
- 🔵 **Detection (blue team):** Baseline expected security headers and alert on drift via periodic header scans.
- 🔵 **Remediation:** Set CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; harden defaults; disable directory listing and verbose errors.

### 5. Security Misconfiguration (missing headers)  — MEDIUM (CVSS 4.3, P3)

- **Target:** http://127.0.0.1:34447/search?q=hi
- **Mapping:** A05:2021-Security Misconfiguration · CWE-16
- **CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`
- **Status:** verified · confidence 95%
- **Safe proof:** missing: content-security-policy, strict-transport-security, x-frame-options, x-content-type-options, referrer-policy, permissions-policy
- **Request:** `GET http://127.0.0.1:34447/search?q=hi`
- **Response (excerpt):**
  ```
  response headers: content-type, date, server, set-cookie
  ```
- **Steps:** fetch the page → compare against expected security headers
- 🔵 **Detection (blue team):** Baseline expected security headers and alert on drift via periodic header scans.
- 🔵 **Remediation:** Set CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; harden defaults; disable directory listing and verbose errors.

### 6. Insecure Cookie Flags  — MEDIUM (CVSS 4.3, P3)

- **Target:** http://127.0.0.1:34447/search?q=hi · param `sid`
- **Mapping:** A05:2021-Security Misconfiguration · CWE-614
- **CVSS vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`
- **Status:** verified · confidence 95%
- **Safe proof:** cookie 'sid' missing: httponly, secure, samesite
- **Request:** `GET http://127.0.0.1:34447/search?q=hi`
- **Response (excerpt):**
  ```
  Set-Cookie: sid=… ; (flags: path=/)
  ```
- **Steps:** read Set-Cookie attributes
- 🔵 **Detection (blue team):** Inspect Set-Cookie attributes in traffic; alert on session cookies lacking HttpOnly/Secure.
- 🔵 **Remediation:** Set HttpOnly, Secure, and SameSite on session cookies; scope Path/Domain tightly.

---
_Generated by AutoPwn AI 0.1.0 · non-destructive, safe-verification only._