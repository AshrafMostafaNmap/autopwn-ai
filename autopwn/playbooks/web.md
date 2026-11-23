# Web Playbook — OWASP WSTG / Top 10 (safe, non-destructive)

Methodology: map → identify candidate classes → probe safely → **verify
non-destructively** → score. A finding is only VERIFIED after a safe proof.

## Classes to cover (v1)
- **SQL injection** — error-based (DB error signatures) and boolean/time blind.
  Verify by *differential* (`AND 1=1` vs `AND 1=2`) or a single short time delay.
  Never `DROP`, `DELETE`, `UPDATE`, stacked writes, or data exfiltration.
- **Reflected XSS** — inject a unique marker; verify it reflects **unencoded** in
  an HTML/JS-executable context (not entity-escaped). Do not pop real payloads at
  users; the marker + context is the proof.
- **Security misconfiguration** — missing security headers (CSP, HSTS, X-Frame-
  Options, X-Content-Type-Options), directory listing, verbose errors.
- **Sensitive file exposure** — `/.env`, `/.git/config`, `/config.php.bak`,
  `/backup.zip`, `/.DS_Store` etc. Verify by signature in the returned body.
- **Session/cookie weaknesses** — missing `HttpOnly` / `Secure` / `SameSite`.
- **Open redirect** — `?next=//evil` reflected into `Location:` unchecked.
- **IDOR / access control** *(needs auth session)* — differential on object ids.
- **TLS/transport** — weak protocol, expired/self-signed cert (see server).

## Safe-verification rules
- Read-only. Confirm with reflection, boolean differential, a single bounded
  time delay, or presence-of-artifact. Stop at proof — never weaponize.
- A class that cannot be safely confirmed stays **SUSPECTED** (not reported).
