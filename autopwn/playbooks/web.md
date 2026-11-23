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

## Client-side (real browser)
- **Crawl in the browser** (`browser_crawl`): JavaScript-rendered pages and
  `#/routes` exist only there; HTTP-only crawlers miss them. Log in first
  (`browser_login`) when the app has an authenticated area, then crawl again.
- **DOM-based XSS** — `browser_dom_xss` puts a harmless `<i id=marker>` into each
  query and `#fragment` parameter; if the page creates that element, the value
  reaches an HTML sink. Proof without running script.
- **Tokens in browser storage** — JWTs / session tokens in localStorage or
  sessionStorage (`browser_application`).
- **Vulnerable JS libraries, secrets in bundles, exposed source maps** —
  `browser_sources`, confirmed by `browser_audit`.
- **CSP / CORS** — `unsafe-inline`/`unsafe-eval`/wildcards; CORS that reflects
  any Origin with credentials (check the API calls in `browser_network`).
- **Console leaks** — stack traces and internal paths (`browser_console`).
- **APIs** — every XHR/fetch endpoint in the API map is a target for
  `detect_web` (injection, errors) and for access-control review.
- Never click or crawl state-changing links (logout, delete, reset…); the
  crawler skips them by design.

## Safe-verification rules
- Read-only. Confirm with reflection, boolean differential, a single bounded
  time delay, or presence-of-artifact. Stop at proof — never weaponize.
- A class that cannot be safely confirmed stays **SUSPECTED** (not reported).
