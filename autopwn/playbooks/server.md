# Server / Infra Playbook (safe, non-destructive)

Transport and platform posture for a reachable host/service.

## Classes to cover (v1)
- **Weak/expired/self-signed TLS** — protocol < TLS1.2, expired or not-yet-valid
  cert, self-signed on a public service. The handshake/cert is the proof.
- **Missing security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-
  Options, Referrer-Policy on HTTP responses.
- **Exposed admin/management panel** — common paths (`/admin`, `/manager/html`,
  `/phpmyadmin`, `/.git/`, `/actuator`, `/server-status`) returning a real panel.
  Verify by signature in the body; never log in or submit.
- **Outdated software** — server/framework version in banners mapped to EOL/known
  issues (advisory → SUSPECTED unless behaviourally confirmed).

## Safe-verification rules
- GET/HEAD and TLS handshake only. Presence-of-artifact or the negotiated params
  are the proof. No authentication, no configuration changes.
