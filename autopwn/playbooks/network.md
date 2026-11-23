# Network Playbook — PTES (safe, non-destructive)

Discover hosts/services, then flag weak exposure. No exploitation, no brute-force,
no destructive checks. "Default creds" means a *safe* single documented-default
probe only where protocol allows an unauthenticated banner — never a credential
spray.

## Classes to cover (v1)
- **Unauthenticated exposed datastore** — Redis, MongoDB, Elasticsearch,
  Memcached, Docker API open to the network. Verify by a read-only, no-auth
  protocol hello (e.g. Redis `PING`/`INFO`, Mongo `ismaster`) that returns data
  without credentials. Never write, never dump datasets.
- **Cleartext service** — Telnet, FTP, plain HTTP on sensitive hosts, unencrypted
  DB ports reachable. The open cleartext port is the proof.
- **Anonymous FTP** — connect, try the documented `anonymous` login, list nothing;
  the accepted anonymous banner is the proof. No file retrieval.
- **Known-vulnerable version** — map service banner/version → known CVE class
  (heuristic, advisory). Mark SUSPECTED unless a safe behavioural check confirms.

## Safe-verification rules
- Connect + read-only protocol query only. If confirming needs a write, an auth
  attempt beyond a documented default, or any payload — do NOT do it; leave it
  SUSPECTED and note what a human should check.
