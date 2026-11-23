# Mobile (Android) Playbook — OWASP MASVS/MASTG, static (safe)

Static analysis of the APK contents already inventoried in recon. No dynamic
execution, no instrumentation in v1 — read-only over the unpacked package.

## Classes to cover (v1)
- **Hardcoded secrets** — API keys, tokens, private keys, cloud creds in dex/
  resources/assets. The matched secret (vaulted) is the proof.
- **Cleartext traffic allowed** — `android:usesCleartextTraffic="true"` or a
  permissive network-security-config.
- **Exported components** — activities/services/receivers/providers exported
  without permission (attack surface).
- **Debuggable build** — `android:debuggable="true"`.
- **Weak crypto** — ECB mode, hardcoded IV/key, MD5/SHA1 for security, `DES`.
- **Insecure storage hints** — world-readable modes, external storage of secrets.
- **Backend API checks** — endpoints found in the APK re-checked with the web
  playbook (with authorization).

## Safe-verification rules
- Pure static signature/structure checks over the package. The artifact (string,
  manifest flag, component attribute) is the proof. Nothing runs.
