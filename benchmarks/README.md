# AutoPwn AI — Benchmarks

Ground-truth targets for the evaluation harness (`autopwn.eval`). Each target
lists the vulnerability classes (`autopwn.detect.signatures.VULN_CLASSES` ids) it
is known to contain; the harness runs the real, non-destructive detection →
safe-verification pipeline and scores the verified findings against that list
(detection rate, **false positives**, false negatives, precision, F1).

## Offline (always runnable)

The **planted-web** target is an in-process, deliberately-vulnerable HTTP app
served on localhost. It needs no external services and is fully deterministic —
this is what CI runs.

```python
from autopwn.eval import run_local_benchmark
run = run_local_benchmark()
print(run.report.to_markdown())
```

Ground truth: `sqli`, `xss_reflected`, `security_misconfig`, `sensitive_file`,
`cookie_flags`.

## External targets (require a reachable instance)

`external_targets.json` catalogues real intentionally-vulnerable apps with their
ground truth: OWASP Juice Shop, DVWA, WebGoat, bWAPP (web); Metasploitable2
(network); DIVA, InsecureBankv2, Pivaa (mobile). These are gated behind
`requires_instance` — stand up the instance, set its `base_url`, then run the
harness against it. Example:

```bash
docker run -p 3000:3000 bkimminich/juice-shop   # then:
# autopwn eval --target "OWASP Juice Shop"
```

Network and mobile targets are evaluated through the same pipeline via the recon
and detection tools against the host IP or APK path, respectively.
