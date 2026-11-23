# Security policy

## Reporting a vulnerability in AutoPwn AI

Please **do not open a public issue** for security problems in the tool itself.
Use GitHub's private vulnerability reporting (*Security → Report a vulnerability*)
on this repository. Include what you found, how to reproduce it and the version
(`autopwnai --version`). You will get an acknowledgement within a few days.

In scope: anything that could leak provider keys or secrets, run commands outside
the curated toolset, bypass scope/authorization, approvals or the audit log, or
let a target or an MCP server inject instructions that change the agent's safety
behaviour.

## Responsible use

AutoPwn AI performs real network actions. Use it only against systems you own or
are explicitly authorized in writing to test, within the agreed scope. It verifies
findings non-destructively and has no exploitation, exfiltration or denial-of-service
capability by design. The first-run setup records your acknowledgement of this,
and every session keeps a tamper-evident audit log.

## How keys and data are handled

- Provider keys are stored encrypted on your machine (`~/.config/autopwn`,
  owner-only permissions) and are never written to logs or sent to the model.
- Secrets that tools encounter are replaced with `«secret:…»` placeholders
  before anything reaches the model.
- Nothing is sent anywhere except to the model provider you choose and the
  targets you authorize.
