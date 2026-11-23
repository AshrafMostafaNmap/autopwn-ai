# Changelog

## 0.1.0

First public release.

- Chat-driven purple-team agent with a methodology planner (recon → detection →
  verification → report) for web, network, server and Android targets.
- Provider-agnostic through LiteLLM: 15 providers including OpenRouter free models,
  local Ollama / LM Studio and any OpenAI-compatible server; keys verified with the
  provider and stored encrypted.
- Hard scope gate enforced in code (hosts, wildcards, CIDR, exclusions, authorization).
- Real browser for the agent (headless Chromium/Chrome): one tool per DevTools tab —
  Elements, Console, Sources, Network, Performance/Memory, Application, Security —
  plus a JS-aware crawler, a passive client-side audit, safe DOM-XSS proofs, login
  with vaulted credentials, and `web_deep_scan`; navigation and every redirect hop
  are scope-checked. Nine new client-side vulnerability classes.
- `autopwnai mcp-serve --toolset browser|web|all`.
- Scanner integration: nuclei, httpx, subfinder, katana, dnsx, naabu, ffuf, gau, nmap;
  `autopwnai tools` installs them from official releases with SHA-256 verification.
- Safe, non-destructive verification; only verified findings are reported.
- Reports: PDF, HTML, Markdown, JSON, SARIF; technical and executive styles.
- MCP client (presets + stdio / HTTP / SSE) and MCP server mode (`autopwnai mcp-serve`).
- Short- and long-term memory; resumable sessions; chat export and copy.
- OpenCode-style terminal app with a first-run setup wizard.
- One-line installer, Docker image, CI on Python 3.12–3.14.
