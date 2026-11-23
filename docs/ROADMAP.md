# AutoPwn AI — Build Plan (Phases & Tasks)

> The implementation roadmap we follow into the coding phase.
> Design reference: [`ARCHITECTURE.md`](ARCHITECTURE.md). Every decision here is
> already locked unless marked **⟐ lock at phase start**.

**Legend:** `[x]` done · `[ ]` to do · **DoD** = Definition of Done ·
**⟐** = a small decision to finalize when that phase begins.

---

## Information check (is everything we need settled?)

**Locked** (from the requirements pass): identity (Purple, safe-verification),
**domains = web · networking (incl. local/LAN) · servers · Android** (web/network/
server primary), **conversational interface** (natural-language chat, no command
syntax), soft scope + full-trust + ack log,
autonomous + HITL modes, self-contained container, CLI/TUI (Linux), single agent
+ methodology planner, native+MCP tool harness, redaction/data-governance,
externalized state + per-target memory, provider-agnostic single LLM, PDF/JSON/MD
reports with CVSS, two-level eval, non-destruction by toolset curation, and the
**brand/UI** (official logo + Home / QuickStart design, now the TUI shell).

**Not blockers — resolved inside their phase (⟐):**
1. "coverage-complete" termination signal → **Phase 3**
2. exact recon tool set + flags → **Phase 2**
3. v1 vulnerability-class coverage list → **Phase 3**

➡️ Nothing blocks the start of coding. Phase 0 begins immediately.

---

## Build order (dependency flow)

```
P0 Foundation ─▶ P1 Agent Core ─▶ P2 Recon + Tools + Governance ─▶ P3 Detection + Verify
                                                                         │
     P6 Live TUI ◀────────────────────────────────────────────────┐     ▼
          ▲                                                        └─ P4 Reporting
          │                                                             │
   P7 Evaluation ◀── P5 Memory & Context ◀───────────────────────────── ┘
          │
          ▼
   P8 Hardening & Packaging  ──▶  v1.0
```

TUI (P6) can start in parallel after P1 (it only needs the engine's event
interface). Everything flows into P7/P8.

---

## Cross-cutting (applies to EVERY phase)

- **Authorized-only:** scope prompt + ack enforced at run start; nothing outside declared scope.
- **Data governance:** secrets never reach the LLM — redaction + local vault, re-injected at execution.
- **Safe verification:** non-destructive only; destructive capabilities are never built (toolset curation).
- **Observability:** structured logs + per-step traces (tool, tokens, latency) from day one.
- **Tests:** each phase ships unit/integration tests; no phase is "done" without them.

---

## Phase 0 — Foundation & Scaffolding   *(done — engine boots)*

**Goal:** a runnable skeleton with config, logging, the LLM adapter, and the state store.

- [x] Project structure, packaging (`pyproject.toml`), venv
- [x] UI theme + official logo (pixel-exact) + Home / splash screens (static)
- [x] Architecture & design docs
- [x] **Config system** — `config.toml`: provider, model, API key (via env), profiles (safe/standard), scope defaults, rate limits
- [x] **Run context** — per-run directory (`runs/<id>/`) for logs, artifacts, state; structured logger
- [x] **LLM adapter** — a thin `LLMProvider` interface over **LiteLLM** (one API → 100+ providers + local models, with tool-calling & streaming); `supports_function_calling()` gate at startup; wrapped behind our own types so we're never locked to it
- [x] **State store** — SQLite schema: `runs`, `targets`, `findings`, `artifacts`, `memory`

**Deliverable:** `autopwn run "<goal>" --target <t>` boots, loads config, does a live LLM round-trip (no tools yet).
**DoD:** config + logging + run-dir in place; one real LLM call through the adapter; tests green.
**⟐ lock:** default model + minimum model requirements; `config.toml` shape; run-dir layout.

---

## Phase 1 — Agent Core (the brain)   *(done — loop runs end-to-end)*

**Goal:** the methodology-driven think→act→observe loop with a working tool harness.

- [x] **Agent loop** — think → act → observe; `max_steps` + budget guard (tokens/time)
- [x] **Tool harness (native)** — tool registry (name, input schema, handler), dispatch, structured results, good error messages
- [x] **MCP client** — connect external MCP servers, surface their tools alongside native ones
- [x] **Prompts** — system prompt + Scope prompt assembly; behavior/consent text
- [x] **Planner** — phase state machine (`recon → planning → detection → verify → report`); methodology selection (OWASP / PTES) stub
- [x] **Context manager v1** — message history + compaction hook
- [x] **Modes** — autonomous vs human-in-the-loop; approval gate points
- [x] **Conversational interface** — natural-language chat is the only interface; the LLM turns intent into plans and tool-calls directly. No command DSL.

**Deliverable:** the agent runs a full loop with 1–2 dummy tools and returns a final answer from a plain-English request.
**DoD:** loop terminates, respects `max_steps`, calls a tool, feeds the result back; HITL pause works.
**⟐ lock:** approval gate points; planner phase contract.

---

## Phase 2 — Recon, Tooling & Data Governance   *(done — deep recon + secrets stay local)*

**Goal:** real recon tools across domains, the browser, secret handling, and the findings store.

- [x] **Web recon** — `httpx` (`http_probe`), `subfinder` (`subdomain_discovery`), `dnsx` (`dns_records`), `gau` (`known_urls`), `katana` (`crawl`), `ffuf` (`content_discovery`); structured JSON parsers
- [x] **Network recon (incl. local/LAN)** — service/version enumeration with `nmap` (safe flags), `naabu` connect-scan fallback, then a pure-Python connect scan
- [x] **Server/infra recon** — TLS/headers, exposed panels/services, software/version fingerprint
- [x] **Mobile intake** — APK unpack + static inventory (manifest, components, libs, secrets) — groundwork for P3 mobile detection
- [x] **Browser MCP** — Playwright/CDP: read DOM / network / cookies; **authenticated-session** support (user logs into their own target)
- [x] **Redaction layer** — local secret vault; tokenize secrets → placeholders for the LLM; re-inject real values locally at execution
- [x] **Findings store** — wire `core/findings.py` schema to SQLite; artifact storage (requests, screenshots)
- [x] **Target model** — per-domain fingerprint → tech/stack/attack-surface picture

**Deliverable:** agent performs **deep recon** on web / network / server / mobile targets and stores a complete structured picture; secrets stay local.
**DoD:** recon produces a tech+surface map per domain; a captured cookie appears as a placeholder in LLM context, real value used only locally; redaction unit tests pass.
**⟐ lock:** exact tool set + flags per domain; vault storage + encryption.

---

## Phase 3 — Detection & Safe Verification   *(done — detect→verify, FP-filtered)*

**Goal:** find vulnerabilities across domains and confirm them non-destructively.

- [x] **Skills / playbooks (per domain)** — Markdown playbooks loaded per phase:
  - *Web:* OWASP WSTG / Top-10 — SQLi, XSS, SSRF, IDOR, auth, access control, misconfig…
  - *Network:* weak/exposed services, default creds (safe check), known-CVE by version
  - *Server:* misconfig, exposed panels, outdated software, TLS/header issues
  - *Mobile (Android):* static — secrets, insecure storage, exported components, weak crypto; + backend API checks
- [x] **Detection tools** — web: `nuclei` (`template_scan`, safe tag set), `ffuf`, custom probes · network: service/CVE checks · mobile: static-analysis engine (MobSF-style)
- [x] **Safe-verification engine** — per class, non-destructive confirmation (boolean/time-based, reflection, differential); **no destructive ops**
- [x] **Findings pipeline** — `suspected → verified`; CVSS scoring; dedup; only verified findings are reportable (the FP filter)
- [x] **Coverage model** — define & implement the **"coverage-complete"** signal (per-domain surface checklist + no-new-findings plateau + budget)

**Deliverable:** end-to-end scan of a known-vuln target (web / network / mobile) yields **verified** findings.
**DoD:** on Juice Shop / DVWA (web) and a vulnerable VM/APK, finds + verifies planted issues; false positives filtered by verification; coverage signal stops the loop cleanly.
**⟐ lock:** v1 vuln-class coverage list per domain; CVSS auto-scoring method.

---

## Phase 4 — Reporting   *(done — PDF/JSON/MD/HTML, 2 styles)*

**Goal:** professional, defender-framed reports.

- [x] **Report builder** — Jinja2 templates → **PDF** (WeasyPrint), **JSON**, **Markdown**
- [x] **Finding render** — CVSS + priority, evidence, safe PoC, 🔵 detection guidance, 🔵 remediation
- [x] **Styles** — pluggable templates (technical / executive to start)
- [x] **Report tools** — exposed to the agent so it generates the report itself

**Deliverable:** a professional PDF + JSON + MD report from a scan.
**DoD:** report renders every finding field incl. the two purple fields; valid JSON; style switch works.

---

## Phase 5 — Memory & Context   *(done — cross-run memory + bounded context)*

**Goal:** smarter re-scans and bounded context on long runs.

- [x] **Per-target memory** — persist across runs; retrieval tools
- [x] **Context compaction** — at phase boundaries; working-summary + findings index in-context, details on demand
- [x] **Knowledge base** — signatures / techniques; encryption at rest for stored target data

**Deliverable:** re-scanning a target reuses prior knowledge; a long scan never blows the context window.
**DoD:** second run references the first; long run stays within context budget.

---

## Phase 6 — Live TUI (Textual)   *(done — interactive app wired to the engine)*

**Goal:** turn the static design into an interactive app wired to the engine.

- [x] **Port to Textual** — Home, scan/chat view, QuickStart wizard, command palette, findings view (from the implemented design)
- [x] **Wire to engine** — live stream, phase stepper, findings panel, job progress, HITL approvals
- [x] **Keybindings / modes / roles** — Pentester / Scope Approver / Admin / Viewer (per the design)

**Deliverable:** interactive TUI driving real scans.
**DoD:** run a scan from the TUI, watch phases + findings live, approve a HITL step.

---

## Phase 7 — Evaluation   *(done — 100% detection / 0 FP on planted target)*

**Goal:** prove it's strong, measurably.

- [x] **Benchmark harness** (pytest) — targets with ground-truth lists:
  - *Web:* Juice Shop, DVWA, WebGoat, bWAPP
  - *Network/Server:* Metasploitable, VulnHub VMs
  - *Mobile:* vulnerable APKs (DIVA, InsecureBankv2, Pivaa)
  - + custom planted-vuln targets
- [x] **Metrics** — detection rate, **false positives**, false negatives, time, cost, depth; regression report per build
- [x] **Graders** — code-based + LLM-as-judge + human-review rubric (report quality / depth / purple-framing)

**Deliverable:** a scored benchmark run + report-quality rubric.
**DoD:** metrics computed vs ground truth; tracking toward ~99% detection with very low FP; regression suite runs in CI.

---

## Phase 8 — Hardening & Packaging   *(done — container + audit log + docs)*

**Goal:** the self-contained product.

- [x] **Container** — Dockerfile bundling every security tool; Linux base; `docker run autopwn`
- [x] **Security** — secrets management, encryption at rest, audit log; legal ack + scope + non-destructive-by-toolset verification
- [x] **Docs** — user guide, install, provider setup; README polish

**Deliverable:** `docker run autopwn` runs a full scan + report with zero host dependencies.
**DoD:** fresh machine (Docker only) completes an end-to-end scan + report.

---

## v1.1 — Production   *(done)*

- [x] **Hard scope gate at the tool layer** — every target-touching tool is checked against in/out-of-scope (hosts, `*.wildcards`, CIDR, URLs); active tools also need the authorization ack
- [x] **Scanner manager** — `autopwnai tools install` fetches nuclei, httpx, subfinder, katana, dnsx, naabu, ffuf, gau from official releases, SHA-256 verified, no root
- [x] **Scanner tools for the agent** — 7 new native tools over those binaries, rate-limited, time-boxed, intrusive templates excluded; nuclei matches flow into the findings pipeline
- [x] **MCP server mode** — `autopwnai mcp-serve` exposes the toolset to any MCP client, same scope gate and audit log
- [x] **SARIF 2.1.0 reports** — for GitHub code scanning and CI dashboards
- [x] **First-run setup wizard** + key verification; **one-line installer**; CI on 3.12–3.14; macOS host support

## v2 (explicitly deferred)

Orchestrator + sub-agents · model routing · Windows host support.

---

## Milestones

| Milestone | Phases | Outcome |
|---|---|---|
| **M1 — Engine walks** | P0–P1 | agent loop + tools, dummy end-to-end |
| **M2 — Finds & verifies** | P2–P3 | real recon → verified web findings |
| **M3 — Reports** | P4–P5 | professional reports + memory |
| **M4 — Product** | P6–P8 | live TUI, evaluated, packaged → **v1.0** |
