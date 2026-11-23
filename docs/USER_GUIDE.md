# AutoPwn AI — User Guide

A purple-team assistant for defenders: it finds weaknesses with offensive
techniques, **confirms them non-destructively**, and reports them the way a blue
team needs them — with detection guidance and a fix for every finding. You drive
it by chatting in plain language; there is no command language for the agent.

> ⚠️ **Authorized testing only.** Use AutoPwn AI exclusively against targets you
> own or are explicitly permitted to assess. It performs real network actions.

---

## 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/AshrafMostafaNmap/autopwn-ai/main/install.sh | sh
```

The installer uses [uv](https://docs.astral.sh/uv) (installed into `~/.local/bin`
if missing) to put AutoPwn AI in its own isolated environment with its own Python;
nothing is installed system-wide and nothing runs as root. Add options after
`sh -s --`: `--with-browser`, `--with-pdf`, `--ref <tag>`, `--uninstall`. Run it
again to update.

From a checkout instead: `sh install.sh --from .`, or for development
`python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"`.

This installs two equivalent commands: **`autopwnai`** and `autopwn`.

Optional extras:

| Extra | Adds | For |
|---|---|---|
| `pdf` | WeasyPrint | PDF reports (also needs pango/cairo system libraries) |
| `browser` | Playwright | browser recon of client-side apps (`playwright install chromium`) |

MCP support is built in. Recon/detection work with no external binaries;
`nmap`, `nuclei`, `ffuf`, `httpx`, `subfinder` are used automatically when
installed. The Docker image bundles all of them (§9).

## 2. Open the app

```bash
autopwnai
```

**First launch: setup.** A short wizard walks through:

1. **Welcome** — confirm you will only test systems you own or are authorized to
   test (recorded in the audit log), and your name for the audit trail.
2. **Providers** — tick the ones you have. Keys in your environment, keys already
   saved, AWS credentials and running Ollama / LM Studio servers are detected and
   ticked for you.
3. **Keys** — paste each key; it is **checked with the provider** (a free
   model-list call — no tokens spent) before it is saved, encrypted.
4. **Model** — the default model, from the providers you connected.
5. **Preferences** — human-in-the-loop (recommended to start) or autonomous,
   optional MCP servers, and which scanners are installed (with install commands).

Run it again any time: `autopwnai setup` or `/setup` inside the app.

It opens on a home screen with the prompt at the bottom. Once you send a
message the session view takes over:

- **conversation** — your messages (green bar), the agent's short narration,
  every tool call on one line that updates in place (spinner → ✓ / ✗ / ⊘ with
  its duration), the answer in Markdown, and verified findings as they are
  confirmed;
- **status bar** — mode badge (AUTO / HITL), model, current phase, scope ✓ when
  authorized, context use (tokens and %), session cost, findings count.

| key | does |
|---|---|
| Enter | send (on a half-typed `/command`, completes and runs it) |
| `/` | command autocomplete; Tab or Enter picks |
| Tab | autonomous ⇄ human-in-the-loop |
| Esc | interrupt the running turn |
| ↑ / ↓ | prompt history |
| PgUp / PgDn | scroll the conversation |
| Ctrl+P | command menu (fuzzy search) |
| Ctrl+X, then a letter | shortcut: `n` new · `l` sessions · `m` model · `p` provider · `g` MCP · `s` scope · `t` tools · `i` context · `c` compact · `f` findings · `r` report · `y` memory · `x` export · `h` help · `q` quit |
| F3 | cycle operator role |
| mouse drag | select text anywhere in the chat |
| Ctrl+C | copy the selection · with nothing selected, clear the prompt · press twice to save and quit |

## 3. Connect a provider and pick a model

On first run the **Providers** screen opens by itself. Choose a provider, paste
your API key, press **Save**. The key is stored **encrypted on this machine**
(`~/.config/autopwn/credentials.enc`, owner-only permissions) and is never
written to logs or sent to the model.

Then **Pick a model** (or `/model`): the list shows only models that support
tool-calling — the agent needs it — with their context size. Type to filter, or
type a full id such as `openai/gpt-5.5` and press Enter. OpenRouter's list is
fetched live and marks the **free** models; `openrouter/openrouter/free` routes
to whichever free tool-capable model is available.

| Provider | example model | key |
|---|---|---|
| Anthropic | `anthropic/claude-sonnet-5-5` | API key |
| OpenAI | `openai/gpt-5.5` | API key |
| Google Gemini | `gemini/gemini-2.5-pro` | API key |
| OpenRouter, Groq, Mistral, DeepSeek, xAI, Together, Fireworks | from the list | API key |
| Azure OpenAI | your deployment | API key + endpoint |
| AWS Bedrock | from the list | your AWS credentials |
| Ollama / LM Studio (local) | models you have pulled | none |
| any OpenAI-compatible server | `openai_compatible/<model>` | endpoint (key optional; never your OpenAI key) |

From the shell instead:

```bash
autopwnai connect anthropic            # hidden prompt, stored encrypted
autopwnai connect ollama --api-base http://10.0.0.5:11434
autopwnai models openai                # tool-capable models
autopwnai providers                    # what is connected, and from where
autopwnai doctor                       # is the active model ready?
```

Environment variables still work (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …) and
are picked up automatically; a key stored in the app takes precedence.

## 4. Set scope and authorization

`/scope` (do this before testing):

- **in scope** — hosts, URLs, wildcards (`*.lab.local` — also matches
  `lab.local`), IPs or CIDR ranges (`10.0.5.0/24`) the agent may assess;
- **out of scope** — never touched, even when it matches an in-scope wildcard;
- **domain** — web, network, server or mobile (selects the methodology:
  OWASP WSTG, PTES, MASVS);
- **run mode** — autonomous, or human-in-the-loop (you approve every tool call);
- **authorization** — confirm you are permitted to test these targets.

Every change is recorded in the run's tamper-evident audit log.

**The scope gate is enforced in code, not by the model.** Before any tool that
touches a target runs, its targets are checked against these lists; anything
outside is refused with the reason, and tools that send traffic (scans, probes,
crawls, templates) additionally need the authorization confirmed. Passive tools
(subdomain discovery from public sources, archived URLs, DNS) only need the target
in scope. Subdomains found outside scope are listed but never tested until you add
them.

## 5. Work with the agent

Talk to it normally, for example:

- *map juice.company.lab — what is it built with and what is exposed?*
- *check the login and search endpoints for injection*
- *verify what you found, then write the executive report*

The agent follows recon → planning → detection → verification → report. It is
not time-boxed. Only findings it can **safely verify** count; everything else
stays "suspected" and never reaches the report — that is the false-positive
filter.

**Approvals.** In human-in-the-loop mode, and for tools that always ask (browser
recon, untrusted MCP servers), a dialog shows the exact tool and arguments:
**a** (or **y**) approves, **d** / **n** / **Esc** declines. A declined call is
reported back to the agent, which adapts. **F3** cycles the operator role; the
*Viewer* role cannot approve.

**Sessions.** Every session is saved as you go (conversation, findings, scope).
`/sessions` lists earlier ones; pick one to continue exactly where it stopped.
`/new` starts fresh and keeps the current one.

## 6. Scanners

The agent drives well-known open-source scanners when they are installed, and
falls back to built-in Python checks when they are not:

| tool the agent calls | scanner | what it does |
|---|---|---|
| `http_probe` | httpx | live hosts, status, title, server, technologies, CDN |
| `subdomain_discovery` | subfinder | passive subdomains (public sources only) |
| `dns_records` | dnsx | A/AAAA/CNAME/MX/NS/TXT records |
| `known_urls` | gau | historical URLs and parameters from public archives |
| `crawl` | katana | endpoints and forms, same host, depth ≤ 3 |
| `content_discovery` | ffuf | sensitive paths from a short built-in list |
| `template_scan` | nuclei | known CVEs, exposures, misconfigurations → findings |
| `network_scan` | nmap → naabu → Python | open ports and service versions |

Everything runs rate-limited and time-boxed. nuclei runs in safe mode: DoS,
fuzzing, brute-force, RCE, LFI, upload and takeover templates are excluded. By
default it runs the exposure, misconfiguration, admin-panel and technology checks
(a few minutes per target); ask for a CVE sweep (`tags: cve`) or everything
(`full`) when you want it. Results for the same template and URL are merged
(e.g. one "missing security headers" result listing each header); low and above
become *suspected* findings that still go through verification, informational ones
stay in the tool output.

```bash
autopwnai tools                 # what is installed, versions, how to get the rest
autopwnai tools install         # all downloadable scanners (official releases, SHA-256 checked, no root)
autopwnai tools install nuclei  # just one
autopwnai tools update          # newer releases + fresh nuclei templates
```

They go into `~/.local/share/autopwn/bin` (or `$AUTOPWN_HOME/data/bin`). nmap,
dig and openssl come from your system's package manager — the command for your
system is printed.

## 7. MCP servers

`/mcp` lists your servers. **Enter** connects / disconnects, **p** adds a
preset, **a** adds your own, **d** removes one.

Presets (one key, no configuration):

| preset | what the agent gets | runs with |
|---|---|---|
| `fetch` | fetch any URL as Markdown | `uvx` |
| `filesystem` | read and write files inside one folder you choose | `npx` |
| `git` | inspect a repository's history and diffs | `uvx` |
| `browser` | a headless Playwright browser | `npx` |
| `thinking` | structured step-by-step reasoning (trusted) | `npx` |
| `knowledge-graph` | a persistent entity/relation memory (trusted) | `npx` |
| `time` | current time and timezone conversion (trusted) | `uvx` |

Your own server: a name and either a **command + arguments** (stdio) or a
**URL** (streamable HTTP or SSE, optional headers), optional env vars, and
whether it is **trusted** (trusted tools run without asking; untrusted ones ask
every time). Its tools join the agent's toolbox immediately (`/tools` lists them
as `server__tool`); if it exposes resources, `list_resources`/`read_resource`
are added too. Enabled servers reconnect when the app starts, and a dropped
connection is re-established once automatically. A server's own log output goes
to `runs/<id>/mcp-<name>.log`, never the screen.

Servers can also be declared for a whole project in `config.toml`:

```toml
[[mcp.servers]]
name = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/srv/evidence"]
trusted = false
```

### AutoPwn as an MCP server

The other direction works too: `autopwnai mcp-serve` exposes AutoPwn's own tools
(recon, scanners, detection, verification, findings, reports, memory) to any MCP
client — Claude Desktop, an IDE, another agent — with the same scope gate and audit
log. Scope is fixed when the server starts:

```json
{
  "mcpServers": {
    "autopwn": {
      "command": "autopwnai",
      "args": ["mcp-serve", "-t", "app.lab", "-t", "*.app.lab", "--authorize"]
    }
  }
}
```

Without `--authorize` only passive tools run.

## 8. Findings, reports, memory, context

- **`/findings`** — every finding: status, severity, CVSS, evidence, the safe
  proof, 🔵 how to detect it, 🔵 how to fix it.
- **`/report`** — PDF, HTML, JSON, Markdown and/or SARIF (for GitHub code scanning and CI dashboards); *technical* (full evidence) or
  *executive* (business summary). Built from verified findings only; files land
  in `runs/<id>/reports/`.
- **`/memory`** — long-term memory per target, across runs (encrypted at rest):
  facts the agent learned, finding history and a short summary of each past
  session. It is given to the agent at the start of every turn, and the next
  run reports what is **new / fixed / reopened**.
- **`/context`** — short-term memory: how full the model's context window is,
  measured in real tokens for the active model. When the conversation nears its
  budget, older turns are folded into a running working summary (written by the
  model, with a deterministic fallback) while recent turns stay verbatim.
  `/compact` forces it.

Other controls: `/mode`, `/new` (start fresh — the current session is saved),
`/help`, `/quit` (or Ctrl+C — saves).

### Exporting the chat

`/export` saves the **whole** conversation — every question you asked and every
answer — even after older turns were compacted out of the model's context or
the session was resumed. Pick a format:

| choice | gives |
|---|---|
| **Text** (default) | a plain `.txt`: your questions and the answers, Markdown noise removed (tables aligned, bullets as •) |
| Text — with tool activity | the same plus the agent's narration and each tool call |
| Markdown | questions, answers, the agent's narration and each tool call (✓/✗, args, duration), verified findings |
| Markdown — conversation only | just your questions and the answers |
| HTML / HTML — conversation only | the same as a styled page (light/dark, Arabic shown right-to-left); print it to PDF from the browser |

Shortcuts: `/export txt`, `/export md`, `/export html`, `/export html clean`.
Files land in `runs/<id>/exports/chat-<time>.<txt|md|html>`; the app shows the
full path.

### Copying from the chat

- **Drag with the mouse** over any part of the chat (answers included), then
  **Ctrl+C** — it goes to the clipboard.
- **`/copy`** copies the last answer as-is (Markdown); **`/copy N`** copies
  answer number N (each answer shows its `/copy N` under it); **`/copy all`**
  copies the whole chat as clean text.

All of these are on screen: type `/` and the autocomplete offers `/copy`,
`/copy all`, `/export txt`, `/export txt full`, `/export md` and `/export html`
(arrows + Enter runs one); the same entries are in the **Ctrl+P** menu, and
**Ctrl+X o** / **Ctrl+X x** are the shortcuts for copy / export.

The clipboard is set through the terminal (OSC 52) and, on Linux/macOS, through
`wl-copy`, `xclip`, `xsel` or `pbcopy` when installed. Your terminal's own
selection still works too — usually **Shift + drag**.
Secrets appear only as `«secret:…»` placeholders, as everywhere else.

From the shell, for any saved session:

```bash
autopwnai export --list                         # saved sessions
autopwnai export                                # latest → .txt
autopwnai export 20261123-1042 --format html --clean -o ~/chat.html
```

## 9. One-shot runs (scripts / CI)

```bash
autopwnai run "assess example.lab for misconfiguration and report" \
    -t example.lab --domain web --authorize
```

Options: `--model`, `--profile`, `--hitl`, `--operator`, `--no-llm` (assemble the
engine without calling the model). Uses the same provider/key/model as the app.

## 10. Container (zero host dependencies)

```bash
docker build -t autopwn .
docker run --rm -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
    -v "$PWD/engagements:/engagements" autopwn \
    run "assess example.lab" -t example.lab --authorize
```

Bundles `nmap`, `masscan`, `nuclei`, `httpx`, `ffuf`, `subfinder`, `katana`,
`dig`, `openssl`, `curl`; runs as a non-root user.

## 11. Where things are stored

| what | where |
|---|---|
| app settings (model, MCP servers, mode) | `~/.config/autopwn/settings.json` |
| provider keys (encrypted) | `~/.config/autopwn/credentials.enc` + `credentials.key` |
| run folders (events, state, audit, reports) | `./runs/` inside a project with `config.toml`, else `~/.local/share/autopwn/runs/` |
| cross-run target memory (encrypted) | `~/.local/share/autopwn/memory.db` |

Set `AUTOPWN_HOME` to keep everything under one directory instead.

## 12. Safety & data governance

- **Scope + authorization** are part of every session and recorded in a
  hash-chained audit log (`runs/<id>/audit.jsonl`, verifiable).
- **Safe verification only** — non-destructive proofs; no exploitation,
  exfiltration or DoS (those capabilities are not in the toolset).
- **Secrets stay local** — credentials and cookies the tools encounter are
  replaced by `«secret:…»` placeholders before anything reaches the model; real
  values are re-injected only locally at execution.

## 13. Troubleshooting

| symptom | fix |
|---|---|
| ○ in the header / "no API key" | `/provider`, paste the key, Save |
| "does not support tool-calling" | `/model` and pick a listed model |
| "rate-limited upstream" on a free model | free models are shared; retry, or pick `openrouter/openrouter/free` |
| "tool-calling support … unverified" | the model is not in the catalog (local/new); it is allowed — the first request confirms it |
| Ollama / LM Studio "not running" | start the server (`ollama serve`, or LM Studio's local server) or set its endpoint in `/provider` |
| "needs an endpoint" (Azure, OpenAI-compatible) | `/provider` → set the API base URL |
| Bedrock "needs credentials" | set `AWS_PROFILE` / `AWS_ACCESS_KEY_ID`, or `~/.aws/credentials` |
| "not found or this API key cannot access it" | the key is wrong or the model is not on your plan (Fireworks reports both this way) |
| MCP server "error" in `/mcp` | check the command/arguments; details in `runs/<id>/mcp-<name>.log` |
| PDF skipped in `/report` | `pip install ".[pdf]"` plus pango/cairo |
| browser tool unavailable | reinstall with `install.sh --with-browser` |
| "blocked by the scope gate" | the target is not in scope or not authorized — `/scope` |
| "nuclei is not installed" (or another scanner) | `autopwnai tools install` |
