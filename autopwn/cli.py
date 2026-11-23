"""Command-line entrypoint for `autopwnai` / `autopwn`. With no arguments it
opens the app; subcommands manage providers, models and one-shot runs.
"""
from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.table import Table

from . import __version__
from .ui.theme import THEME

console = Console(theme=THEME)


# ── app ───────────────────────────────────────────────────────────────────────
def cmd_app(args: argparse.Namespace) -> int:
    from .tui.app import run_app
    run_app(config_path=getattr(args, "config", None))
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    from .tui.app import run_app
    run_app(config_path=getattr(args, "config", None), setup=True)
    return 0


# ── doctor ────────────────────────────────────────────────────────────────────
def cmd_doctor(args: argparse.Namespace) -> int:
    from .config import ConfigError
    from .engine import EngineSession
    try:
        session = EngineSession.create(config_path=args.config, goal="doctor", ephemeral=True)
    except ConfigError as e:
        console.print(f"[red]config error:[/] {e}")
        return 2
    try:
        cfg = session.config
        console.print(f"[bold]config[/]     {cfg.source or 'built-in defaults (+ app settings)'}")
        console.print(f"[bold]model[/]      {session.model}")
        active = next(p for p in session.provider_status() if p["active"]) \
            if any(p["active"] for p in session.provider_status()) else None
        if active:
            state = "[green]connected[/]" if active["connected"] else "[red]not connected[/]"
            console.print(f"[bold]provider[/]   {active['label']}  {state}  ({active['source']})")
        console.print(f"[bold]profile[/]    {cfg.run.profile} ({cfg.active_profile().max_steps} max steps)")
        console.print(f"[bold]tools[/]      {len(session.registry)} registered")
        _print_scanners()
        state = session.ready()
        for w in state.warnings:
            console.print(f"[yellow]! {w}[/]")
        if state.ok:
            console.print("[green]✓ ready[/] — credentials resolve and the model can call tools.")
            return 0
        console.print(f"[red]✗ not ready:[/] {state.message}")
        return 1
    finally:
        session.close()


def _print_scanners() -> None:
    from .onboarding import scan
    console.print("[bold]scanners[/]")
    for t in scan().tools:
        if t.path:
            console.print(f"  [green]✓[/] {t.name:<11} [muted]{t.purpose}[/]")
        else:
            console.print(f"  [muted]·[/] {t.name:<11} [muted]{t.purpose} — install:[/] {t.install}", soft_wrap=True)


# ── MCP server ────────────────────────────────────────────────────────────────
def cmd_mcp_serve(args: argparse.Namespace) -> int:
    import anyio

    from .config import ConfigError, load_config
    from .engine import EngineSession
    from .mcp.server import serve_stdio

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    targets = list(args.target or [])
    if not targets:
        print("mcp-serve needs at least one --target (the scope is fixed for the server's lifetime)",
              file=sys.stderr)
        return 2
    session = EngineSession.create(config=cfg, goal="mcp server", targets=targets, domain=args.domain)
    session.set_scope(out_of_scope=list(args.exclude or []), authorized=bool(args.authorize))
    if not args.authorize:
        print("note: not authorized — only passive tools will run (add --authorize)", file=sys.stderr)
    try:
        anyio.run(serve_stdio, session)
    except KeyboardInterrupt:
        pass
    finally:
        session.close()
    return 0


# ── scanners ──────────────────────────────────────────────────────────────────
def cmd_tools(args: argparse.Namespace) -> int:
    from .recon import installer
    from .recon.runner import which

    if args.action in ("install", "update"):
        names = args.names or [s.name for s in installer.SCANNERS.values() if s.downloadable]
        failed = 0
        for name in names:
            try:
                path = installer.install(name, progress=lambda m: console.print(f"[muted]  {m}[/]"))
                console.print(f"[green]✓[/] {name} → {path}")
            except installer.InstallError as e:
                failed += 1
                console.print(f"[red]✗[/] {e}", soft_wrap=True)
        which.cache_clear()
        if "nuclei" in names and installer.resolve("nuclei"):
            ok = installer.update_nuclei_templates(lambda m: console.print(f"[muted]  {m}[/]"))
            console.print("[green]✓[/] nuclei templates up to date" if ok
                          else "[yellow]! nuclei templates could not be updated — run: nuclei -update-templates[/]")
        system = [r for r in installer.status() if not r["installed"] and not r["downloadable"]]
        for r in system:
            console.print(f"[yellow]·[/] {r['name']} is a system package — {r['system_hint']}", soft_wrap=True)
        return 1 if failed else 0

    table = Table(title="scanners", title_style="muted", header_style="muted", box=None, pad_edge=False)
    for col in ("", "tool", "purpose", "version", "location / how to install"):
        table.add_column(col)
    for r in installer.status():
        if r["installed"]:
            table.add_row("[green]✓[/]", r["name"], r["purpose"], installer.version_of(r["name"]), r["path"])
        else:
            how = f"autopwnai tools install {r['name']}" if r["downloadable"] else r["system_hint"]
            table.add_row("[muted]·[/]", r["name"], r["purpose"], "", f"[muted]{how}[/]")
    console.print(table)
    return 0


# ── providers / connect / models ──────────────────────────────────────────────
def cmd_providers(args: argparse.Namespace) -> int:
    from .engine import EngineSession
    session = EngineSession.create(goal="providers", ephemeral=True)
    try:
        t = Table(title="providers", header_style="bold")
        for col in ("provider", "status", "source", "key", "endpoint"):
            t.add_column(col)
        for p in session.provider_status():
            name = f"[bold]{p['label']}[/]" + ("  ◀ active" if p["active"] else "")
            status = "[green]connected[/]" if p["connected"] else "[dim]—[/]"
            t.add_row(name, status, p["source"], p["key"], p["api_base"] or "")
        console.print(t)
        return 0
    finally:
        session.close()


def cmd_connect(args: argparse.Namespace) -> int:
    import getpass

    from .llm.catalog import PROVIDERS
    from .settings import CredentialStore, Settings
    info = PROVIDERS.get(args.provider)
    if info is None:
        console.print(f"[red]unknown provider[/] '{args.provider}'. Known: {', '.join(PROVIDERS)}")
        return 2
    if args.api_base:
        s = Settings.load()
        s.api_bases[info.id] = args.api_base
        s.save()
        console.print(f"[green]✓[/] endpoint saved for {info.label}: {args.api_base}")
    if not info.requires_key and not args.key_prompt:
        console.print(f"{info.label}: no key needed.")
        return 0
    key = getpass.getpass(f"{info.label} API key (input hidden): ")
    if not key.strip():
        console.print("[yellow]nothing stored.[/]")
        return 1
    CredentialStore().set(info.id, key)
    console.print(f"[green]✓[/] {info.label} key stored locally (encrypted).")
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    from .llm.catalog import PROVIDERS, list_models
    providers = [args.provider] if args.provider else list(PROVIDERS)
    for pid in providers:
        if pid not in PROVIDERS:
            console.print(f"[red]unknown provider[/] '{pid}'")
            return 2
        models = list_models(pid)
        if not models:
            continue
        console.print(f"\n[bold]{PROVIDERS[pid].label}[/]  ({len(models)} tool-capable)")
        for m in models[: (None if args.provider else 6)]:
            ctxw = f"{m.context // 1000}k" if m.context else "?"
            star = "★ " if m.featured else "  "
            free = "  [green]free[/]" if m.free else ""
            console.print(f"  {star}{m.id}  [dim]{ctxw}[/]{free}")
    return 0


# ── run (one-shot) ────────────────────────────────────────────────────────────
def cmd_run(args: argparse.Namespace) -> int:
    from .config import ConfigError, load_config
    from .engine import EngineSession

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        console.print(f"[red]config error:[/] {e}")
        return 2
    if args.profile:
        cfg.run.profile = args.profile

    session = EngineSession.create(config=cfg, goal=args.goal, targets=list(args.target or []),
                                   domain=args.domain, echo=True, console=console)
    if args.operator:
        session.settings.operator = args.operator
    if args.model:
        session.set_model(args.model)
    session.set_scope(authorized=cfg.scope.authorized_ack or args.authorize)
    console.print(f"[dim]run[/] [bold]{session.ctx.run_id}[/]  → {session.ctx.run_dir}")

    if args.no_llm:
        console.print("[yellow]--no-llm:[/] boot check only — the engine assembled successfully.")
        session.close()
        return 0

    if args.hitl:
        from .agent.modes import console_prompt
        prompt = console_prompt(console)
        session.set_mode("hitl")
        session.set_approver(lambda call, tool: prompt(call, tool).approved)

    state = session.ready()
    if not state.ok:
        console.print(f"[red]not ready:[/] {state.message}")
        session.close("failed")
        return 1
    for w in state.warnings:
        console.print(f"[yellow]! {w}[/]")

    console.print(f"[dim]model[/] {session.model}  ·  [dim]mode[/] {session.mode}  "
                  f"·  [dim]methodology[/] {session.planner.methodology.value}  "
                  f"·  [dim]tools[/] {len(session.registry)}")
    result = session.chat(args.goal)

    console.print()
    if result.reason == "error":
        console.print(f"[red]error:[/] {result.error}")
    console.print(result.final or "[dim](no final answer)[/]")
    console.print()
    reportable = session.pipeline.reportable()
    if reportable:
        console.print(f"[bold]verified findings:[/] {len(reportable)}")
        for f in reportable[:12]:
            console.print(f"  [{f.severity.rating.value}] {f.title} · {f.target.url or f.target.host}"
                          f"{(' · ' + f.target.param) if f.target.param else ''}  (CVSS {f.severity.cvss_score})")
    deltas = session.close("completed" if result.reason != "error" else "failed")
    for host, summary in deltas.items():
        console.print(f"[dim]since last scan of {host}:[/] {summary}")
    console.print(f"[dim]reason[/] {result.reason}  ·  [dim]steps[/] {result.steps}  "
                  f"·  [dim]tool calls[/] {result.tool_calls}  ·  [dim]verified[/] {len(reportable)}")
    return 0 if result.reason != "error" else 1


# ── eval ──────────────────────────────────────────────────────────────────────
def cmd_eval(args: argparse.Namespace) -> int:
    from .eval import run_external_target, run_local_benchmark
    run = run_external_target(args.target) if args.target else run_local_benchmark()
    console.print(run.report.to_markdown())
    if args.out:
        from pathlib import Path
        Path(args.out).write_text(run.report.to_json(), encoding="utf-8")
        console.print(f"[dim]wrote[/] {args.out}")
    return 1 if run.report.summary()["total_false_positives"] else 0   # CI gate on FPs


# ── export ────────────────────────────────────────────────────────────────────
def cmd_export(args: argparse.Namespace) -> int:
    from pathlib import Path

    from .config import ConfigError, load_config
    from .engine import export_session, list_sessions, runs_root

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        console.print(f"[red]config error:[/] {e}")
        return 2
    sessions = list_sessions(runs_root(cfg), limit=200)
    if args.list:
        if not sessions:
            console.print("[muted]no saved sessions[/]")
        for s in sessions:
            console.print(f"[green]{Path(s['path']).name}[/]  {s['title']}  [muted]{s['turns']} turn(s)[/]")
        return 0
    if args.session:
        match = [s for s in sessions if Path(s["path"]).name.startswith(args.session)
                 or Path(s["path"]) == Path(args.session).expanduser()]
        if not match and Path(args.session).expanduser().is_dir():
            match = [{"path": str(Path(args.session).expanduser())}]
    else:
        match = sessions[:1]
    if not match:
        console.print(f"[red]no session matches[/] {args.session or ''}  [muted](autopwnai export --list)[/]")
        return 1
    if len(match) > 1:
        console.print(f"[orange1]{len(match)} sessions match {args.session!r} — use more of the id[/]")
        return 1
    out = Path(args.output).expanduser() if args.output else None
    path = export_session(Path(match[0]["path"]), args.format, tools=not args.clean, path=out)
    console.print(f"[green]✓[/] chat exported → {path.resolve()}")
    return 0


# ── parser ────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="autopwnai",
                                description="AutoPwn AI — purple-team vulnerability discovery agent")
    p.add_argument("--config", "-c", help="path to config.toml")
    p.add_argument("--version", action="store_true", help="print version")
    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("app", aliases=["tui"], help="open the interactive app (default)")
    a.set_defaults(func=cmd_app)

    st = sub.add_parser("setup", help="run the setup wizard (providers, keys, model, preferences)")
    st.set_defaults(func=cmd_setup)

    r = sub.add_parser("run", help="one-shot: run a natural-language goal and print the result")
    r.add_argument("goal", help="what to assess, in plain language")
    r.add_argument("--target", "-t", action="append", help="in-scope target (repeatable)")
    r.add_argument("--model", "-m", help="override the model id (e.g. openai/gpt-5.5)")
    r.add_argument("--profile", help="override the active profile (safe/standard)")
    r.add_argument("--domain", choices=["web", "network", "server", "mobile"],
                   help="target domain (selects methodology)")
    r.add_argument("--hitl", action="store_true", help="human-in-the-loop: approve every tool call")
    r.add_argument("--authorize", action="store_true",
                   help="acknowledge you are authorized to assess the targets")
    r.add_argument("--operator", help="operator name for the authorization/audit record")
    r.add_argument("--no-llm", action="store_true", help="assemble the engine without calling the model")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("doctor", help="check that the active model is ready")
    d.set_defaults(func=cmd_doctor)

    pr = sub.add_parser("providers", help="show provider connection status")
    pr.set_defaults(func=cmd_providers)

    c = sub.add_parser("connect", help="store a provider API key locally (encrypted)")
    c.add_argument("provider", help="provider id, e.g. anthropic, openai, gemini, ollama")
    c.add_argument("--api-base", help="custom endpoint (Azure, gateways, local servers)")
    c.add_argument("--key", dest="key_prompt", action="store_true",
                   help="prompt for a key even for providers that don't require one")
    c.set_defaults(func=cmd_connect)

    m = sub.add_parser("models", help="list tool-capable models")
    m.add_argument("provider", nargs="?", help="limit to one provider")
    m.set_defaults(func=cmd_models)

    ms = sub.add_parser("mcp-serve", help="serve AutoPwn's tools over MCP (stdio) for other MCP clients")
    ms.add_argument("--target", "-t", action="append", help="in-scope target (repeatable; wildcards and CIDR ok)")
    ms.add_argument("--exclude", "-x", action="append", help="out-of-scope target (repeatable)")
    ms.add_argument("--domain", choices=["web", "network", "server", "mobile"], default="web")
    ms.add_argument("--authorize", action="store_true",
                    help="acknowledge you are authorized to test the targets (enables active tools)")
    ms.set_defaults(func=cmd_mcp_serve)

    tl = sub.add_parser("tools", help="list, install or update the external scanners")
    tl.add_argument("action", nargs="?", choices=["list", "install", "update"], default="list")
    tl.add_argument("names", nargs="*", help="scanners to install (default: all downloadable)")
    tl.set_defaults(func=cmd_tools)

    x = sub.add_parser("export", help="export a saved chat as clean text, Markdown or HTML")
    x.add_argument("session", nargs="?", help="session id (or prefix / folder); default: the latest")
    x.add_argument("--format", "-f", choices=["txt", "md", "html"], default="txt")
    x.add_argument("--clean", action="store_true", help="questions and answers only, no tool activity")
    x.add_argument("--output", "-o", help="file to write (default: <session>/exports/chat-<time>.<fmt>)")
    x.add_argument("--list", action="store_true", help="list saved sessions")
    x.set_defaults(func=cmd_export)

    e = sub.add_parser("eval", help="run the benchmark harness (offline planted target by default)")
    e.add_argument("--target", help="external target from benchmarks/external_targets.json")
    e.add_argument("--out", help="write the regression report JSON here")
    e.set_defaults(func=cmd_eval)
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        console.print(f"autopwnai {__version__}")
        return
    if getattr(args, "func", None):
        raise SystemExit(args.func(args))
    # no subcommand → the app (needs a real terminal)
    if sys.stdin.isatty() and sys.stdout.isatty():
        raise SystemExit(cmd_app(args))
    parser.print_help()


if __name__ == "__main__":
    main()
