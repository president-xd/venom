"""
VENOM command-line interface.

  venom scope    --scope FILE                 Validate & summarize an engagement scope
  venom ingest   --in DIR/FILE...             Ingest artifacts, print endpoint registry
  venom providers                             Test configured LLM providers
  venom agents   [--ping]                     Show the multi-agent model fleet
  venom burp     [--status]                   Burp MCP status / setup instructions
  venom run      --scope FILE --in ... [opts] Full engagement (dry-run by default)
  venom web      [--host --port --open]        Web console (UI over the real engine)

Safety: `run` is DRY-RUN by default (no requests are sent). Pass --live to send
real requests — only allowed within the authorized scope, and the scope guard
still blocks anything out of scope.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .config import SETTINGS, configure_logging
from .core.scope import Scope, ScopeError


def _cmd_scope(args) -> int:
    try:
        scope = Scope.from_file(args.scope)
        scope.validate_window()
    except ScopeError as e:
        print(f"[scope] INVALID: {e}", file=sys.stderr)
        return 2
    print(scope.summary())
    print("\n[scope] OK — engagement is authorized and within its time window.")
    return 0


def _cmd_ingest(args) -> int:
    from .ingest import ingest

    res = ingest(args.inputs)
    print(f"Ingested {len(res.registry)} endpoints from {len(args.inputs)} input(s):\n")
    for note in res.notes:
        print(f"  - {note}")
    if res.secrets:
        print(f"\n  ! possible secrets (redacted): {res.secrets}")
    print("\nTop endpoints by risk:")
    for ep in res.registry.by_risk()[:25]:
        flags = ",".join(ep.business_rule_tags) or "-"
        print(f"  [{ep.risk_tier.value:8}] {ep.key:45} {flags}")
    return 0


def _cmd_providers(args) -> int:
    from .llm import LLMRouter
    from .llm.providers import test_all_providers

    async def go():
        print("Testing configured LLM providers...\n")
        await test_all_providers(LLMRouter.from_env())

    asyncio.run(go())
    return 0


def _cmd_agents(args) -> int:
    from .agents.roles import DEFAULT_AGENTS
    from .llm import LLMRouter, Provider

    router = LLMRouter.from_env()
    nim = router.providers.get(Provider.NVIDIA_NIM)
    nim_ok = bool(nim and nim.enabled)
    print(f"VENOM multi-agent fleet  (NVIDIA NIM: {'configured' if nim_ok else 'NOT configured -> offline'})\n")
    print(f"  {'ROLE':<14}{'MODEL':<34}PROVIDER")
    print(f"  {'-'*14}{'-'*34}{'-'*10}")
    for role, spec in DEFAULT_AGENTS.items():
        print(f"  {role.value:<14}{spec.model():<34}{spec.provider.value}")
    print("\n  Override any model in .env via VENOM_MODEL_<ROLE> (see .env.template).")

    if args.ping:
        if not nim_ok:
            print("\n  --ping skipped: set NVIDIA_API_KEY to test models.")
            return 0
        import asyncio
        from .llm import TaskType

        async def ping():
            seen = {}
            print("\n  Pinging each unique model (1 token)...")
            for role, spec in DEFAULT_AGENTS.items():
                model = spec.model()
                if model in seen:
                    continue
                try:
                    res = await router.complete(
                        TaskType.TEST_SUMMARIZATION,
                        [{"role": "user", "content": "Reply with: OK"}],
                        override_provider=Provider.NVIDIA_NIM, model=model, max_tokens=8,
                    )
                    seen[model] = f"OK ({res['model']})"
                except Exception as e:  # noqa: BLE001
                    seen[model] = f"FAILED — {e}"
                print(f"    {model:<34}{seen[model]}")

        asyncio.run(ping())
    return 0


def _cmd_burp(args) -> int:
    print(f"Burp MCP (keyless, local)  url={SETTINGS.burp_mcp_url}  "
          f"enabled={SETTINGS.burp_mcp_enabled}\n")
    if args.status:
        import asyncio
        from .integrations import burp_status

        info = asyncio.run(burp_status(SETTINGS.burp_mcp_url))
        if info.get("ok"):
            print(f"  CONNECTED — {info['tool_count']} tool(s): {', '.join(info['tools'])}")
        else:
            print(f"  NOT CONNECTED — {info.get('reason')}")
        return 0

    print("Setup (no API key needed):")
    print("  1) pwsh scripts/setup_burp.ps1     # or: scripts/setup_burp.sh")
    print("  2) pwsh scripts/run_burp_mcp.ps1   # launches Burp with the MCP extension")
    print("  3) set BURP_MCP_ENABLED=true in .env")
    print("  4) venom burp --status            # verify the local SSE endpoint")
    print("\n  MCP client SDK: pip install \"venom-agent[burp]\"")
    return 0


def _cmd_run(args) -> int:
    from .engagement import run_engagement

    out_dir = args.out or (SETTINGS.reports_dir() / "latest")
    domain_docs = ""
    if args.docs:
        domain_docs = "\n\n".join(Path(d).read_text(encoding="utf-8", errors="ignore")
                                  for d in args.docs if Path(d).exists())

    async def go():
        return await run_engagement(
            scope_path=args.scope,
            artifact_paths=args.inputs,
            out_dir=out_dir,
            dry_run=not args.live,
            use_llm=not args.no_llm,
            domain_docs=domain_docs,
            discover=args.crawl,
            crawl_seeds=args.seed or None,
            think=args.think,
            objective_text=args.objective or "",
        )

    try:
        result = asyncio.run(go())
    except ScopeError as e:
        print(f"[run] BLOCKED: {e}", file=sys.stderr)
        return 2

    confirmed = sum(1 for c in result.cases if c.verdict.value == "CONFIRMED_EXPLOIT")
    mode = "LIVE" if args.live else "DRY-RUN"
    print(f"\n[{mode}] {len(result.cases)} test cases, {confirmed} confirmed.")
    print(f"Report: {result.artifacts['report']}")
    print(f"Findings JSON: {result.artifacts['findings']}")
    if not args.live:
        print("\nNote: dry-run sends no requests. Re-run with --live (inside the "
              "authorized window) to execute against the target.")
    return 0


def build_hunt_scope(args) -> dict:
    """Synthesize an authorized engagement scope dict from `hunt` CLI args.
    Pure (no I/O) so it can be unit-tested."""
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    bases = [args.url.rstrip("/")]
    if args.email_client:
        host = args.email_client.split("//")[-1].split("/")[0]
        if host and host not in args.url:
            bases.append("https://" + host)
    scope = {
        "engagement_id": "HUNT-" + now.strftime("%Y%m%d-%H%M%S"),
        "target_name": args.url,
        "authorized_base_urls": bases,
        "discovery": {"enabled": True, "seeds": ["/"], "max_pages": args.max_pages, "forced_browse": True},
        "rate_limit_per_second": args.rate,
        "allow_destructive": args.allow_destructive or bool(args.delete_user),
        "authorization_date": now.isoformat(),
        "expiry_date": (now + timedelta(days=1)).isoformat(),
        "authorized_by": "venom hunt (operator-supplied target)",
    }
    if args.login:
        u, _, p = args.login.partition(":")
        scope["identities"] = [{"name": u, "role": "user", "auth": {
            "type": "form_login", "login_url": args.login_url, "method": "POST",
            "username_field": "username", "password_field": "password",
            "username": u, "password": p, "csrf_field": "csrf"}}]
    if args.email_client:
        scope["email_client_url"] = args.email_client
    if args.delete_user:
        scope["objective_delete_user"] = args.delete_user
    if args.objective:
        scope["objective"] = {"description": args.objective}
    return scope


def _cmd_hunt(args) -> int:
    """Point-and-hunt: synthesize an authorized scope from a URL and run the
    autonomous agent loop (crawl + reason + exploit) against it."""
    import json
    import tempfile

    scope = build_hunt_scope(args)
    tf = Path(tempfile.gettempdir()) / f"{scope['engagement_id']}.json"
    tf.write_text(json.dumps(scope, indent=2), encoding="utf-8")
    print(f"[hunt] target {args.url} — scope {tf}")

    # Delegate to the engagement runner in autonomous live mode.
    args.scope = str(tf)
    args.inputs, args.seed, args.docs = [], [], []
    args.crawl = args.live = args.think = True
    args.no_llm = False
    if not args.objective:
        args.objective = ("Discover and exploit a business-logic flaw to reach the win condition "
                          "(e.g. admin access / unintended purchase); verify success from the response.")
    return _cmd_run(args)


def _cmd_oneshot(args) -> int:
    """LLM-frugal hunt: deterministic crawl -> ONE concise synthesis call ->
    self-verified exploit script (hard-capped LLM calls). Survives free tiers."""
    import asyncio
    from pathlib import Path as _P
    from .core.scope import Scope
    from .core.registry import EndpointRegistry
    from .ingest.crawler import crawl
    from .engine.auth import AuthManager
    from .llm import LLMRouter
    from .agents import build_orchestrator, AgentRole
    from .cognition import oneshot_hunt, make_oneshot_synthesizer, Objective

    scope = Scope.from_dict(build_hunt_scope(args))
    scope.validate_window()
    router = LLMRouter.from_env(air_gap=scope.air_gap_mode, mode=scope.llm_mode)
    if not router.any_enabled():
        print("[oneshot] no LLM provider enabled — set a key in .env"); return 2

    async def go():
        registry = EndpointRegistry()
        auth = None
        if scope.identities:
            try:
                auth = await AuthManager(scope, dry_run=False).ensure(scope.identities[0]["name"])
            except Exception as exc:  # noqa: BLE001
                print(f"[oneshot] login failed ({exc}) — crawling unauthenticated")
        await crawl(scope, registry, seeds=["/"], auth_state=auth,
                    max_pages=args.max_pages, forced_browse=True)
        orch = build_orchestrator(router)
        synth = make_oneshot_synthesizer(orch.agent(AgentRole.CODEGEN))
        obj = Objective.from_scope(scope, fallback=args.objective or
                                   "find and exploit a business-logic flaw to reach the win condition")
        return await oneshot_hunt(scope, registry, synth, objective=obj,
                                  max_llm_calls=args.max_llm_calls)

    findings = asyncio.run(go())
    print(f"\n[oneshot] {len(findings)} confirmed exploit(s)")
    for f in findings:
        print(f"  {f.test_id} {f.verdict.value} — {f.hypothesis[:90]}")
        code = f.evidence.get("exploit_code", "")
        if args.out and code:
            out = _P(args.out); out.mkdir(parents=True, exist_ok=True)
            (out / "exploit.py").write_text(code, encoding="utf-8")
            print(f"  exploit script -> {out / 'exploit.py'}")
        elif code:
            print("  --- exploit.py ---\n" + code)
    return 0


def _cmd_web(args) -> int:
    """Launch the VENOM console — a local web UI over the real engine. Launching
    an engagement from the UI runs in-process against the bundled VulnLab."""
    from .web import serve

    if args.open:
        import threading
        import webbrowser

        url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    serve(host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="venom", description="VENOM business-logic pentest agent")
    p.add_argument("--log-level", default=None, help="DEBUG|INFO|WARNING|ERROR")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scope", help="Validate and summarize an engagement scope")
    s.add_argument("--scope", required=True)
    s.set_defaults(func=_cmd_scope)

    i = sub.add_parser("ingest", help="Ingest artifacts and print the endpoint registry")
    i.add_argument("--in", dest="inputs", nargs="+", required=True)
    i.set_defaults(func=_cmd_ingest)

    pr = sub.add_parser("providers", help="Ping configured LLM providers")
    pr.set_defaults(func=_cmd_providers)

    ag = sub.add_parser("agents", help="Show the multi-agent model fleet")
    ag.add_argument("--ping", action="store_true", help="Test each model via NVIDIA NIM")
    ag.set_defaults(func=_cmd_agents)

    bp = sub.add_parser("burp", help="Burp MCP status / setup instructions")
    bp.add_argument("--status", action="store_true", help="Probe the local Burp MCP endpoint")
    bp.set_defaults(func=_cmd_burp)

    r = sub.add_parser("run", help="Run a full engagement (dry-run by default)")
    r.add_argument("--scope", required=True)
    r.add_argument("--in", dest="inputs", nargs="*", default=[],
                   help="Artifacts (OpenAPI/GraphQL/HAR/Burp/JS). Optional if --crawl is used.")
    r.add_argument("--crawl", action="store_true",
                   help="Live web-app discovery: crawl the target (needs --live)")
    r.add_argument("--seed", nargs="*", default=[], help="Crawl seed paths (default /)")
    r.add_argument("--out", default=None, help="Output directory for the report")
    r.add_argument("--docs", nargs="*", default=[], help="Domain doc files for rule inference")
    r.add_argument("--live", action="store_true", help="Send real requests (default: dry-run)")
    r.add_argument("--no-llm", action="store_true", help="Force offline (playbooks only)")
    r.add_argument("--think", action="store_true",
                   help="Run the autonomous agent loop (tools+memory; needs --live + an LLM)")
    r.add_argument("--objective", default="", help="Agent goal, e.g. \"buy the jacket\"")
    r.set_defaults(func=_cmd_run)

    h = sub.add_parser("hunt", help="Point-and-hunt: autonomous agent against a target URL")
    h.add_argument("url", help="Target base URL (you must be authorized to test it)")
    h.add_argument("--login", default="", help="Credentials user:pass for form login")
    h.add_argument("--login-url", default="/login", help="Login form path (default /login)")
    h.add_argument("--email-client", default="", help="Inbox URL for email-verification flows")
    h.add_argument("--delete-user", default="", help="Destructive objective: delete this user")
    h.add_argument("--objective", default="", help="Free-text goal for the agent")
    h.add_argument("--allow-destructive", action="store_true", help="Permit state-changing exploits")
    h.add_argument("--max-pages", type=int, default=40, help="Crawl page budget (default 40)")
    h.add_argument("--rate", type=float, default=10.0, help="Max requests/sec (default 10)")
    h.add_argument("--out", default=None, help="Output directory for the report")
    h.set_defaults(func=_cmd_hunt)

    o = sub.add_parser("oneshot", help="LLM-frugal hunt: recon -> 1 synthesis call -> exploit script")
    o.add_argument("url", help="Target base URL (you must be authorized to test it)")
    o.add_argument("--login", default="", help="Credentials user:pass for form login")
    o.add_argument("--login-url", default="/login", help="Login form path (default /login)")
    o.add_argument("--email-client", default="", help="Inbox URL for email-verification flows")
    o.add_argument("--delete-user", default="", help="Destructive objective: delete this user")
    o.add_argument("--objective", default="", help="Free-text goal for the synthesis")
    o.add_argument("--allow-destructive", action="store_true", help="Permit state-changing exploits")
    o.add_argument("--max-pages", type=int, default=40, help="Crawl page budget (default 40)")
    o.add_argument("--rate", type=float, default=10.0, help="Max requests/sec (default 10)")
    o.add_argument("--max-llm-calls", type=int, default=3, help="Hard cap on synthesis calls (default 3)")
    o.add_argument("--out", default=None, help="Directory to write exploit.py")
    o.set_defaults(func=_cmd_oneshot)

    w = sub.add_parser("web", help="Launch the VENOM web console (UI over the real engine)")
    w.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    w.add_argument("--port", type=int, default=8080, help="Bind port (default 8080)")
    w.add_argument("--open", action="store_true", help="Open the console in a browser")
    w.set_defaults(func=_cmd_web)
    return p


def main(argv: list[str] | None = None) -> int:
    from ._env import load_dotenv
    load_dotenv()   # so provider keys in .env work without manual export
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
