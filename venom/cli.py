"""
VENOM command-line interface.

  venom scope    --scope FILE                 Validate & summarize an engagement scope
  venom ingest   --in DIR/FILE...             Ingest artifacts, print endpoint registry
  venom providers                             Test configured LLM providers
  venom agents   [--ping]                     Show the multi-agent model fleet
  venom burp     [--status]                   Burp MCP status / setup instructions
  venom run      --scope FILE --in ... [opts] Full engagement (dry-run by default)

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
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
