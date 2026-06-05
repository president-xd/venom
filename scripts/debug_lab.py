"""
Debug a single VulnLab lab through the real oneshot pipeline, printing EVERYTHING
the model saw and produced: the recon brief (accessible/denied), each synthesized
exploit, the actual server trace per request, and the objective verdict.

Usage:  PYTHONPATH=. python scripts/debug_lab.py <lab> [max_calls]
"""
import asyncio
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
from venom._env import load_dotenv
load_dotenv()
from venom.core.scope import Scope
from venom.core.registry import EndpointRegistry
from venom.ingest.crawler import crawl
from venom.ingest.recon import enrich_recon
from venom.engine.auth import AuthManager
from venom.llm import LLMRouter
from venom.agents import build_orchestrator, AgentRole
from venom.cognition import make_oneshot_synthesizer, Objective
from venom.cognition.oneshot import build_brief
from venom.memory import Notebook
from venom.tools import Toolbox
from vulnlab.labs import LAB_BY_NAME

BASE = "http://localhost:8000"


def scope():
    return Scope.from_dict({
        "engagement_id": "DBG", "target_name": "VulnLab", "authorized_base_urls": [BASE],
        "allow_destructive": True, "rate_limit_per_second": 200,
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "method": "POST",
            "username_field": "username", "password_field": "password",
            "username": "wiener", "password": "peter", "csrf_field": "csrf"}}],
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z"})


async def main():
    name = sys.argv[1]
    max_calls = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    lab = LAB_BY_NAME[name]
    import httpx
    try:
        httpx.post(f"{BASE}/__reset", timeout=10)
    except Exception:
        pass
    sc = scope()
    reg = EndpointRegistry()
    auth = await AuthManager(sc, dry_run=False).ensure("wiener")
    await crawl(sc, reg, seeds=lab.seeds, auth_state=auth, max_pages=25, forced_browse=False)
    obj = Objective(description=lab.objective, win_action=lab.win_action,
                    win_url=lab.win_url, success_text=lab.success_text, win_signals=("is-solved",))
    r = LLMRouter.from_env()
    synth = make_oneshot_synthesizer(build_orchestrator(r).agent(AgentRole.CODEGEN))

    nb = Notebook()
    tb = Toolbox(sc, nb, objective=obj)
    tb.default_identity = "wiener"
    tb.known_paths = {(e.path or "/").rstrip("/") or "/" for e in reg}
    tb.known_paths |= {"/", (obj.win_url or "/").rstrip("/") or "/"}
    if obj.win_action and obj.win_action.get("path"):
        tb.known_paths.add(obj.win_action["path"].rstrip("/") or "/")
    enrichment = await enrich_recon(sc, reg, transport=None)
    brief = build_brief(reg, obj, enrichment=enrichment)

    print("=" * 70)
    print(f"LAB: {name}  ({lab.difficulty})  objective: {lab.objective}")
    print(f"KNOWN PATHS: {sorted(tb.known_paths)}")
    print(f"ACCESSIBLE: {brief.get('accessible_to_you')}")
    print(f"DENIED:     {brief.get('denied_to_you')}")
    print("PAGE SNIPPETS:")
    for p in brief.get("page_snippets", []):
        print(f"   {p.get('method')} {p.get('path')} -> {(p.get('snippet') or '')[:120]}")
    print("LOOT:", brief.get("loot"))
    print("PRIVILEGED READS:")
    for p in brief.get("privileged_reads", []):
        print(f"   {p.get('source')} -> {(p.get('snippet') or '')[:120]}")
    print("=" * 70)

    baseline_ok = await obj.baseline(tb)
    print(f"BASELINE win-action already allowed? {baseline_ok}")
    last = None
    for i in range(1, max_calls + 1):
        plan = await synth(brief, last)
        code = plan.get("exploit_code") or ""
        print(f"\n------ ATTEMPT {i}  (vuln={plan.get('vuln_class')}) ------")
        print(code)
        res = await tb.run_exploit_code(code)
        met = bool((await tb.check_objective()).data.get("met"))
        if not met and obj.win_action and obj.action_succeeded_in_trace((res.data or {}).get("trace")):
            met = True
        print(f"  -> ran ok={res.ok} objective_met={met}")
        trace = (res.data or {}).get("trace") or []
        for t in trace:
            print(f"     {t.get('method')} {t.get('path')} [{t.get('status')}] "
                  f"{(t.get('snippet') or '')[:120]}" + (f"  NOTE={t['note']}" if t.get('note') else ""))
        if (res.data or {}).get("error"):
            print("  ERROR:", (res.data or {}).get("error")[:300])
        if (res.data or {}).get("unknown_endpoints"):
            print("  INVENTED:", (res.data or {}).get("unknown_endpoints"))
        if met:
            print(">>> SOLVED")
            break
        unknown = (res.data or {}).get("unknown_endpoints") or []
        observed = [{"method": t.get("method"), "path": t.get("path"), "status": t.get("status"),
                     "saw": (t.get("snippet") or "")[:160]} for t in trace[-8:]]
        last = {"objective_met": False,
                "exploit_returned": str((res.data or {}).get("return"))[:200],
                "run_error": ((res.data or {}).get("error") or "")[:300],
                "observed_responses": observed, "invented_endpoints": unknown,
                "hint": "retry"}
    await tb.aclose()

asyncio.run(main())
