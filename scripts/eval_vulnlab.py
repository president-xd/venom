"""
End-to-end evaluation harness: drive the product's autonomous `oneshot_hunt`
against the local VulnLab with whatever model OLLAMA_MODEL points to, and print an
enterprise-grade scorecard per lab (vuln chosen, calls, solved, evidence, time).

Usage:  python scripts/eval_vulnlab.py [lab ...]   (default: all)
Labs: price idor pin mass
"""
import asyncio
import sys
import time
from venom._env import load_dotenv
load_dotenv()
from venom.core.scope import Scope
from venom.core.registry import EndpointRegistry
from venom.ingest.crawler import crawl
from venom.engine.auth import AuthManager
from venom.llm import LLMRouter
from venom.agents import build_orchestrator, AgentRole
from venom.cognition import oneshot_hunt, make_oneshot_synthesizer, Objective
from vulnlab.labs import LABS as LAB_REGISTRY, LAB_BY_NAME

BASE = "http://localhost:8000"

# Single source of truth: the lab registry in vulnlab/labs.py. Each entry carries
# the operator GOAL (no technique hint) and the oracle config (differential where
# a forbidden action exists, legacy marker for economic flaws).
LABS = {
    lab.name: dict(seeds=lab.seeds, objective=lab.objective, win_action=lab.win_action,
                   win_url=lab.win_url, success_text=lab.success_text,
                   difficulty=lab.difficulty, vuln_id=lab.vuln_id)
    for lab in LAB_REGISTRY
}


def scope():
    return Scope.from_dict({
        "engagement_id": "EVAL", "target_name": "VulnLab", "authorized_base_urls": [BASE],
        "allow_destructive": True, "rate_limit_per_second": 200,
        "identities": [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "method": "POST",
            "username_field": "username", "password_field": "password",
            "username": "wiener", "password": "peter", "csrf_field": "csrf"}}],
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z"})


async def run_lab(name, cfg):
    # Honest measurement: reset the server so a persistent process cannot report a
    # stale 'solved' banner from a previous lab/run as a (fake) win.
    import httpx
    try:
        httpx.post(f"{BASE}/__reset", timeout=10)
    except Exception:  # noqa: BLE001 - reset is best-effort
        pass
    sc = scope()
    reg = EndpointRegistry()
    auth = await AuthManager(sc, dry_run=False).ensure("wiener")
    await crawl(sc, reg, seeds=cfg["seeds"], auth_state=auth, max_pages=25, forced_browse=False)
    r = LLMRouter.from_env()
    synth = make_oneshot_synthesizer(build_orchestrator(r).agent(AgentRole.CODEGEN))
    obj = Objective(description=cfg["objective"], win_action=cfg["win_action"],
                    win_url=cfg["win_url"], success_text=cfg["success_text"],
                    win_signals=("is-solved",))
    # Tier-aware budget: harder, multi-step labs deserve more directed retries.
    # (Each failed attempt now feeds back the REAL observed responses, so extra
    # calls are productive rather than blind re-rolls.)
    budget = {"easy": 3, "medium": 5, "hard": 6}.get(cfg["difficulty"], 3)
    t0 = time.monotonic()
    findings = await oneshot_hunt(sc, reg, synth, objective=obj, max_llm_calls=budget)
    dt = time.monotonic() - t0
    f = findings[0] if findings else None
    print(f"\n##### [{cfg['difficulty']}] {name}: {'SOLVED' if f else 'NOT solved'}  ({dt:.0f}s)"
          f"  (expected vuln: {cfg['vuln_id']})")
    if f:
        print("  vuln_class:", f.vulnerability_class.value)
        print("  notes:", [n for n in f.notes if not n.startswith('code:')])
        print("  requests:", len(f.evidence.get("requests", [])))
        print("  differential:", f.evidence.get("differential"))
    return name, bool(f), dt, cfg["difficulty"]


async def main():
    labs = [a for a in sys.argv[1:] if a in LABS] or list(LABS)
    results = []
    for name in labs:
        try:
            results.append(await run_lab(name, LABS[name]))
        except Exception as exc:  # noqa: BLE001
            print(f"##### {name}: ERROR {exc}")
            results.append((name, False, 0, LABS[name]["difficulty"]))
    print("\n================ SCORECARD ================")
    order = {"easy": 0, "medium": 1, "hard": 2}
    for name, ok, dt, diff in sorted(results, key=lambda r: (order.get(r[3], 9), r[0])):
        print(f"  [{diff:6}] {name:10} {'PASS' if ok else 'fail'}  {dt:.0f}s")
    solved = sum(1 for _, ok, _, _ in results if ok)
    print(f"  ---------------------------------------")
    print(f"  TOTAL: {solved}/{len(results)} solved")

asyncio.run(main())
