"""
Per-lab coverage hunt for the bundled VulnLab demo.

The web console targets the bundled VulnLab, which serves ALL labs on one surface
with SHARED state. A single engagement against that combined surface can only
confirm the most generic flaw (e.g. forced-browse) because each lab's win-oracle
expects that lab in isolation. This module hunts each lab as a DISCRETE, ISOLATED
target — fresh state, the lab's own objective + win-oracle — using the SAME agent
one-shot synthesizer the real engine uses. That is how the demo surfaces the MANY
vulnerabilities the engine is capable of, each proven by the differential oracle
(forbidden at baseline → succeeds after the exploit) or the lab's success marker.

This is the VulnLab DEMO path (it legitimately uses the bundled labs' ground
truth, exactly like venom/flows and the eval). The general engine in
venom/engagement.py stays app-agnostic and never imports this.
"""

from __future__ import annotations

import asyncio
import logging

from ..core.registry import EndpointRegistry
from ..core.scope import Scope
from ..testing.schema import Severity, TestCase, TestStep, Verdict, VulnClass

logger = logging.getLogger("venom.web.coverage")

_VC = {v.value: v for v in VulnClass}


def _vuln_class(vuln_id: str) -> VulnClass:
    """Map a lab's vuln id (e.g. 'broken-object-level-auth') to a VulnClass."""
    vid = (vuln_id or "").lower()
    table = {
        "broken-object-level": VulnClass.BOLA_IDOR, "idor": VulnClass.BOLA_IDOR,
        "mass-assignment": VulnClass.MASS_ASSIGNMENT, "client-side": VulnClass.PARAM_POLLUTION,
        "trusted-identity": VulnClass.PRIV_ESCALATION, "privilege": VulnClass.PRIV_ESCALATION,
        "sequence": VulnClass.SEQUENCE_VIOLATION, "workflow": VulnClass.SEQUENCE_VIOLATION,
        "overflow": VulnClass.PARAM_POLLUTION, "race": VulnClass.RACE_CONDITION,
    }
    for k, v in table.items():
        if k in vid:
            return v
    return VulnClass.FAITH_BASED_RULE


async def _hunt_lab(lab, scope_dict: dict, per_lab_calls: int, sem: asyncio.Semaphore):
    """Hunt ONE lab in complete isolation; return (lab, list[TestCase])."""
    # Imports are local so the general engine never depends on the demo target.
    from vulnlab.app import make_transport
    from ..ingest.crawler import crawl
    from ..engine.auth import AuthManager
    from ..llm import LLMRouter
    from ..agents import build_orchestrator, AgentRole
    from ..cognition import oneshot_hunt, make_oneshot_synthesizer, Objective

    async with sem:
        transport, _ = make_transport()                 # FRESH, isolated lab state
        scope = Scope.from_dict(scope_dict)
        reg = EndpointRegistry()
        auth = None
        if scope.identities:
            try:
                auth = await AuthManager(scope, transport=transport).ensure(scope.identities[0]["name"])
            except Exception as exc:  # noqa: BLE001
                logger.debug("coverage auth failed for %s: %s", lab.name, exc)
        try:
            await crawl(scope, reg, seeds=lab.seeds, auth_state=auth, transport=transport,
                        max_pages=25, forced_browse=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug("coverage crawl failed for %s: %s", lab.name, exc)
            return lab, []

        router = LLMRouter.from_env()
        synth = make_oneshot_synthesizer(build_orchestrator(router).agent(AgentRole.CODEGEN))
        obj = Objective(description=lab.objective, win_action=lab.win_action,
                        win_url=lab.win_url, success_text=lab.success_text or "",
                        win_signals=("is-solved",))
        try:
            found = await oneshot_hunt(scope, reg, synth, objective=obj,
                                       transport=transport, max_llm_calls=per_lab_calls)
        except Exception as exc:  # noqa: BLE001 — one lab must never abort coverage
            logger.warning("coverage lab %s errored: %s", lab.name, exc)
            found = []
        # Re-label the generic ONE-001 case with this lab's identity for the report.
        for c in found:
            c.test_id = f"COV-{lab.name}"
            c.vulnerability_class = _vuln_class(getattr(lab, "vuln_id", ""))
            c.affected_endpoint = (lab.win_action or {}).get("path") or lab.win_url
            c.hypothesis = f"{lab.title or lab.name}: {lab.objective}"
        return lab, found


async def vulnlab_coverage(scope_dict: dict, *, labs=None, concurrency: int = 4,
                           per_lab_calls: int = 3, on_lab=None) -> list[TestCase]:
    """Hunt EVERY lab in isolation, concurrently (bounded). Returns the confirmed
    TestCases (one per solved lab). `on_lab(name, solved)` is called as each finishes
    so the live trace can report progress in real time."""
    from vulnlab.labs import LABS
    lab_list = labs if labs is not None else list(LABS)
    sem = asyncio.Semaphore(max(1, concurrency))
    tasks = [asyncio.create_task(_hunt_lab(lab, scope_dict, per_lab_calls, sem)) for lab in lab_list]
    cases: list[TestCase] = []
    done = solved = 0
    for coro in asyncio.as_completed(tasks):
        lab, found = await coro
        done += 1
        if found:
            solved += 1
            cases.extend(found)
        if on_lab:
            try:
                on_lab(getattr(lab, "name", "?"), bool(found), done, len(lab_list), solved)
            except Exception:  # noqa: BLE001
                pass
    logger.info("vulnlab coverage: %d/%d labs solved", solved, len(lab_list))
    return cases
