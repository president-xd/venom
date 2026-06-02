"""
Adversarial hypothesis generation. For high-risk endpoints, ask the LLM to
propose attack chains the deterministic playbooks might miss, using the five
adversarial lenses from the CIPHER prompt (precondition bypass, sequence
violation, concurrency, actor confusion, state rollback).

Returns extra TestCase objects (origin="llm"). Safe no-op when no LLM exists.
"""

from __future__ import annotations

import logging
from itertools import count

from ..core.graph import BusinessModelGraph
from ..core.registry import EndpointRegistry
from ..llm import LLMRouter, TaskType, complete_json
from ..prompts import agent_system_prompt
from ..testing.schema import Severity, TestCase, TestStep, VulnClass

logger = logging.getLogger("venom.inference")
_counter = count(1)

_SYSTEM = (
    "You are CIPHER's hypothesis engine. Do NOT ask what the rules are. Given a "
    "state machine and endpoints, enumerate sequences of API calls that grant a "
    "financial or privilege benefit the actor is not entitled to. Apply five "
    "lenses to each financial/state endpoint: (1) precondition bypass, (2) sequence "
    "violation, (3) concurrency, (4) actor confusion / cross-tenant, (5) state "
    "rollback. Each hypothesis must be concrete and testable."
)

_VCLASS = {v.value: v for v in VulnClass}
_SEV = {s.value: s for s in Severity}

_SCHEMA_HINT = (
    '{"hypotheses":[{"vulnerability_class":"STATE_BYPASS","hypothesis":"...",'
    '"risk_rating":"HIGH","business_impact":"...","affected_endpoint":"POST /x",'
    '"steps":[{"step":1,"description":"...","method":"POST","path":"/x",'
    '"body":{},"success_condition":"status in (200,201)"}]}]}'
)


def _to_testcase(h: dict) -> TestCase | None:
    try:
        steps = [
            TestStep(
                step=s.get("step", i + 1),
                description=s.get("description", ""),
                method=s.get("method", "POST"),
                path=s.get("path", "/"),
                body=s.get("body"),
                success_condition=s.get("success_condition"),
                concurrency=int(s.get("concurrency", 1)),
            )
            for i, s in enumerate(h.get("steps", []))
        ]
        return TestCase(
            test_id=f"TC-LLM-{next(_counter):03d}",
            vulnerability_class=_VCLASS.get(h.get("vulnerability_class", ""), VulnClass.STATE_BYPASS),
            hypothesis=h.get("hypothesis", ""),
            risk_rating=_SEV.get(h.get("risk_rating", "MEDIUM"), Severity.MEDIUM),
            business_impact=h.get("business_impact", ""),
            affected_endpoint=h.get("affected_endpoint", ""),
            steps=steps,
            rag_source=h.get("rag_source", ""),
            origin="llm",
        )
    except Exception:  # noqa: BLE001
        return None


async def generate_hypotheses(
    registry: EndpointRegistry,
    graph: BusinessModelGraph,
    router: LLMRouter | None = None,
    max_endpoints: int = 15,
    agent=None,  # venom.agents.base.Agent — hypothesis subagent when provided
) -> list[TestCase]:
    if agent is None and (router is None or not router.any_enabled()):
        logger.info("No LLM available — skipping LLM hypothesis generation.")
        return []

    targets = [e for e in registry.by_risk()
               if e.risk_tier.value in {"CRITICAL", "HIGH"}][:max_endpoints]
    if not targets:
        return []

    user = (
        "BUSINESS MODEL GRAPH:\n"
        f"{graph.to_dict()}\n\n"
        "HIGH-RISK ENDPOINTS:\n"
        f"{[e.to_dict() for e in targets]}\n\n"
        "Generate attack-chain hypotheses."
    )
    try:
        if agent is not None:
            parsed = await agent.complete_json(user, schema_hint=_SCHEMA_HINT, extra_system=_SYSTEM)
        else:
            result = await complete_json(
                router, TaskType.HYPOTHESIS_GEN,
                [{"role": "user", "content": user}],
                system=agent_system_prompt() + "\n\n---\n\n" + _SYSTEM,
                schema_hint=_SCHEMA_HINT,
            )
            parsed = result["parsed"]
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM hypothesis generation failed: %s", exc)
        return []

    cases = [tc for h in parsed.get("hypotheses", []) if (tc := _to_testcase(h))]
    logger.info("Hypothesis subagent produced %d additional hypotheses", len(cases))
    return cases
