"""
Test-case generation orchestrator: deterministic playbooks + optional LLM
hypotheses, de-duplicated and sorted by risk.
"""

from __future__ import annotations

from ..core.graph import BusinessModelGraph
from ..core.registry import EndpointRegistry
from ..llm import LLMRouter
from . import playbooks
from .schema import Severity, TestCase

_SEV_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


async def generate_test_cases(
    registry: EndpointRegistry,
    graph: BusinessModelGraph,
    router: LLMRouter | None = None,
    hypothesis_agent=None,  # venom.agents.base.Agent - uses the Kimi subagent
    identities: list[str] | None = None,
) -> list[TestCase]:
    # Lazy import avoids a circular dependency (inference -> testing -> inference).
    from ..inference.hypotheses import generate_hypotheses

    from . import web_playbooks

    cases = playbooks.run_all(registry, graph, identities=identities)
    cases += web_playbooks.run_all(registry, identities=identities)  # web-app (HTML/form) classes
    cases += await generate_hypotheses(registry, graph, router, agent=hypothesis_agent)

    # RAG: attach prior-art references from the writeup corpus.
    try:
        from ..rag import annotate_cases
        annotate_cases(cases)
    except Exception:  # noqa: BLE001 - RAG is augmentation, never fatal
        pass

    # De-duplicate by (class, endpoint, hypothesis prefix).
    seen: set[tuple] = set()
    unique: list[TestCase] = []
    for c in cases:
        key = (c.vulnerability_class, c.affected_endpoint, c.hypothesis[:60])
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    unique.sort(key=lambda c: _SEV_ORDER.get(c.risk_rating, 9))
    return unique
