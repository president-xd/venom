"""
Business-model inference. Given the endpoint registry (and optionally domain
docs), ask the strongest available LLM to reconstruct the intended business
model as a graph: entities, state machines, rules, actors, economic flows.

If no LLM is configured, fall back to a heuristic graph derived from endpoint
naming so the rest of the pipeline still has something to attack.
"""

from __future__ import annotations

import logging

from ..core.graph import BusinessModelGraph, Entity, Transition, Rule, Actor
from ..core.registry import EndpointRegistry
from ..llm import LLMRouter, TaskType, complete_json
from ..prompts import agent_system_prompt

logger = logging.getLogger("venom.inference")

_SYSTEM = (
    "You are VENOM's business-model inference module. Given an API endpoint "
    "registry and optional domain documentation, reconstruct the application's "
    "INTENDED business model. Identify domain entities and their state machines, "
    "the business rules that constrain them (RATE_LIMIT, UNIQUENESS, TEMPORAL, "
    "RELATIONAL, THRESHOLD, SEQUENCE), the actor roles and their privilege "
    "boundaries, and any economic flows (points<->cash, credits<->services). "
    "For each rule, set \"enforced\": false if the registry shows no validation "
    "parameter or documented error for violating it (a 'faith-based' rule)."
)

_SCHEMA_HINT = (
    '{"entities":{"Order":{"name":"Order","states":["paid","shipped","refunded"],'
    '"ownership_model":"customer","access_model":{"customer":["read"]}}},'
    '"transitions":[{"entity":"Order","from_state":"paid","to_state":"shipped",'
    '"trigger":"POST /api/v1/orders/{id}/ship","preconditions":["paid"],'
    '"idempotent":false,"reversible":false}],'
    '"rules":[{"rule_id":"R1","rule_type":"TEMPORAL","description":"Refund within 30 days",'
    '"attached_to":"POST /api/v1/orders/{id}/refund","enforced":false}],'
    '"actors":{"customer":{"role":"customer","can_read":["Order"],"can_impersonate":false}},'
    '"economic_flows":[{"from_asset":"cash","to_asset":"points","rate":"1 USD = 100 pts",'
    '"reverse_flow":"1000 pts = 1 USD","abuse_note":"asymmetric round-trip"}]}'
)


def _heuristic_graph(registry: EndpointRegistry) -> BusinessModelGraph:
    """No-LLM fallback: build a coarse graph from financial/state endpoints."""
    g = BusinessModelGraph()
    # A generic Order entity if order-like endpoints exist.
    order_eps = [e for e in registry if "order" in e.path.lower()]
    if order_eps:
        g.add_entity(Entity(
            name="Order",
            states=["draft", "paid", "shipped", "refunded", "cancelled"],
            ownership_model="customer",
            access_model={"customer": ["read", "write"]},
        ))
        chain = [("draft", "paid"), ("paid", "shipped"), ("shipped", "refunded")]
        for frm, to in chain:
            trig = next((e.key for e in order_eps if to[:4] in e.path.lower()), "")
            g.add_transition(Transition(entity="Order", from_state=frm, to_state=to, trigger=trig))
    # Faith-based rules for any 'financial' endpoint lacking parameters.
    for e in registry.with_tag("financial"):
        if not e.parameters:
            g.add_rule(Rule(
                rule_id=f"FB-{abs(hash(e.key)) % 1000:03d}",
                rule_type="THRESHOLD",
                description=f"Implicit constraint on {e.key} (no visible validation params)",
                attached_to=e.key,
                enforced=False,
            ))
    g.add_actor(Actor(role="attacker", can_read=["Order"], can_impersonate=False))
    return g


async def infer_business_model(
    registry: EndpointRegistry,
    router: LLMRouter | None = None,
    domain_docs: str = "",
    agent=None,  # venom.agents.base.Agent — orchestrator/base model when provided
) -> BusinessModelGraph:
    if agent is None and (router is None or not router.any_enabled()):
        logger.warning("No LLM available — using heuristic business model graph.")
        return _heuristic_graph(registry)

    endpoints_json = registry.to_dict()
    user = (
        "ENDPOINT REGISTRY:\n"
        f"{endpoints_json}\n\n"
        + (f"DOMAIN DOCUMENTATION / RESEARCH NOTES:\n{domain_docs}\n\n" if domain_docs else "")
        + "Reconstruct the intended business model graph."
    )
    try:
        if agent is not None:
            parsed = await agent.complete_json(user, schema_hint=_SCHEMA_HINT, extra_system=_SYSTEM)
        else:
            result = await complete_json(
                router, TaskType.GRAPH_EXTRACTION,
                [{"role": "user", "content": user}],
                system=agent_system_prompt() + "\n\n---\n\n" + _SYSTEM,
                schema_hint=_SCHEMA_HINT,
            )
            parsed = result["parsed"]
        return BusinessModelGraph.from_dict(parsed)
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM graph extraction failed (%s) — falling back to heuristic.", exc)
        return _heuristic_graph(registry)
