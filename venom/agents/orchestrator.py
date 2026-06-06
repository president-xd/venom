"""
Orchestrator - the main agent (DeepSeek). It owns the subagent fleet and drives
the reasoning stages of an engagement, delegating each stage to the agent whose
model is best suited to it.

When NVIDIA NIM is not configured, `enabled` is False and the engagement falls
back to the deterministic offline pipeline.
"""

from __future__ import annotations

import logging

from ..core.graph import BusinessModelGraph
from ..core.registry import EndpointRegistry
from ..llm import LLMRouter, Provider
from .base import Agent
from .roles import DEFAULT_AGENTS, AgentRole

logger = logging.getLogger("venom.agents.orchestrator")


class Orchestrator:
    def __init__(self, router: LLMRouter, agents: dict[AgentRole, Agent], enabled: bool):
        self.router = router
        self.agents = agents
        self.enabled = enabled

    def agent(self, role: AgentRole) -> Agent:
        return self.agents[role]

    # ------------------------------------------------------------- stages
    async def research(self, registry: EndpointRegistry, domain_docs: str = "") -> str:
        """Research agent surfaces implicit rules / analogous vuln classes."""
        if not self.enabled:
            return ""
        agent = self.agents[AgentRole.RESEARCH]
        user = (
            "ENDPOINT REGISTRY (risk-ranked):\n"
            f"{[e.to_dict() for e in registry.by_risk()[:40]]}\n\n"
            + (f"DOMAIN DOCS:\n{domain_docs}\n\n" if domain_docs else "")
            + "Produce concise research notes: implicit business rules, tier/role "
            "policies, economic flows, and analogous vulnerability classes worth probing."
        )
        try:
            notes = await agent.complete_text(user)
            logger.info("[research:%s] produced %d chars of notes", agent.model, len(notes))
            return notes
        except Exception as exc:  # noqa: BLE001
            logger.warning("[research] failed: %s", exc)
            return ""

    async def reconstruct_model(self, registry: EndpointRegistry,
                                domain_docs: str = "") -> BusinessModelGraph:
        """Research notes + orchestrator synthesis -> business model graph."""
        from ..inference.rules import infer_business_model  # avoid import cycle

        if not self.enabled:
            return await infer_business_model(registry, router=None)
        notes = await self.research(registry, domain_docs)
        augmented = "\n\n".join(p for p in (domain_docs, notes) if p)
        return await infer_business_model(
            registry, agent=self.agents[AgentRole.ORCHESTRATOR], domain_docs=augmented
        )

    async def hypothesize(self, registry: EndpointRegistry, graph: BusinessModelGraph):
        from ..inference.hypotheses import generate_hypotheses  # avoid import cycle

        if not self.enabled:
            return []
        return await generate_hypotheses(
            registry, graph, agent=self.agents[AgentRole.HYPOTHESIS]
        )

    async def concretize(self, cases):
        """CODEGEN subagent fills runnable success_conditions for any LLM-proposed
        case that came back without one (deterministic playbook cases already have
        them). Returns the cases, mutated in place."""
        if not self.enabled:
            return cases
        pending = [c for c in cases if c.origin == "llm"
                   and any(s.success_condition in (None, "") for s in c.steps)]
        if not pending:
            return cases
        agent = self.agents[AgentRole.CODEGEN]
        brief = [{"test_id": c.test_id, "endpoint": c.affected_endpoint,
                  "hypothesis": c.hypothesis,
                  "steps": [{"step": s.step, "method": s.method, "path": s.path} for s in c.steps]}
                 for c in pending]
        try:
            out = await agent.complete_json(
                "For each test, return a machine-checkable success_condition (a Python "
                "boolean expression over: status, body, text, results_2xx, net_balance_delta) "
                f"that proves the exploit. Tests:\n{brief}",
                schema_hint='{"conditions":[{"test_id":"...","step":1,"success_condition":"..."}]}')
            by_id = {(c["test_id"], c.get("step", 1)): c["success_condition"]
                     for c in out.get("conditions", [])}
            for c in pending:
                for s in c.steps:
                    if not s.success_condition:
                        s.success_condition = by_id.get((c.test_id, s.step)) or "status in (200, 201)"
                c.origin = "codegen"
            logger.info("[codegen:%s] concretized %d case(s)", agent.model, len(pending))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[codegen] failed: %s", exc)
        return cases

    async def summarize_results(self, findings_brief: list[dict]) -> str:
        """SUMMARIZER subagent writes a terse coverage/results summary for the report."""
        if not self.enabled:
            return ""
        try:
            return await self.agents[AgentRole.SUMMARIZER].complete_text(
                f"Summarize this VENOM run in 3-4 sentences (coverage + confirmed risk, "
                f"no hype):\n{findings_brief}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("[summarizer] failed: %s", exc)
            return ""


def build_orchestrator(router: LLMRouter | None) -> Orchestrator | None:
    """Construct the fleet. Returns None if there is no router at all."""
    if router is None:
        return None
    # The fleet is live if ANY keyed cloud provider is configured (DeepSeek is the
    # paid primary; NVIDIA NIM / OpenRouter are fallbacks). Air-gap relies on Ollama.
    nim = router.providers.get(Provider.NVIDIA_NIM)
    ds = router.providers.get(Provider.DEEPSEEK)
    orr = router.providers.get(Provider.OPENROUTER)
    enabled = bool((ds and ds.enabled) or (nim and nim.enabled)
                   or (orr and orr.enabled) or getattr(router, "air_gap", False))
    agents = {role: Agent(spec, router) for role, spec in DEFAULT_AGENTS.items()}
    if not enabled:
        logger.warning("No LLM provider configured - multi-agent fleet disabled (offline mode).")
    return Orchestrator(router, agents, enabled)
