"""
Agent role definitions and the default model fleet.

Each role maps to a model (overridable via an environment variable) and a
role-specific system addendum that is appended to the VENOM master prompt.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from ..llm.providers import Provider, TaskType, resolve_nvidia_model


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"  # main coordinator (base model)
    RESEARCH = "research"          # context gathering, RAG, similar-vuln retrieval
    HYPOTHESIS = "hypothesis"      # adversarial attack-chain generation
    CODEGEN = "codegen"            # concrete test steps / payloads
    SUMMARIZER = "summarizer"      # cheap, high-volume result summaries
    REPORTER = "reporter"          # final report prose (quality matters)


@dataclass(frozen=True)
class AgentSpec:
    role: AgentRole
    default_model: str
    env_var: str
    description: str
    system_addendum: str
    provider: Provider = Provider.NVIDIA_NIM
    primary_task: TaskType = TaskType.RULE_INFERENCE
    temperature: float = 0.2

    def model(self) -> str:
        """Resolve the model, honoring the per-role env override and accepting
        either a full NIM id or a catalog alias (e.g. 'kimi-k2.6'). For non-NVIDIA
        providers (e.g. DeepSeek) the alias map is a harmless pass-through."""
        return resolve_nvidia_model(os.getenv(self.env_var, self.default_model))


# The fleet runs on DeepSeek's paid, OpenAI-compatible API (the operator's
# purchased key). `deepseek-chat` (V3) is fast and strong at codegen/reasoning;
# upgrade any role to `deepseek-reasoner` (R1) via its env var for harder reasoning.
# NVIDIA NIM / OpenRouter remain configured as automatic fallbacks in the router.
_DS_CHAT = "deepseek-chat"

DEFAULT_AGENTS: dict[AgentRole, AgentSpec] = {
    AgentRole.ORCHESTRATOR: AgentSpec(
        role=AgentRole.ORCHESTRATOR,
        default_model=_DS_CHAT,
        provider=Provider.DEEPSEEK,
        env_var="VENOM_MODEL_ORCHESTRATOR",
        description="Main coordinator: planning, business-model synthesis, decisions.",
        system_addendum=(
            "You are the ORCHESTRATOR — the lead application-security engineer. "
            "You synthesize the inputs from your research and hypothesis subagents "
            "into a coherent business model and an attack plan. Be rigorous, "
            "deterministic, and explicit about state and preconditions."
        ),
        primary_task=TaskType.GRAPH_EXTRACTION,
    ),
    AgentRole.RESEARCH: AgentSpec(
        role=AgentRole.RESEARCH,
        default_model=_DS_CHAT,
        provider=Provider.DEEPSEEK,
        env_var="VENOM_MODEL_RESEARCH",
        description="Research: analyze domain docs, recall similar vulnerability patterns.",
        system_addendum=(
            "You are the RESEARCH agent. Given an endpoint registry and any domain "
            "documentation, surface the implicit business rules, tier/role policies, "
            "economic flows, and analogous real-world vulnerability classes worth "
            "probing. Output concise, factual research notes — no speculation framed "
            "as fact."
        ),
        primary_task=TaskType.RULE_INFERENCE,
        temperature=0.3,
    ),
    AgentRole.HYPOTHESIS: AgentSpec(
        role=AgentRole.HYPOTHESIS,
        default_model=_DS_CHAT,
        provider=Provider.DEEPSEEK,
        env_var="VENOM_MODEL_HYPOTHESIS",
        description="Adversarial hypothesis generation via the five attack lenses.",
        system_addendum=(
            "You are the HYPOTHESIS subagent. For each financial/state endpoint, "
            "apply the five lenses (precondition bypass, sequence violation, "
            "concurrency, actor confusion, state rollback) and produce concrete, "
            "testable attack chains that yield an unearned benefit."
        ),
        primary_task=TaskType.HYPOTHESIS_GEN,
        temperature=0.4,
    ),
    AgentRole.CODEGEN: AgentSpec(
        role=AgentRole.CODEGEN,
        # DeepSeek V3 (deepseek-chat) drives `oneshot`: strong, fast code synthesis
        # via the paid OpenAI-compatible API. Returns clean fenced ```python blocks.
        default_model=_DS_CHAT,
        provider=Provider.DEEPSEEK,
        env_var="VENOM_MODEL_CODEGEN",
        description="Generate concrete, executable test steps and payloads.",
        system_addendum=(
            "You are the CODEGEN subagent. Turn attack hypotheses into precise, "
            "executable request sequences: method, path, body, extraction rules, "
            "and machine-checkable success conditions. Prefer exactness over prose."
        ),
        primary_task=TaskType.CODE_GENERATION,
    ),
    AgentRole.SUMMARIZER: AgentSpec(
        role=AgentRole.SUMMARIZER,
        default_model=_DS_CHAT,
        provider=Provider.DEEPSEEK,
        env_var="VENOM_MODEL_SUMMARIZER",
        description="Summarize test results cheaply and consistently.",
        system_addendum=(
            "You are the SUMMARIZER subagent. Condense test results into terse, "
            "accurate findings. Never inflate severity; never invent evidence."
        ),
        primary_task=TaskType.TEST_SUMMARIZATION,
    ),
    AgentRole.REPORTER: AgentSpec(
        role=AgentRole.REPORTER,
        default_model=_DS_CHAT,
        provider=Provider.DEEPSEEK,
        env_var="VENOM_MODEL_REPORTER",
        description="Final report prose — executive summary and remediation framing.",
        system_addendum=(
            "You are the REPORTER. Write clear, business-risk-framed prose for a "
            "mixed audience (executives + engineers). No hype; quantify impact."
        ),
        primary_task=TaskType.REPORT_GENERATION,
    ),
}


def resolve_models() -> dict[AgentRole, str]:
    """Current role -> model mapping (after env overrides). Used by `venom agents`."""
    return {role: spec.model() for role, spec in DEFAULT_AGENTS.items()}
