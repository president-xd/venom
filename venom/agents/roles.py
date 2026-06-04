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
        either a full NIM id or a catalog alias (e.g. 'kimi-k2.6')."""
        return resolve_nvidia_model(os.getenv(self.env_var, self.default_model))


# Base model for the fleet is DeepSeek (orchestrator + reporter). Subagents use
# the model best matched to their task. All run through NVIDIA NIM.
DEFAULT_AGENTS: dict[AgentRole, AgentSpec] = {
    AgentRole.ORCHESTRATOR: AgentSpec(
        role=AgentRole.ORCHESTRATOR,
        default_model="deepseek-ai/deepseek-v4-pro",
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
        default_model="z-ai/glm-5.1",
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
        default_model="moonshotai/kimi-k2.6",
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
        # Llama-4 Maverick returns clean fenced/JSON output fast on NVIDIA NIM and is
        # the verified-working codegen path. (deepseek-v4-pro is listed on NIM but
        # hangs — 200s+ ReadTimeout even on a 1-token prompt — verified 2026-06-04.)
        default_model="meta/llama-4-maverick-17b-128e-instruct",
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
        default_model="qwen/qwen3.5-397b-a17b",
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
        default_model="deepseek-ai/deepseek-v4-pro",
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
