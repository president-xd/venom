"""
VENOM multi-agent fleet.

A main orchestrator (DeepSeek) coordinates specialist subagents, each backed by
the model best suited to its job and all served through a single NVIDIA NIM key:

    Orchestrator / Reporter   deepseek-ai/deepseek-v4-pro   (base model)
    Research                  z-ai/glm-5.1
    Hypothesis                moonshotai/kimi-k2.6
    CodeGen / Summarizer      qwen/qwen3.5-397b-a17b

Models are selected via .env (VENOM_MODEL_<ROLE>) with the defaults above.
"""

from .roles import AgentRole, AgentSpec, DEFAULT_AGENTS, resolve_models
from .base import Agent
from .orchestrator import Orchestrator, build_orchestrator

__all__ = [
    "AgentRole",
    "AgentSpec",
    "DEFAULT_AGENTS",
    "resolve_models",
    "Agent",
    "Orchestrator",
    "build_orchestrator",
]
