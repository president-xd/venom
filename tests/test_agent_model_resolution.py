"""
Regression: agent model resolution must be provider-aware.

The NVIDIA alias catalog (providers.py::_DEFAULT_NVIDIA_MODELS) contains the key
'deepseek-v4-pro'. Applying that catalog to a DeepSeek-provider role rewrote the
model to the NVIDIA id 'deepseek-ai/deepseek-v4-pro', which DeepSeek's
OpenAI-compatible API rejects with HTTP 400 - silently failing the reasoner over to
Ollama. These tests pin the fix: the catalog is consulted ONLY for NVIDIA.
"""

from __future__ import annotations

from venom.agents.roles import DEFAULT_AGENTS, AgentRole, AgentSpec
from venom.llm.providers import Provider


def test_deepseek_role_passes_reasoner_model_through_unchanged(monkeypatch):
    monkeypatch.setenv("VENOM_MODEL_CODEGEN", "deepseek-v4-pro")
    spec = DEFAULT_AGENTS[AgentRole.CODEGEN]
    assert spec.provider == Provider.DEEPSEEK
    # MUST stay 'deepseek-v4-pro' - not the NVIDIA id that 400s on DeepSeek.
    assert spec.model() == "deepseek-v4-pro"


def test_deepseek_role_chat_alias_passthrough(monkeypatch):
    monkeypatch.setenv("VENOM_MODEL_CODEGEN", "deepseek-chat")
    assert DEFAULT_AGENTS[AgentRole.CODEGEN].model() == "deepseek-chat"


def test_nvidia_role_still_expands_catalog_alias(monkeypatch):
    monkeypatch.delenv("VENOM_MODEL_TEST_NV", raising=False)
    spec = AgentSpec(role=AgentRole.CODEGEN, default_model="deepseek-v4-pro",
                     env_var="VENOM_MODEL_TEST_NV", description="", system_addendum="",
                     provider=Provider.NVIDIA_NIM)
    # For NVIDIA the alias MUST expand to the full NIM id.
    assert spec.model() == "deepseek-ai/deepseek-v4-pro"
