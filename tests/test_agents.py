"""Multi-agent fleet: model selection, env overrides, orchestrator gating."""

import asyncio
import os

import pytest

from venom.agents import build_orchestrator, AgentRole, Agent
from venom.agents.roles import DEFAULT_AGENTS, resolve_models
from venom.llm import Provider, TaskType


def _default(role):
    # The built-in default, independent of any .env override the user may have set.
    return DEFAULT_AGENTS[role].default_model


def test_base_model_is_deepseek():
    assert _default(AgentRole.ORCHESTRATOR).startswith("deepseek-ai/deepseek-v4")
    assert _default(AgentRole.REPORTER).startswith("deepseek-ai/deepseek-v4")


def test_fleet_assignments():
    assert _default(AgentRole.RESEARCH) == "z-ai/glm-5.1"
    assert _default(AgentRole.HYPOTHESIS) == "moonshotai/kimi-k2.6"
    # CODEGEN drives the autonomous agent brain — Llama-4 Maverick is the verified
    # fast/clean codegen path on NVIDIA NIM (deepseek-v4-pro hangs on NIM, 2026-06-04).
    assert _default(AgentRole.CODEGEN) == "meta/llama-4-maverick-17b-128e-instruct"
    assert _default(AgentRole.SUMMARIZER) == "qwen/qwen3.5-397b-a17b"
    # resolve_models() honors .env overrides — that's the intended behavior.


def test_all_agents_route_through_nim():
    assert all(spec.provider == Provider.NVIDIA_NIM for spec in DEFAULT_AGENTS.values())


def test_env_override(monkeypatch):
    monkeypatch.setenv("VENOM_MODEL_HYPOTHESIS", "moonshotai/kimi-k9-test")
    assert DEFAULT_AGENTS[AgentRole.HYPOTHESIS].model() == "moonshotai/kimi-k9-test"


def test_catalog_alias_resolution(monkeypatch):
    from venom.llm.providers import resolve_nvidia_model, nvidia_model_catalog

    # Built-in alias resolves to full id; unknown name passes through unchanged.
    assert resolve_nvidia_model("kimi-k2.6") == "moonshotai/kimi-k2.6"
    assert resolve_nvidia_model("org/full-id") == "org/full-id"

    # A model registered purely via env is usable, with no code change.
    monkeypatch.setenv("VENOM_NVIDIA_MODELS", "myllm=acme/super-llm-v9")
    assert nvidia_model_catalog()["myllm"] == "acme/super-llm-v9"
    assert resolve_nvidia_model("myllm") == "acme/super-llm-v9"


def test_role_var_accepts_alias(monkeypatch):
    # Users can put a short alias in the role var instead of the full id.
    monkeypatch.setenv("VENOM_MODEL_RESEARCH", "glm-5.1")
    assert DEFAULT_AGENTS[AgentRole.RESEARCH].model() == "z-ai/glm-5.1"


class _StubProvider:
    enabled = True


class _StubRouter:
    """Minimal router that records the provider/model an agent forces."""

    def __init__(self, nim_enabled=True):
        self.providers = {Provider.NVIDIA_NIM: type("C", (), {"enabled": nim_enabled})()}
        self.calls = []

    def any_enabled(self):
        return True

    async def complete(self, task, messages, system="", override_provider=None, **kwargs):
        self.calls.append({"task": task, "provider": override_provider, "model": kwargs.get("model")})
        return {"content": '{"ok": true}', "model": kwargs.get("model"), "provider": "nvidia_nim"}


def test_agent_forces_its_model_and_provider():
    router = _StubRouter()
    agent = Agent(DEFAULT_AGENTS[AgentRole.HYPOTHESIS], router)
    parsed = asyncio.run(agent.complete_json("test", schema_hint="{}"))
    assert parsed == {"ok": True}
    call = router.calls[-1]
    assert call["provider"] == Provider.NVIDIA_NIM
    assert call["model"] == "moonshotai/kimi-k2.6"


def test_orchestrator_disabled_without_nim_key():
    router = _StubRouter(nim_enabled=False)
    orch = build_orchestrator(router)
    assert orch is not None
    assert orch.enabled is False  # falls back to offline pipeline


def test_orchestrator_enabled_with_nim():
    orch = build_orchestrator(_StubRouter(nim_enabled=True))
    assert orch.enabled is True
    assert orch.agent(AgentRole.ORCHESTRATOR).model.startswith("deepseek-ai/deepseek-v4")


def test_codegen_and_summarizer_are_wired(monkeypatch):
    """CODEGEN + SUMMARIZER must actually be invoked (not decorative)."""
    from venom.testing.schema import TestCase, TestStep, VulnClass, Severity

    class _Router(_StubRouter):
        async def complete(self, task, messages, system="", override_provider=None, **kwargs):
            self.calls.append({"model": kwargs.get("model")})
            # CODEGEN expects JSON; SUMMARIZER expects text.
            return {"content": '{"conditions":[{"test_id":"TC-LLM-001","step":1,'
                               '"success_condition":"status == 200"}]}',
                    "model": kwargs.get("model"), "provider": "nvidia_nim"}

    router = _Router()
    orch = build_orchestrator(router)

    case = TestCase(test_id="TC-LLM-001", vulnerability_class=VulnClass.STATE_BYPASS,
                    hypothesis="x", risk_rating=Severity.HIGH, origin="llm",
                    steps=[TestStep(step=1, description="d", method="GET", path="/x")])
    # Resolve the EXPECTED model from each role's spec (honors env overrides) so the
    # test proves the right role was invoked without hard-coding a (possibly dead) id.
    codegen_model = orch.agent(AgentRole.CODEGEN).model
    summarizer_model = orch.agent(AgentRole.SUMMARIZER).model

    out = asyncio.run(orch.concretize([case]))
    assert out[0].steps[0].success_condition == "status == 200"
    assert out[0].origin == "codegen"
    assert any(c["model"] == codegen_model for c in router.calls)  # CODEGEN model

    asyncio.run(orch.summarize_results([{"class": "X", "verdict": "Y"}]))
    assert any(c["model"] == summarizer_model for c in router.calls)  # SUMMARIZER model
