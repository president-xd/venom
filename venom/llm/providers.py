"""
Multi-provider LLM router for the VENOM / CIPHER pentest agent.

Supported providers:
  - Anthropic (Claude)       -> cloud, strongest reasoning
  - OpenRouter               -> cloud, flexible model routing + fallback
  - NVIDIA NIM               -> cloud/on-prem GPU, enterprise deployments
  - Ollama                   -> fully local, air-gapped engagements

Usage:
    from venom.llm import LLMRouter, TaskType

    router = LLMRouter.from_env()
    response = await router.complete(
        task=TaskType.RULE_INFERENCE,
        messages=[{"role": "user", "content": "Analyze this state machine..."}],
        system=AGENT_SYSTEM_PROMPT,
    )
"""

from __future__ import annotations

import os
import json
import time
import logging
from enum import Enum
from typing import Any, Optional
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger("venom.llm")


# ---------------------------------------------------------------------------
# Task taxonomy — drives provider routing decisions
# ---------------------------------------------------------------------------

class TaskType(str, Enum):
    RULE_INFERENCE     = "rule_inference"        # Complex business rule extraction
    HYPOTHESIS_GEN     = "hypothesis_generation" # Attack hypothesis creation
    RAG_EMBEDDING      = "rag_embedding"         # High-volume embedding generation
    TEST_SUMMARIZATION = "test_summarization"    # Summarize test results cheaply
    REPORT_GENERATION  = "report_generation"     # Final report quality matters
    CODE_GENERATION    = "code_generation"       # Generate test scripts
    GRAPH_EXTRACTION   = "graph_extraction"      # Extract structured graph from docs


class Provider(str, Enum):
    ANTHROPIC  = "anthropic"
    OPENROUTER = "openrouter"
    NVIDIA_NIM = "nvidia_nim"
    OLLAMA     = "ollama"


# ---------------------------------------------------------------------------
# Per-provider configuration
# ---------------------------------------------------------------------------

@dataclass
class ProviderConfig:
    provider: Provider
    api_key: Optional[str] = None
    base_url: str = ""
    model: str = ""
    max_tokens: int = 4096
    temperature: float = 0.2  # Low for deterministic security analysis
    timeout: float = 120.0
    enabled: bool = True
    extra_headers: dict[str, str] = field(default_factory=dict)

    # Rate limiting
    requests_per_minute: int = 60
    _request_times: list[float] = field(default_factory=list, repr=False)

    def check_rate_limit(self) -> None:
        """Sliding-window rate limiter — raises if we'd exceed RPM."""
        now = time.monotonic()
        self._request_times = [t for t in self._request_times if now - t < 60]
        if len(self._request_times) >= self.requests_per_minute:
            wait = 60 - (now - self._request_times[0])
            raise RuntimeError(f"[{self.provider}] Rate limit hit — retry in {wait:.1f}s")
        self._request_times.append(now)


# ---------------------------------------------------------------------------
# Default provider configurations
# ---------------------------------------------------------------------------

ANTHROPIC_DEFAULT = ProviderConfig(
    provider=Provider.ANTHROPIC,
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    base_url="https://api.anthropic.com/v1/messages",
    model="claude-opus-4-8",  # Strongest for complex reasoning
    max_tokens=8192,
    temperature=0.2,
    extra_headers={"anthropic-version": "2023-06-01"},
    requests_per_minute=50,
)

OPENROUTER_DEFAULT = ProviderConfig(
    provider=Provider.OPENROUTER,
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url="https://openrouter.ai/api/v1/chat/completions",
    model="anthropic/claude-sonnet-4-6",  # Default; override per task
    max_tokens=4096,
    temperature=0.2,
    extra_headers={
        "HTTP-Referer": "https://github.com/your-org/venom-agent",
        "X-Title": "VENOM Pentest Agent",
    },
    requests_per_minute=60,
)

NVIDIA_NIM_DEFAULT = ProviderConfig(
    provider=Provider.NVIDIA_NIM,
    api_key=os.getenv("NVIDIA_API_KEY"),
    base_url=os.getenv(
        "NVIDIA_NIM_BASE_URL", "https://integrate.api.nvidia.com/v1/chat/completions"
    ),
    # Base model for the whole agent system (DeepSeek). Per-agent models override
    # this at call time — see venom.agents.roles.
    model=os.getenv("VENOM_BASE_MODEL", "deepseek-ai/deepseek-v4-pro"),
    max_tokens=8192,
    temperature=0.2,
    requests_per_minute=40,
)

OLLAMA_DEFAULT = ProviderConfig(
    provider=Provider.OLLAMA,
    api_key=None,  # No key needed for local Ollama
    base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/api/chat"),
    model=os.getenv("OLLAMA_MODEL", "llama3.1:70b"),
    max_tokens=4096,
    temperature=0.2,
    timeout=300.0,  # Local inference is slower
    requests_per_minute=20,
)


# ---------------------------------------------------------------------------
# Task -> provider routing tables
# ---------------------------------------------------------------------------

DEFAULT_ROUTING: dict[TaskType, Provider] = {
    TaskType.RULE_INFERENCE:     Provider.ANTHROPIC,
    TaskType.HYPOTHESIS_GEN:     Provider.ANTHROPIC,
    TaskType.RAG_EMBEDDING:      Provider.OLLAMA,
    TaskType.TEST_SUMMARIZATION: Provider.OPENROUTER,
    TaskType.REPORT_GENERATION:  Provider.ANTHROPIC,
    TaskType.CODE_GENERATION:    Provider.OPENROUTER,
    TaskType.GRAPH_EXTRACTION:   Provider.ANTHROPIC,
}

AIR_GAP_ROUTING: dict[TaskType, Provider] = {task: Provider.OLLAMA for task in TaskType}

BUDGET_ROUTING: dict[TaskType, Provider] = {
    TaskType.RULE_INFERENCE:     Provider.OPENROUTER,
    TaskType.HYPOTHESIS_GEN:     Provider.OPENROUTER,
    TaskType.RAG_EMBEDDING:      Provider.OLLAMA,
    TaskType.TEST_SUMMARIZATION: Provider.OLLAMA,
    TaskType.REPORT_GENERATION:  Provider.OPENROUTER,
    TaskType.CODE_GENERATION:    Provider.NVIDIA_NIM,
    TaskType.GRAPH_EXTRACTION:   Provider.OPENROUTER,
}

OPENROUTER_MODEL_MAP: dict[TaskType, str] = {
    TaskType.RULE_INFERENCE:     "anthropic/claude-opus-4-8",
    TaskType.HYPOTHESIS_GEN:     "anthropic/claude-sonnet-4-6",
    TaskType.RAG_EMBEDDING:      "openai/text-embedding-3-small",
    TaskType.TEST_SUMMARIZATION: "mistralai/mistral-7b-instruct",
    TaskType.REPORT_GENERATION:  "anthropic/claude-opus-4-8",
    TaskType.CODE_GENERATION:    "deepseek/deepseek-coder-v2",
    TaskType.GRAPH_EXTRACTION:   "anthropic/claude-sonnet-4-6",
}

OLLAMA_MODEL_OPTIONS: list[str] = [
    "llama3.1:70b",     # Best balance of quality/speed for local
    "llama3.1:8b",      # Fast, lower quality
    "mistral:7b",       # Good for structured output tasks
    "deepseek-r1:14b",  # Strong reasoning, good for hypothesis generation
    "deepseek-r1:32b",  # Better reasoning, slower
    "codellama:34b",    # Best for code generation tasks
    "phi3:medium",      # Compact but capable
]

# NVIDIA NIM model catalog (alias -> full model id). These are only built-in
# DEFAULTS; users register/override models from the environment via
# VENOM_NVIDIA_MODELS (comma-separated `alias=full/model-id` pairs) — no code
# edit required. Aliases may be used as shorthand in VENOM_MODEL_<ROLE>.
_DEFAULT_NVIDIA_MODELS: dict[str, str] = {
    "deepseek-v4-pro":  "deepseek-ai/deepseek-v4-pro",   # base / orchestrator / reporter
    "kimi-k2.6":        "moonshotai/kimi-k2.6",          # hypothesis subagent
    "glm-5.1":          "z-ai/glm-5.1",                  # research agent
    "qwen3.5":          "qwen/qwen3.5-397b-a17b",        # codegen / summarizer subagent
    "llama3.1-70b":     "meta/llama-3.1-70b-instruct",
    "llama3.1-405b":    "meta/llama-3.1-405b-instruct",
    "nemotron-340b":    "nvidia/nemotron-4-340b-instruct",
}


def nvidia_model_catalog() -> dict[str, str]:
    """Built-in defaults merged with any aliases registered in VENOM_NVIDIA_MODELS.
    Read at call time so .env edits take effect without a restart of the import."""
    catalog = dict(_DEFAULT_NVIDIA_MODELS)
    for pair in os.getenv("VENOM_NVIDIA_MODELS", "").split(","):
        pair = pair.strip()
        if "=" in pair:
            alias, full = (s.strip() for s in pair.split("=", 1))
            if alias and full:
                catalog[alias] = full
    return catalog


def resolve_nvidia_model(name: str) -> str:
    """Resolve an alias (e.g. 'kimi-k2.6') to its full NIM id; pass through full ids."""
    return nvidia_model_catalog().get(name, name)


# Back-compat snapshot of the default catalog (use nvidia_model_catalog() for live).
NVIDIA_MODEL_MAP: dict[str, str] = nvidia_model_catalog()


# ---------------------------------------------------------------------------
# The main router
# ---------------------------------------------------------------------------

class LLMRouter:
    """Routes LLM calls to the appropriate provider, with fallback."""

    def __init__(
        self,
        providers: dict[Provider, ProviderConfig],
        routing: dict[TaskType, Provider] = DEFAULT_ROUTING,
        air_gap: bool = False,
        fallback_chain: list[Provider] | None = None,
    ):
        self.providers = providers
        self.routing = AIR_GAP_ROUTING if air_gap else routing
        self.air_gap = air_gap
        self.fallback_chain = fallback_chain or [
            Provider.OPENROUTER,
            Provider.NVIDIA_NIM,
            Provider.OLLAMA,
        ]
        # Optional Phase-E telemetry (cache / budget / tracer). None => no-op.
        self.cache = None
        self.budget = None
        self.tracer = None

    def with_telemetry(self, *, cache=None, budget=None, tracer=None) -> "LLMRouter":
        self.cache, self.budget, self.tracer = cache, budget, tracer
        return self

    @classmethod
    def from_env(cls, air_gap: bool = False, mode: str = "default") -> "LLMRouter":
        air_gap = air_gap or os.getenv("LLM_AIR_GAP", "").lower() == "true"
        mode = os.getenv("LLM_MODE", mode)

        routing = {
            "default": DEFAULT_ROUTING,
            "budget": BUDGET_ROUTING,
            "air_gap": AIR_GAP_ROUTING,
        }.get(mode, DEFAULT_ROUTING)

        providers = {
            Provider.ANTHROPIC: ANTHROPIC_DEFAULT,
            Provider.OPENROUTER: OPENROUTER_DEFAULT,
            Provider.NVIDIA_NIM: NVIDIA_NIM_DEFAULT,
            Provider.OLLAMA: OLLAMA_DEFAULT,
        }

        # Re-read API keys at call time (robust if .env was loaded after this
        # module was imported), then disable providers with no key (Ollama needs none).
        env_key = {Provider.ANTHROPIC: "ANTHROPIC_API_KEY",
                   Provider.OPENROUTER: "OPENROUTER_API_KEY",
                   Provider.NVIDIA_NIM: "NVIDIA_API_KEY"}
        for p, cfg in providers.items():
            if p in env_key:
                cfg.api_key = os.getenv(env_key[p]) or cfg.api_key
            if p != Provider.OLLAMA and not cfg.api_key:
                cfg.enabled = False
                logger.debug("[%s] disabled — no API key in environment", p)
            elif p != Provider.OLLAMA:
                cfg.enabled = True

        return cls(providers=providers, routing=routing, air_gap=air_gap)

    def any_enabled(self) -> bool:
        """True if at least one provider is usable (Ollama counts only in air-gap)."""
        for p, cfg in self.providers.items():
            if not cfg.enabled:
                continue
            if p == Provider.OLLAMA and not self.air_gap:
                # Ollama is technically enabled but we don't assume a local server
                # is running unless we're in air-gap mode.
                continue
            return True
        return self.air_gap  # air-gap relies on local Ollama

    async def complete(
        self,
        task: TaskType,
        messages: list[dict[str, str]],
        system: str = "",
        override_provider: Optional[Provider] = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Route a completion request, falling back through the fallback chain."""
        target = override_provider or self.routing.get(task, Provider.ANTHROPIC)
        attempt_order = [target] + [p for p in self.fallback_chain if p != target]

        # --- cache: identical calls (common in agent loops) skip the provider ---
        ckey = None
        if self.cache is not None:
            ckey = self.cache.key(task, kwargs.get("model"), system, messages)
            hit = self.cache.get(ckey)
            if hit is not None:
                if self.tracer is not None:
                    self.tracer.record(task=str(task), provider=hit.get("provider"),
                                       model=hit.get("model"), cached=True,
                                       input_tokens=0, output_tokens=0, latency_ms=0)
                return hit

        # --- budget: hard-stop before spending more tokens ---
        if self.budget is not None:
            self.budget.check()

        last_error = None
        for provider in attempt_order:
            cfg = self.providers.get(provider)
            if not cfg or not cfg.enabled:
                continue
            # Model-aware fallback: a model id is provider-specific. Only apply an
            # explicit `model` override to the originally-targeted provider; when
            # falling back to a different provider, drop it and use that provider's
            # own default model (otherwise the request is guaranteed to fail).
            call_kwargs = dict(kwargs)
            if provider != target and "model" in call_kwargs:
                call_kwargs.pop("model")
            try:
                cfg.check_rate_limit()
                t0 = time.monotonic()
                result = await self._dispatch(cfg, task, messages, system, **call_kwargs)
                result["provider"] = provider.value
                latency_ms = int((time.monotonic() - t0) * 1000)
                if self.budget is not None:
                    self.budget.add(result.get("input_tokens", 0), result.get("output_tokens", 0))
                if self.tracer is not None:
                    self.tracer.record(task=str(task), provider=provider.value,
                                       model=result.get("model"), cached=False,
                                       input_tokens=result.get("input_tokens", 0),
                                       output_tokens=result.get("output_tokens", 0),
                                       latency_ms=latency_ms)
                if self.cache is not None and ckey is not None:
                    self.cache.put(ckey, result)
                logger.info(
                    "[%s] %s completed — %s->%s tokens (%dms)",
                    provider, task,
                    result.get("input_tokens", "?"), result.get("output_tokens", "?"), latency_ms,
                )
                return result
            except Exception as exc:  # noqa: BLE001 — provider-agnostic fallback
                last_error = exc
                logger.warning("[%s] %s failed: %s — trying next provider", provider, task, exc)
                continue

        raise RuntimeError(f"All providers failed for task {task}. Last error: {last_error}")

    async def _dispatch(self, cfg, task, messages, system, **kwargs) -> dict[str, Any]:
        if cfg.provider == Provider.ANTHROPIC:
            return await self._call_anthropic(cfg, messages, system, **kwargs)
        if cfg.provider == Provider.OPENROUTER:
            return await self._call_openrouter(cfg, task, messages, system, **kwargs)
        if cfg.provider == Provider.NVIDIA_NIM:
            return await self._call_nvidia(cfg, messages, system, **kwargs)
        if cfg.provider == Provider.OLLAMA:
            return await self._call_ollama(cfg, messages, system, **kwargs)
        raise ValueError(f"Unknown provider: {cfg.provider}")

    # ------------------------------------------------------------------ Anthropic
    async def _call_anthropic(self, cfg, messages, system, **kwargs) -> dict[str, Any]:
        headers = {"x-api-key": cfg.api_key, "Content-Type": "application/json", **cfg.extra_headers}
        payload = {
            "model": kwargs.get("model", cfg.model),
            "max_tokens": kwargs.get("max_tokens", cfg.max_tokens),
            "temperature": kwargs.get("temperature", cfg.temperature),
            "messages": messages,
        }
        if system:
            payload["system"] = system
        async with httpx.AsyncClient(timeout=cfg.timeout) as client:
            resp = await client.post(cfg.base_url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        return {
            "content": data["content"][0]["text"],
            "model": data.get("model", cfg.model),
            "input_tokens": data.get("usage", {}).get("input_tokens", 0),
            "output_tokens": data.get("usage", {}).get("output_tokens", 0),
            "raw": data,
        }

    # ----------------------------------------------------------------- OpenRouter
    async def _call_openrouter(self, cfg, task, messages, system, **kwargs) -> dict[str, Any]:
        model = kwargs.get("model") or OPENROUTER_MODEL_MAP.get(task, cfg.model)
        headers = {"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json", **cfg.extra_headers}
        msgs = ([{"role": "system", "content": system}] if system else []) + messages
        payload = {
            "model": model,
            "messages": msgs,
            "max_tokens": kwargs.get("max_tokens", cfg.max_tokens),
            "temperature": kwargs.get("temperature", cfg.temperature),
            "route": "fallback",
        }
        async with httpx.AsyncClient(timeout=cfg.timeout) as client:
            resp = await client.post(cfg.base_url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        usage = data.get("usage", {})
        return {
            "content": data["choices"][0]["message"]["content"],
            "model": data.get("model", model),
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "raw": data,
        }

    # ----------------------------------------------------------------- NVIDIA NIM
    async def _call_nvidia(self, cfg, messages, system, **kwargs) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json", **cfg.extra_headers}
        msgs = ([{"role": "system", "content": system}] if system else []) + messages
        payload = {
            "model": kwargs.get("model", cfg.model),
            "messages": msgs,
            "max_tokens": kwargs.get("max_tokens", cfg.max_tokens),
            "temperature": kwargs.get("temperature", cfg.temperature),
            "stream": False,
            "nvext": {"repetition_penalty": 1.0},
        }
        async with httpx.AsyncClient(timeout=cfg.timeout) as client:
            resp = await client.post(cfg.base_url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        usage = data.get("usage", {})
        return {
            "content": data["choices"][0]["message"]["content"],
            "model": data.get("model", cfg.model),
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "raw": data,
        }

    # --------------------------------------------------------------------- Ollama
    async def _call_ollama(self, cfg, messages, system, **kwargs) -> dict[str, Any]:
        msgs = ([{"role": "system", "content": system}] if system else []) + messages
        payload = {
            "model": kwargs.get("model", cfg.model),
            "messages": msgs,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", cfg.temperature),
                "num_predict": kwargs.get("max_tokens", cfg.max_tokens),
            },
        }
        async with httpx.AsyncClient(timeout=cfg.timeout) as client:
            resp = await client.post(cfg.base_url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        return {
            "content": data.get("message", {}).get("content", ""),
            "model": data.get("model", cfg.model),
            "input_tokens": data.get("prompt_eval_count", 0),
            "output_tokens": data.get("eval_count", 0),
            "raw": data,
        }


# ---------------------------------------------------------------------------
# Structured output helper
# ---------------------------------------------------------------------------

async def complete_json(
    router: LLMRouter,
    task: TaskType,
    messages: list[dict[str, str]],
    system: str = "",
    schema_hint: str = "",
    **kwargs,
) -> dict[str, Any]:
    """Request a JSON response and parse it robustly."""
    json_instruction = (
        "\n\nRespond ONLY with valid JSON. No markdown, no code fences, no explanation. "
        f"{'Schema hint: ' + schema_hint if schema_hint else ''}"
    )
    augmented = messages.copy()
    if augmented and augmented[-1]["role"] == "user":
        augmented[-1] = {**augmented[-1], "content": augmented[-1]["content"] + json_instruction}

    result = await router.complete(task, augmented, system, **kwargs)
    raw_text = result["content"].strip()
    if raw_text.startswith("```"):
        raw_text = raw_text.split("\n", 1)[-1].rsplit("```", 1)[0]
    result["parsed"] = json.loads(raw_text)
    return result


# ---------------------------------------------------------------------------
# Quick connectivity test
# ---------------------------------------------------------------------------

async def test_all_providers(router: LLMRouter) -> None:
    ping = [{"role": "user", "content": "Reply with the single word: OK"}]
    for provider, cfg in router.providers.items():
        if not cfg.enabled:
            print(f"  [{provider.value}] DISABLED (no API key)")
            continue
        try:
            res = await router.complete(
                TaskType.TEST_SUMMARIZATION, ping, override_provider=provider, max_tokens=10
            )
            print(f"  [{provider.value}] OK — model: {res['model']}")
        except Exception as e:  # noqa: BLE001
            print(f"  [{provider.value}] FAILED — {e}")


if __name__ == "__main__":
    import asyncio

    async def main():
        print("Testing all configured providers...\n")
        await test_all_providers(LLMRouter.from_env())

    asyncio.run(main())
