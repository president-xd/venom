"""LLM response cache, token budget, and tracing on the router."""

import asyncio

import pytest

from venom.llm.providers import LLMRouter, Provider, ProviderConfig, TaskType
from venom.llm.telemetry import ResponseCache, Budget, Tracer, BudgetExceeded


def test_budget_hard_stop():
    b = Budget(max_tokens=20)
    b.add(8, 5)
    b.check()                 # 13 < 20, ok
    b.add(10, 0)              # 23 >= 20
    with pytest.raises(BudgetExceeded):
        b.check()


def test_cache_key_stable_and_store():
    c = ResponseCache()
    k1 = c.key("t", "m", "sys", [{"role": "user", "content": "x"}])
    k2 = c.key("t", "m", "sys", [{"role": "user", "content": "x"}])
    assert k1 == k2
    assert c.get(k1) is None and c.misses == 1
    c.put(k1, {"content": "hi"})
    assert c.get(k1)["content"] == "hi" and c.hits == 1


def _router():
    cfg = ProviderConfig(provider=Provider.NVIDIA_NIM, api_key="x", enabled=True)
    return LLMRouter(providers={Provider.NVIDIA_NIM: cfg},
                     routing={t: Provider.NVIDIA_NIM for t in TaskType})


def test_router_cache_budget_trace_integration():
    router = _router()
    calls = {"n": 0}

    async def fake_dispatch(cfg, task, messages, system, **kw):
        calls["n"] += 1
        return {"content": "ok", "model": "m", "input_tokens": 10, "output_tokens": 5, "raw": {}}

    router._dispatch = fake_dispatch
    router.with_telemetry(cache=ResponseCache(), budget=Budget(max_tokens=1000), tracer=Tracer())

    async def go():
        msg = [{"role": "user", "content": "same"}]
        await router.complete(TaskType.HYPOTHESIS_GEN, msg, system="s",
                              override_provider=Provider.NVIDIA_NIM, model="m")
        await router.complete(TaskType.HYPOTHESIS_GEN, msg, system="s",
                              override_provider=Provider.NVIDIA_NIM, model="m")  # cached

    asyncio.run(go())
    assert calls["n"] == 1                      # second call served from cache
    assert router.cache.hits == 1
    assert router.budget.total == 15            # only the real call counted
    s = router.tracer.summary()
    assert s["llm_calls"] == 2 and s["cached"] == 1


def test_router_budget_blocks_next_call():
    router = _router()

    async def fake_dispatch(cfg, task, messages, system, **kw):
        return {"content": "ok", "model": "m", "input_tokens": 100, "output_tokens": 0, "raw": {}}

    router._dispatch = fake_dispatch
    router.with_telemetry(budget=Budget(max_tokens=50))

    async def go():
        await router.complete(TaskType.HYPOTHESIS_GEN, [{"role": "user", "content": "a"}],
                              override_provider=Provider.NVIDIA_NIM)  # spends 100 -> over
        with pytest.raises(BudgetExceeded):
            await router.complete(TaskType.HYPOTHESIS_GEN, [{"role": "user", "content": "b"}],
                                  override_provider=Provider.NVIDIA_NIM)

    asyncio.run(go())
