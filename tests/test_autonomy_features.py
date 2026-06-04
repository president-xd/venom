"""
Deterministic proofs (no LLM) for the production autonomy features:
  - skill REPLAY with per-session token re-binding   (reuse speeds up later runs)
  - strategy BACKTRACKING / self-correction          (retire a stalled strategy)
  - COST/TIME caps                                    (bounded hunts)
  - reliability success_rate harness                 (X% over N runs)
"""

import asyncio
from urllib.parse import parse_qs

import httpx

from venom.core.scope import Scope
from venom.core.registry import EndpointRegistry, Endpoint
from venom.memory import SkillLibrary
from venom.cognition import Agent, Objective, success_rate
from venom.llm.providers import _loads_lenient

BASE = "https://shop.example.net"


# ===================== robust LLM JSON parsing (reliability) =================
def test_loads_lenient_salvages_messy_llm_output():
    assert _loads_lenient('{"tool":"http_get","args":{"path":"/"}}') == {"tool": "http_get", "args": {"path": "/"}}
    assert _loads_lenient('{"a":1} then I will...')["a"] == 1          # trailing prose
    assert _loads_lenient("```json\n{\"a\":1,}\n```")["a"] == 1         # fence + trailing comma
    assert _loads_lenient('here: {"x":{"y":2}} ok')["x"]["y"] == 2     # embedded object
    import pytest
    with pytest.raises(Exception):
        _loads_lenient("no json here")


def _scope():
    return Scope.from_dict({"engagement_id": "E", "target_name": "Shop",
                            "authorized_base_urls": [BASE], "rate_limit_per_second": 5000,
                            "authorization_date": "2026-01-01T00:00:00Z",
                            "expiry_date": "2030-01-01T00:00:00Z"})


# ============================ skill replay (D + F) ============================
def make_rotating_shop():
    """Price-tamper shop whose CSRF ROTATES each GET — exact replay fails, only
    re-bound replay succeeds (proving the skill generalises across sessions)."""
    st = {"csrf": None, "n": 0, "solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html><body>{b}</body></html>")

    def handler(req):
        path, method = req.url.path, req.method
        form = {k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()}
        if path == "/" and method == "GET":
            return page("<div class='is-solved'>solved!</div>" if st["solved"] else "<a href=/product>p</a>")
        if path == "/product" and method == "GET":
            st["n"] += 1
            st["csrf"] = f"tok{st['n']}"
            return page(f"<form action=/buy method=POST><input name=csrf value={st['csrf']}>"
                        f"<input name=price value=1337></form>")
        if path == "/buy" and method == "POST":
            if form.get("csrf") == st["csrf"] and int(form.get("price", "1337")) < 100:
                st["solved"] = True
            return page("ok")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _registry():
    reg = EndpointRegistry()
    reg.add(Endpoint(path="/product", method="GET", source=["crawl"]))
    reg.add(Endpoint(path="/buy", method="POST", source=["crawl"]))
    return reg


def _composing_brain():
    """Reads the live CSRF from the form, then tampers the price."""
    async def brain(ctx):
        nb = ctx["notebook"]
        actions = [a["action"] for a in nb["recent_attempts"]]
        last = ctx.get("last_result") or {}
        if not any("http_get" in a and "/product" in a for a in actions):
            return {"tool": "http_get", "args": {"path": "/product"},
                    "strategy": "price_tamper", "rationale": "inspect form"}
        forms = (last.get("data") or {}).get("forms") or []
        if forms and not any("/buy" in a for a in actions):
            csrf = {f["name"]: f["value"] for f in forms[0]["fields"]}.get("csrf", "")
            return {"tool": "http_post_form", "args": {"path": "/buy", "fields": {"price": "1", "csrf": csrf}},
                    "strategy": "price_tamper", "rationale": "tamper price"}
        return {"tool": "give_up"}
    return brain


def test_skill_is_learned_then_replayed_with_token_rebinding(tmp_path):
    obj = Objective(description="buy the product cheaply", win_url="/", win_signals=("is-solved",))

    # Run 1: reason it out, learn a structured skill.
    skills = SkillLibrary(path=tmp_path / "s.json")
    a1 = Agent(_scope(), _composing_brain(), transport=make_rotating_shop(), skills=skills, max_steps=10)
    assert asyncio.run(a1.run(_registry(), obj)), "run1 did not solve"
    learned = SkillLibrary(path=tmp_path / "s.json").skills
    assert learned and learned[0].steps and any(s["tool"] == "http_post_form" for s in learned[0].steps)

    # Run 2: a brain that MUST NOT be called — replay has to carry it alone, and
    # the rotating CSRF means it only works if the replay re-binds the token.
    def boom(ctx):  # pragma: no cover - must never run
        raise AssertionError("brain called — replay should have solved it")

    a2 = Agent(_scope(), boom, transport=make_rotating_shop(),
               skills=SkillLibrary(path=tmp_path / "s.json"), max_steps=10,
               skill_replay_threshold=0.1)
    findings = asyncio.run(a2.run(_registry(), obj))
    assert findings, "replay did not solve run2"
    assert a2.last_run_stats["via"] == "replay"


# ====================== backtracking / self-correction (A) ===================
def make_dead_end_shop():
    st = {"solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html><body>{b}</body></html>")

    def handler(req):
        path, method = req.url.path, req.method
        form = {k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()}
        if path == "/" and method == "GET":
            return page("<div class='is-solved'>solved!</div>" if st["solved"] else "home")
        if path == "/nope" and method == "POST":
            return httpx.Response(404, headers={"content-type": "text/html"}, text="no")
        if path == "/win" and method == "POST":
            if form.get("key") == "x":
                st["solved"] = True
            return page("ok")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _stubborn_brain():
    """Pushes a failing 'bad' strategy until the LOOP retires it (surfaces it in
    stalled_strategies), then switches to the winning action."""
    async def brain(ctx):
        if "bad" in ctx.get("stalled_strategies", []):
            return {"tool": "http_post_form", "args": {"path": "/win", "fields": {"key": "x"}},
                    "strategy": "good", "rationale": "switch after stall"}
        return {"tool": "http_post_form", "args": {"path": "/nope", "fields": {}},
                "strategy": "bad", "rationale": "keep trying the dead end"}
    return brain


def test_backtracking_retires_stalled_strategy_and_skips_repeats(tmp_path):
    reg = EndpointRegistry()
    reg.add(Endpoint(path="/nope", method="POST", source=["crawl"]))
    reg.add(Endpoint(path="/win", method="POST", source=["crawl"]))
    agent = Agent(_scope(), _stubborn_brain(), transport=make_dead_end_shop(),
                  skills=SkillLibrary(path=tmp_path / "s.json"), max_steps=15, stall_window=4)
    obj = Objective(description="reach win", win_url="/", win_signals=("is-solved",))
    findings = asyncio.run(agent.run(reg, obj))
    assert findings, "agent never recovered from the dead end"
    # The failing /nope was executed only ONCE (then skipped), not spammed.
    reqs = [r for r in findings[0].evidence["requests"] if r["path"] == "/nope"]
    assert len(reqs) == 1, f"identical failed action not de-duplicated: {len(reqs)} calls"


# ============================== cost/time caps (B) ===========================
def test_deadline_stops_the_hunt():
    async def slow_loser(ctx):
        return {"tool": "http_get", "args": {"path": "/"}, "strategy": "x", "rationale": "spin"}
    agent = Agent(_scope(), slow_loser, transport=make_dead_end_shop(), deadline_seconds=0.0, max_steps=999)
    obj = Objective(description="never", win_url="/", win_signals=("never-xyz",))
    assert asyncio.run(agent.run(_registry(), obj)) == []
    assert agent.last_run_stats["won"] is False and agent.last_run_stats["steps"] <= 1


def test_max_steps_caps_the_hunt():
    async def loser(ctx):
        return {"tool": "http_get", "args": {"path": "/"}, "strategy": "x", "rationale": "spin"}
    agent = Agent(_scope(), loser, transport=make_dead_end_shop(), max_steps=3)
    obj = Objective(description="never", win_url="/", win_signals=("never-xyz",))
    assert asyncio.run(agent.run(_registry(), obj)) == []
    assert agent.last_run_stats["steps"] <= 3


# ========================= reliability harness (C) ===========================
def test_success_rate_measures_over_n_runs(tmp_path):
    outcomes = iter([True, False, True, False, True, False])   # deterministic 50%

    def make_agent():
        win = next(outcomes)

        async def brain(ctx):
            if win and not ctx["notebook"]["recent_attempts"]:
                return {"tool": "http_post_form", "args": {"path": "/win", "fields": {"key": "x"}},
                        "strategy": "g", "rationale": "win"}
            return {"tool": "give_up"}
        return Agent(_scope(), brain, transport=make_dead_end_shop(),
                     skills=SkillLibrary(path=tmp_path / f"s{id(brain)}.json"), max_steps=4)

    reg = EndpointRegistry()
    reg.add(Endpoint(path="/win", method="POST", source=["crawl"]))
    obj = Objective(description="reach win", win_url="/", win_signals=("is-solved",))
    stats = asyncio.run(success_rate(make_agent, lambda: reg, obj, runs=6))
    assert stats.runs == 6 and stats.wins == 3 and stats.rate == 0.5
    assert len(stats.per_run) == 6
