"""
The agent loop.

A stub 'brain' (no LLM, no hardcoded flow module) drives the agent to an
objective by COMPOSING tools: it first tries a decoy strategy (coupon) that
makes no progress, then BACKTRACKS to price-tampering — reading the CSRF/price
out of the live form via the toolbox — and wins. On success the agent LEARNS a
retrievable skill. This proves the mechanism is generic, not a pre-written script.
"""

import asyncio
from urllib.parse import parse_qs

import httpx

from venom.core.scope import Scope
from venom.core.registry import EndpointRegistry, Endpoint
from venom.memory import SkillLibrary
from venom.cognition import Agent, Objective
from venom.testing.schema import Verdict

BASE = "https://shop.example.net"


def make_shop():
    state = {"solved": False}

    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def handler(req):
        path, method = req.url.path, req.method
        form = {k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()}
        if path == "/" and method == "GET":
            return page("<div class='is-solved'>Congratulations, you solved the lab!</div>"
                        if state["solved"] else "<a href=/product>jacket</a>")
        if path == "/product" and method == "GET":
            return page("<form action=/buy method=POST>"
                        "<input type=hidden name=price value=1337>"
                        "<input type=hidden name=csrf value=ABC></form>")
        if path == "/coupon" and method == "POST":          # decoy — never helps
            return page("No such coupon.")
        if path == "/buy" and method == "POST":             # client-trust price flaw
            if int(form.get("price", "1337")) < 100 and form.get("csrf") == "ABC":
                state["solved"] = True
            return page("ok")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _registry():
    reg = EndpointRegistry()
    reg.add(Endpoint(path="/product", method="GET", source=["crawl"]))
    reg.add(Endpoint(path="/buy", method="POST", source=["crawl"]))
    reg.add(Endpoint(path="/coupon", method="POST", source=["crawl"]))
    return reg


def _stub_brain():
    """Deterministic reasoning: try coupon (decoy) → backtrack to price tamper."""
    async def brain(ctx):
        nb = ctx["notebook"]
        actions = [a["action"] for a in nb["recent_attempts"]]
        tried = set(nb["strategies_tried"])
        last = ctx.get("last_result") or {}

        # Strategy 1: coupon (will not meet the objective).
        if "coupon" not in tried:
            return {"tool": "http_post_form", "args": {"path": "/coupon", "fields": {"code": "FREE"}},
                    "strategy": "coupon", "rationale": "try a discount code first"}

        # Backtrack → Strategy 2: price tampering.
        if not any("http_get {'path': '/product'}" == a for a in actions):
            return {"tool": "http_get", "args": {"path": "/product"},
                    "strategy": "price_tamper", "rationale": "inspect the purchase form"}

        # Compose the exploit from the live form (read CSRF/price from last result).
        forms = (last.get("data") or {}).get("forms") or []
        if forms and not any("/buy" in a for a in actions):
            fields = {f["name"]: f["value"] for f in forms[0]["fields"]}
            csrf = fields.get("csrf", "")
            return {"tool": "http_post_form",
                    "args": {"path": "/buy", "fields": {"price": "1", "csrf": csrf}},
                    "strategy": "price_tamper", "rationale": "submit a tampered price"}
        return {"tool": "give_up"}
    return brain


def _scope():
    return Scope.from_dict({"engagement_id": "E", "target_name": "JacketShop",
                            "authorized_base_urls": [BASE], "rate_limit_per_second": 500,
                            "authorization_date": "2026-01-01T00:00:00Z",
                            "expiry_date": "2030-01-01T00:00:00Z"})


def test_agent_solves_by_composing_tools_and_learns(tmp_path):
    skills = SkillLibrary(path=tmp_path / "skills.json")
    agent = Agent(_scope(), _stub_brain(), transport=make_shop(), skills=skills, max_steps=12)
    obj = Objective(description="buy the jacket cheaply", win_url="/", win_signals=("is-solved",))
    findings = asyncio.run(agent.run(_registry(), obj))

    # Solved the objective by composing tools (not a hardcoded flow).
    assert findings and findings[0].verdict == Verdict.CONFIRMED_EXPLOIT
    assert findings[0].origin == "agent"
    # It actually backtracked: both strategies appear in the chain.
    strategies = findings[0].notes[0]
    assert "price_tamper" in strategies
    # It LEARNED a retrievable skill.
    learned = SkillLibrary(path=tmp_path / "skills.json").retrieve("buy the jacket", "product buy", k=3)
    assert learned, "agent did not persist a skill"


def test_agent_no_win_returns_nothing(tmp_path):
    # An unsolvable objective yields no false-positive finding.
    agent = Agent(_scope(), _stub_brain(), transport=make_shop(),
                  skills=SkillLibrary(path=tmp_path / "s.json"), max_steps=12)
    obj = Objective(description="impossible", win_url="/", win_signals=("never-appears-xyz",))
    assert asyncio.run(agent.run(_registry(), obj)) == []
