"""
Best-of-N reliability lever: each retry of the one-shot synthesizer is a fresh,
MORE DIVERSE sample (rising temperature + an explicit change-approach nudge) so
the agent explores new flaw classes instead of re-rolling the same dead end.
"""

import pytest

from venom.cognition.oneshot import make_oneshot_synthesizer


class _RecordingAgent:
    """Stub LLM agent that records the temperature of each call and returns a
    minimal valid synthesis so the loop continues."""

    def __init__(self):
        self.temps = []
        self.prompts = []

    async def complete_text(self, user, *, temperature=0.1, **kw):
        self.temps.append(temperature)
        self.prompts.append(user)
        return "VULN: client-side-trust\n```python\nasync def exploit(http):\n    return 1\n```"


_BRIEF = {"objective": "buy the jacket", "win_url": "/", "endpoints": [
    {"method": "POST", "path": "/cart", "params": ["productId", "price"]}]}


async def test_temperature_ramps_across_retries():
    agent = _RecordingAgent()
    synth = make_oneshot_synthesizer(agent)
    await synth(_BRIEF, None)                       # attempt 0
    await synth(_BRIEF, {"objective_met": False})   # attempt 1 (retry)
    await synth(_BRIEF, {"objective_met": False})   # attempt 2 (retry)
    assert agent.temps == sorted(agent.temps)       # monotonically non-decreasing
    assert agent.temps[0] < agent.temps[-1]         # genuinely more diverse on retries
    assert agent.temps[0] <= 0.15                    # first attempt stays focused


async def test_retry_prompt_demands_a_different_approach():
    agent = _RecordingAgent()
    synth = make_oneshot_synthesizer(agent)
    await synth(_BRIEF, None)
    await synth(_BRIEF, {"objective_met": False, "hint": "still denied"})
    # the first prompt has no change-approach nudge; the retry prompt does
    assert "different" not in agent.prompts[0].lower() or "DIFFERENT vulnerability" not in agent.prompts[0]
    assert "DIFFERENT vulnerability class" in agent.prompts[1]


async def test_synth_still_returns_valid_shape():
    agent = _RecordingAgent()
    synth = make_oneshot_synthesizer(agent)
    out = await synth(_BRIEF, None)
    assert out["vuln_class"] == "client-side-trust"
    assert "async def exploit" in out["exploit_code"]
