"""
The LLM "brain" for the reasoning loop: given the current (compact) observation
and recent action history, decide the single next action. Uses the business-logic
knowledge base as priors and is explicitly told to *think and probe before
exploiting*. All input is budget-trimmed by the agent layer for free-tier safety.
"""

from __future__ import annotations

import logging

from ..knowledge import kb_prompt
from .reasoner import Action

logger = logging.getLogger("venom.cognition.brain")

_SYSTEM = (
    "You are VENOM's reasoning core: a senior application-security engineer hunting "
    "BUSINESS-LOGIC flaws in a web app you are authorized to test. You THINK before "
    "acting. You prefer a cheap PROBE to learn how the app behaves, READ the actual "
    "response, RE-THINK, and only then attempt an EXPLOIT — which you VERIFY from the "
    "response. You are not limited to known patterns; reason from what you observe."
)

_SCHEMA = ('{"action":"probe|exploit|conclude","method":"GET|POST","path":"/...",'
           '"form":{},"json":{},"identity":"name","follow_redirects":true,'
           '"rationale":"why","success_signal":"text proving success","vuln_class":"...","title":"..."}')


def make_llm_brain(agent):
    """Return an async `decide(observation, history) -> Action` backed by an Agent."""

    async def decide(observation: dict, history: list[dict]) -> Action:
        user = (
            "BUSINESS-LOGIC KNOWLEDGE (priors, not rules):\n"
            f"{kb_prompt()}\n\n"
            "CURRENT OBSERVATION (endpoints, forms, catalog, store_credit, recent history):\n"
            f"{observation}\n\n"
            "Decide the SINGLE next action. If you have not learned enough, PROBE. "
            "Re-use values you already saw (e.g. CSRF tokens, prices) from history. "
            "When you attempt an EXPLOIT, set success_signal to a string that would "
            "appear in the response if it worked (e.g. 'is-solved', 'Order placed'). "
            "Conclude when you've confirmed an exploit or exhausted ideas.\n"
            f"Respond ONLY JSON: {_SCHEMA}"
        )
        try:
            d = await agent.complete_json(user, schema_hint=_SCHEMA)
        except Exception as exc:  # noqa: BLE001
            logger.warning("reasoner brain failed: %s", exc)
            return Action(type="conclude")
        return Action.from_dict(d)

    return decide
