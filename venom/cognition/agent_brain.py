"""
LLM brain for the agent loop. Given the compact context (objective, surface,
tool catalog, notebook/memory, retrieved skills, last result), it picks the SINGLE
next tool call. Explicitly told to probe and reason before exploiting, to reuse
facts from memory, and to switch strategy when one stalls.

Returns a decision dict: {tool, args, strategy, rationale}.
All input is budget-trimmed by the agent layer (free-tier safe).
"""

from __future__ import annotations

import logging

from ..knowledge import kb_prompt
from ..llm.budget import trim

logger = logging.getLogger("venom.cognition.agent_brain")

_SYSTEM = (
    "You are VENOM's autonomous reasoning core — a senior application-security "
    "engineer with a toolbox, working memory, and a goal. THINK before you act: "
    "probe cheaply, read results, update memory, and only then exploit. If a "
    "strategy stalls (memory shows no progress), SWITCH to a different one. You are "
    "not limited to known patterns; reason from what you observe. Respond with ONE "
    "tool call as JSON."
)

_SCHEMA = ('{"tool":"<one of the catalog tool names>","args":{...},'
           '"strategy":"short-name","rationale":"why this advances the goal"}')


def make_agent_brain(agent):
    """Return an async `brain(context) -> decision` backed by an LLM Agent."""

    async def brain(ctx: dict) -> dict:
        user = (
            f"OBJECTIVE: {ctx['objective']}\n\n"
            f"BUSINESS-LOGIC KNOWLEDGE (priors):\n{kb_prompt()}\n\n"
            f"TOOLS:\n{ctx['tools']}\n\n"
            f"SURFACE (endpoints/forms/catalog/credit):\n{ctx['surface']}\n\n"
            f"WORKING MEMORY (facts, recent attempts, strategies tried):\n{ctx['notebook']}\n\n"
            f"RELEVANT PAST SKILLS: {ctx['prior_skills']}\n\n"
            f"LAST RESULT: {ctx['last_result']}\n\n"
            "Pick the SINGLE next tool call. Reuse memory facts (CSRF, prices, codes). "
            "Use `calc` for arithmetic. Use `check_objective` when you think you've won. "
            f"If stuck, change strategy. Respond ONLY JSON: {_SCHEMA}"
        )
        try:
            decision = await agent.complete_json(trim(user), schema_hint=_SCHEMA)
        except Exception as exc:  # noqa: BLE001
            logger.warning("agent brain failed: %s", exc)
            return {"tool": "give_up"}
        return decision if isinstance(decision, dict) else {"tool": "give_up"}

    return brain
