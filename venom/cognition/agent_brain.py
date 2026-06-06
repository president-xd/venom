"""
LLM brain for the agent loop. Given the compact context (objective, surface,
tool catalog, notebook/memory, retrieved skills, last result), it picks the SINGLE
next tool call. Explicitly told to probe and reason before exploiting, to reuse
facts from memory, and to switch strategy when one stalls.

Returns a decision dict: {tool, args, strategy, rationale}.
All input is budget-trimmed by the agent layer (free-tier safe).
"""

from __future__ import annotations

import asyncio
import logging

from ..knowledge import kb_prompt
from ..llm.budget import trim

logger = logging.getLogger("venom.cognition.agent_brain")

_SYSTEM = (
    "You are VENOM's autonomous reasoning core - a senior application-security "
    "engineer with a toolbox, working memory, and a goal. THINK before you act: "
    "probe cheaply, read results, update memory, and only then exploit. If a "
    "strategy stalls (memory shows no progress), SWITCH to a different one. You are "
    "not limited to known patterns; reason from what you observe.\n"
    "OUTPUT RULES (critical): respond with ONE compact JSON object and NOTHING else "
    "- no prose, no markdown. `args` must contain ONLY the request fields: `path` and "
    "`fields` (a flat map of form parameters). NEVER put headers, cookies, session, "
    "content-type, or auth in `args` - the tool layer handles sessions and headers "
    "automatically. Keep the object short."
)

_SCHEMA = ('{"tool":"http_get|http_post|find|forms|calc|check_objective|...",'
           '"args":{"path":"/...","fields":{}},'
           '"strategy":"short-name","rationale":"one short clause"}')


def make_agent_brain(agent):
    """Return an async `brain(context) -> decision` backed by an LLM Agent."""

    async def brain(ctx: dict) -> dict:
        user = (
            f"OBJECTIVE: {ctx['objective']}\n\n"
            f"BUSINESS-LOGIC KNOWLEDGE (priors, ranked to this target):\n"
            f"{kb_prompt(surface=str(ctx.get('surface', '')))}\n\n"
            f"TOOLS:\n{ctx['tools']}\n\n"
            f"SURFACE (endpoints/forms/catalog/credit):\n{ctx['surface']}\n\n"
            f"WORKING MEMORY (facts, recent attempts, strategies tried):\n{ctx['notebook']}\n\n"
            f"RELEVANT PAST SKILLS: {ctx['prior_skills']}\n\n"
            f"LAST RESULT: {ctx['last_result']}\n\n"
            "Pick the SINGLE next tool call. CRITICAL: if the LAST RESULT or memory exposed a "
            "secret you can use (token, id, code, csrf, price, api key), your NEXT action must USE "
            "it to advance the objective (e.g. include a stolen token in the follow-up request that "
            "the hints describe). Do NOT call give_up while the objective is unmet and you still have "
            "an unused lead or an untried strategy - push the exploit to completion and verify. "
            "Use `run_exploit_code` to write a Python loop/computation when one request can't do it. "
            "Use `check_objective` when you think you've won. "
            f"Respond ONLY JSON: {_SCHEMA}"
        )
        # Resilience: a transient LLM/provider blip must NOT abort the whole hunt.
        # Retry a few times with backoff before conceding.
        last_exc = None
        for attempt in range(4):
            try:
                # Low temperature -> stable, compact decisions (less truncation/drift).
                decision = await agent.complete_json(trim(user), schema_hint=_SCHEMA, temperature=0.1)
                if isinstance(decision, dict) and decision.get("tool"):
                    return decision
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                logger.warning("agent brain attempt %d failed: %s", attempt + 1, exc)
                await asyncio.sleep(1.5 * (attempt + 1))
        logger.warning("agent brain giving up after retries: %s", last_exc)
        return {"tool": "give_up"}

    return brain
