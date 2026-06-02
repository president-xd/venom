"""
The agent loop — VENOM's brain at runtime.

    observe → DECIDE (brain) → ACT (tool) → record to notebook → CHECK objective
    → continue / backtrack to another strategy → on success: learn a skill.

The `brain(context) -> decision` is pluggable: a deterministic stub in tests, an
LLM in production. The loop, tools, memory, objective-checking and skill-learning
are all deterministic and unit-tested independently of any model — so the
*mechanism* is proven even where model quality isn't.
"""

from __future__ import annotations

import logging
from itertools import count

from ..core.scope import Scope
from ..memory import Notebook, SkillLibrary, Skill
from ..tools import Toolbox
from ..testing.schema import TestCase, TestStep, VulnClass, Severity, Verdict
from .objective import Objective

logger = logging.getLogger("venom.cognition.agent")
_counter = count(1)

_VC = {v.value: v for v in VulnClass}


class Agent:
    def __init__(self, scope: Scope, brain, *, transport=None, max_steps: int = 24,
                 skills: SkillLibrary | None = None, learn: bool = True):
        self.scope = scope
        self.brain = brain
        self.transport = transport
        self.max_steps = max_steps
        self.skills = skills
        self.learn = learn

    def _surface(self, registry) -> dict:
        eps = []
        for e in registry.by_risk()[:30]:
            item = {"method": e.method, "path": e.path, "tags": e.business_rule_tags}
            if e.form_defaults:
                item["form_defaults"] = e.form_defaults
            eps.append(item)
        return {"endpoints": eps, "catalog": registry.catalog, "store_credit": registry.store_credit}

    async def run(self, registry, objective: Objective) -> list[TestCase]:
        notebook = Notebook()
        toolbox = Toolbox(self.scope, notebook, transport=self.transport, objective=objective)
        surface = self._surface(registry)
        prior_skills = []
        if self.skills:
            prior_skills = [s.name for s in self.skills.retrieve(
                objective.description, str(surface)[:500])]

        last_result = None
        won = False
        winning_strategy = None
        try:
            for step in range(self.max_steps):
                ctx = {
                    "objective": objective.description,
                    "surface": surface,
                    "tools": toolbox.catalog(),
                    "notebook": notebook.render(),
                    "prior_skills": prior_skills,
                    "last_result": last_result.to_dict() if last_result else None,
                    "step": step,
                }
                try:
                    decision = await self.brain(ctx)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("brain error: %s", exc)
                    break
                if not decision:
                    break
                tool = decision.get("tool")
                if tool in (None, "done", "give_up"):
                    break

                strategy = decision.get("strategy", "default")
                res = await toolbox.call(tool, decision.get("args", {}))
                last_result = res
                notebook.record(strategy, f"{tool} {decision.get('args', {})}", res.summary, res.ok)

                # Check the objective after state-changing actions (or explicit checks).
                if tool.startswith("http_post") or tool == "check_objective":
                    chk = res if tool == "check_objective" else await toolbox.check_objective()
                    if chk.data.get("met"):
                        won = True
                        winning_strategy = strategy
                        break

            findings = []
            if won:
                tc = self._finding(objective, notebook, toolbox, winning_strategy)
                findings.append(tc)
                if self.learn and self.skills is not None:
                    self._learn_skill(objective, notebook, surface, winning_strategy)
            logger.info("Agent finished: %d step(s), objective %s",
                        len(notebook.attempts), "MET" if won else "not met")
            return findings
        finally:
            await toolbox.aclose()

    def _finding(self, objective, notebook, toolbox, strategy) -> TestCase:
        steps = [TestStep(step=i + 1, description=a["action"][:120], method="*", path="",
                          response_excerpt=a["result"])
                 for i, a in enumerate(notebook.attempts)]
        return TestCase(
            test_id=f"AGT-{next(_counter):03d}",
            vulnerability_class=VulnClass.FAITH_BASED_RULE,
            hypothesis=f"Autonomous agent achieved objective: {objective.description}",
            risk_rating=Severity.HIGH,
            affected_endpoint=objective.win_url,
            business_impact="Business-logic objective reached by autonomous tool-using reasoning.",
            steps=steps,
            origin="agent",
            verdict=Verdict.CONFIRMED_EXPLOIT,
            notes=[f"strategy='{strategy}', {len(notebook.attempts)} tool calls",
                   "OBJECTIVE MET"],
            evidence={"requests": toolbox.audit(), "facts": notebook.render()["facts"]},
        )

    def _learn_skill(self, objective, notebook, surface, strategy) -> None:
        chain = [{"action": a["action"]} for a in notebook.attempts if a["strategy"] == strategy]
        kws = sorted({w for e in surface.get("endpoints", []) for w in e["path"].split("/") if w})[:12]
        skill = Skill(
            name=f"{strategy}:{objective.description[:40]}",
            vuln_class=VulnClass.FAITH_BASED_RULE.value,
            goal=objective.description,
            keywords=kws,
            steps=chain,
        )
        try:
            self.skills.add(skill)
        except Exception as exc:  # noqa: BLE001
            logger.warning("skill save failed: %s", exc)
