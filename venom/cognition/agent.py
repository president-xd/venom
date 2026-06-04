"""
The agent loop — VENOM's brain at runtime.

    observe → DECIDE (brain) → ACT (tool) → record to notebook → CHECK objective
    → continue / backtrack to another strategy → on success: learn a skill.

The `brain(context) -> decision` is pluggable: a deterministic stub in tests, an
LLM in production. The loop, tools, memory, objective-checking and skill-learning
are all deterministic and unit-tested independently of any model — so the
*mechanism* is proven even where model quality isn't.

Production autonomy features layered on the loop:
  - skill REPLAY: a high-scoring learned skill is replayed first (with dynamic
    re-binding of per-session tokens) — solving a known class with zero LLM calls.
  - strategy BACKTRACKING: a stalled strategy is retired and fed back to the brain
    as "do not repeat"; identical failed actions are not re-executed.
  - COST/TIME caps: a wall-clock deadline and a step cap bound every hunt.
"""

from __future__ import annotations

import logging
import time
from itertools import count

from ..core.scope import Scope
from ..llm.budget import compact_html
from ..memory import Notebook, SkillLibrary, Skill
from ..tools import Toolbox
from ..testing.schema import TestCase, TestStep, VulnClass, Severity, Verdict
from .objective import Objective

logger = logging.getLogger("venom.cognition.agent")
_counter = count(1)

_VC = {v.value: v for v in VulnClass}


class Agent:
    def __init__(self, scope: Scope, brain, *, transport=None, max_steps: int = 24,
                 skills: SkillLibrary | None = None, learn: bool = True,
                 deadline_seconds: float | None = None, skill_replay_threshold: float = 0.5,
                 stall_window: int = 4):
        self.scope = scope
        self.brain = brain
        self.transport = transport
        self.max_steps = max_steps
        self.skills = skills
        self.learn = learn
        self.deadline_seconds = deadline_seconds
        self.skill_replay_threshold = skill_replay_threshold
        self.stall_window = stall_window
        self.last_run_stats: dict = {}

    def _surface(self, registry) -> dict:
        eps = []
        for e in registry.by_risk()[:30]:
            item = {"method": e.method, "path": e.path, "tags": e.business_rule_tags}
            if e.form_defaults:
                item["form_defaults"] = e.form_defaults
            eps.append(item)
        return {"endpoints": eps, "catalog": registry.catalog, "store_credit": registry.store_credit}

    # ------------------------------------------------------------- skill replay
    @staticmethod
    def _rebind(args: dict, toolbox: Toolbox) -> dict:
        """Re-bind per-session tokens (csrf) in a replayed step from the live page,
        so a learned skill works across sessions where the token rotates."""
        args = dict(args or {})
        fields = args.get("fields")
        if isinstance(fields, dict) and "csrf" in fields:
            forms = compact_html(toolbox.last_text or "").get("forms") or []
            for f in forms:
                fresh = {x["name"]: x.get("value") for x in f.get("fields", [])}
                if fresh.get("csrf"):
                    fields = {**fields, "csrf": fresh["csrf"]}
                    break
            args["fields"] = fields
        return args

    async def _replay(self, skill: Skill, toolbox: Toolbox, objective: Objective) -> bool:
        """Replay a learned skill's structured steps (with token re-binding).
        Returns True if it meets the objective — a fast, model-free solve."""
        steps = [s for s in (skill.steps or []) if s.get("tool")]
        if not steps:
            return False
        logger.info("replaying skill '%s' (%d step(s))", skill.name, len(steps))
        for st in steps:
            tool, args = st["tool"], self._rebind(st.get("args", {}), toolbox)
            res = await toolbox.call(tool, args)
            toolbox.notebook.record(f"replay:{skill.name}", f"{tool} {args}", res.summary, res.ok)
            if tool.startswith("http_post") or tool == "check_objective":
                if (await toolbox.check_objective()).data.get("met"):
                    skill.uses += 1
                    if self.skills is not None:
                        self.skills.save()
                    return True
        return bool((await toolbox.check_objective()).data.get("met"))

    async def run(self, registry, objective: Objective) -> list[TestCase]:
        start = time.monotonic()
        notebook = Notebook()
        toolbox = Toolbox(self.scope, notebook, transport=self.transport, objective=objective)
        # Action grounding for every tool the agent uses. Always include the root and
        # the objective's verification paths so the win-oracle's own checks aren't blocked.
        toolbox.known_paths = {(e.path or "/").rstrip("/") or "/" for e in registry}
        toolbox.known_paths |= {"/", (objective.win_url or "/").rstrip("/") or "/"}
        if objective.win_action and objective.win_action.get("path"):
            toolbox.known_paths.add(objective.win_action["path"].rstrip("/") or "/")
        surface = self._surface(registry)
        # Recon depth: accessible/denied maps as the current user (senior-tester view).
        try:
            from ..ingest.recon import enrich_recon
            enrichment = await enrich_recon(self.scope, registry, transport=self.transport)
            if enrichment:
                surface["accessible_to_you"] = enrichment.get("accessible_to_you", [])
                surface["denied_to_you"] = enrichment.get("denied_to_you", [])
                surface["page_snippets"] = [p for p in enrichment.get("probed", []) if p.get("snippet")][:10]
        except Exception as exc:  # noqa: BLE001
            logger.warning("recon enrichment failed: %s", exc)
        # Differential oracle: if the win action already works un-escalated, it's not a flaw.
        try:
            baseline_ok = await objective.baseline(toolbox)
        except Exception:  # noqa: BLE001
            baseline_ok = False
        prior_skills: list[Skill] = []
        if self.skills:
            prior_skills = self.skills.retrieve(objective.description, str(surface)[:500])

        steps_used = 0
        replayed = False
        try:
            # 0) Skill replay fast-path: if a strong skill matches, try it first.
            #    Skipped if the objective is already satisfied at baseline (not a flaw).
            best = prior_skills[0] if prior_skills else None
            if best and not baseline_ok and \
                    best.score(objective.description, str(surface)[:500]) >= self.skill_replay_threshold:
                if await self._replay(best, toolbox, objective):
                    self.last_run_stats = {"won": True, "steps": len(notebook.attempts),
                                           "via": "replay", "skill": best.name}
                    return [self._finding(objective, notebook, toolbox, f"replay:{best.name}")]
                replayed = True  # replay attempted but didn't win → fall through to reasoning

            last_result = None
            won = False
            winning_strategy = None
            decisions_by_strategy: dict[str, list[dict]] = {}

            for step in range(self.max_steps):
                steps_used = step + 1
                # Cost/time cap: never let a hunt run unbounded.
                if self.deadline_seconds is not None and (time.monotonic() - start) > self.deadline_seconds:
                    logger.info("agent deadline (%.1fs) reached — stopping", self.deadline_seconds)
                    break

                dead = sorted(s for s in notebook.strategies_tried()
                              if notebook.stalled(s, self.stall_window))
                ctx = {
                    "objective": objective.description,
                    "surface": surface,
                    "tools": toolbox.catalog(),
                    "notebook": notebook.render(),
                    "prior_skills": [s.name for s in prior_skills],
                    "stalled_strategies": dead,   # backtracking signal to the planner
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
                args = decision.get("args", {})
                action = f"{tool} {args}"

                # Self-correction: don't re-run an identical action that already failed,
                # and don't keep feeding a strategy the loop has already retired.
                prior = [a for a in notebook.attempts if a["action"] == action]
                if prior and not any(a["progressed"] for a in prior):
                    notebook.record(strategy, action, "skipped: identical action already failed", False)
                    last_result = None
                    continue

                res = await toolbox.call(tool, args)
                last_result = res
                # "Progress" = a genuinely useful step. HTTP tools always return ok=True
                # (even on 404), so judge by status; a 4xx/5xx is NOT progress. This is
                # what lets stalled-strategy detection and backtracking actually fire.
                status = (res.data or {}).get("status")
                if tool.startswith("http"):
                    progressed = bool(status and 200 <= int(status) < 400)
                else:
                    progressed = res.ok
                notebook.record(strategy, action, res.summary, progressed)
                decisions_by_strategy.setdefault(strategy, []).append({"tool": tool, "args": args})

                state_changing = (tool.startswith("http_post") or tool in (
                    "post", "run_exploit_code", "exploit", "run_code", "write_exploit", "code",
                    "check_objective"))
                if state_changing:
                    chk = res if tool == "check_objective" else await toolbox.check_objective()
                    # A real win = the objective is met AND it was NOT already met at baseline.
                    if chk.data.get("met") and not baseline_ok:
                        won = True
                        winning_strategy = strategy
                        break

            findings = []
            if won:
                win_steps = decisions_by_strategy.get(winning_strategy, [])
                tc = self._finding(objective, notebook, toolbox, winning_strategy)
                findings.append(tc)
                if self.learn and self.skills is not None:
                    self._learn_skill(objective, notebook, surface, winning_strategy, win_steps)
            self.last_run_stats = {"won": won, "steps": steps_used,
                                   "via": "reason" if not replayed else "reason-after-replay"}
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

    def _learn_skill(self, objective, notebook, surface, strategy, win_steps) -> None:
        # Store the STRUCTURED winning chain so it can be replayed (and re-bound) later.
        steps = win_steps or [{"tool": "note", "args": {}} for _ in notebook.attempts]
        kws = sorted({w for e in surface.get("endpoints", []) for w in e["path"].split("/") if w})[:12]
        skill = Skill(
            name=f"{strategy}:{objective.description[:40]}",
            vuln_class=VulnClass.FAITH_BASED_RULE.value,
            goal=objective.description,
            keywords=kws,
            steps=steps,
        )
        try:
            self.skills.add(skill)
        except Exception as exc:  # noqa: BLE001
            logger.warning("skill save failed: %s", exc)
