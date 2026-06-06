"""
Reliability measurement for the autonomous agent.

LLM-driven hunts are non-deterministic, so "it solved it once" is not a capability
claim. `success_rate` runs the same objective N times with fresh agent state and
reports solved/total, success rate, and average steps - the number an operator
needs to trust (or reject) an autonomous run, and the metric to regression-track.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("venom.cognition.evaluate")


@dataclass
class RunStats:
    runs: int
    wins: int
    avg_steps: float
    per_run: list[dict] = field(default_factory=list)

    @property
    def rate(self) -> float:
        return self.wins / self.runs if self.runs else 0.0

    def to_dict(self) -> dict:
        return {"runs": self.runs, "wins": self.wins, "rate": round(self.rate, 3),
                "avg_steps": round(self.avg_steps, 2), "per_run": self.per_run}


async def success_rate(make_agent, make_registry, objective, runs: int = 5) -> RunStats:
    """Run `make_agent()` against `make_registry()` for the objective `runs` times.

    `make_agent` and `make_registry` are zero-arg factories so each trial starts
    from clean state (fresh notebook, fresh target). Returns aggregate RunStats.
    """
    wins, steps, per = 0, [], []
    for i in range(runs):
        agent = make_agent()
        findings = await agent.run(make_registry(), objective)
        won = bool(findings)
        wins += int(won)
        n = agent.last_run_stats.get("steps", len(getattr(agent, "_", []) or []))
        via = agent.last_run_stats.get("via", "reason")
        steps.append(n)
        per.append({"run": i + 1, "won": won, "steps": n, "via": via})
        logger.info("eval run %d/%d: won=%s steps=%s via=%s", i + 1, runs, won, n, via)
    avg = sum(steps) / len(steps) if steps else 0.0
    return RunStats(runs=runs, wins=wins, avg_steps=avg, per_run=per)
