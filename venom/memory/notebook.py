"""
Working memory ("the notebook") - a structured scratchpad for one engagement.

Holds: facts (key/value), a running log of attempts (with outcome), and sub-goal
status. The agent writes discoveries (codes, prices, totals, CSRF, session state)
and reads them back across many steps. A compact `render()` feeds the planner
without blowing the token budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Notebook:
    facts: dict[str, Any] = field(default_factory=dict)
    attempts: list[dict] = field(default_factory=list)   # {strategy, action, result, progressed}
    subgoals: dict[str, bool] = field(default_factory=dict)

    # ---- facts ----
    def set(self, key: str, value: Any) -> None:
        self.facts[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.facts.get(key, default)

    # ---- attempts (for backtracking / avoiding loops) ----
    def record(self, strategy: str, action: str, result: str, progressed: bool) -> None:
        self.attempts.append({"strategy": strategy, "action": action,
                              "result": result[:160], "progressed": progressed})

    def tried(self, action: str) -> bool:
        return any(a["action"] == action for a in self.attempts)

    def strategies_tried(self) -> set[str]:
        return {a["strategy"] for a in self.attempts}

    def stalled(self, strategy: str, window: int = 4) -> bool:
        """True if the last `window` attempts of a strategy made no progress."""
        recent = [a for a in self.attempts if a["strategy"] == strategy][-window:]
        return len(recent) >= window and not any(a["progressed"] for a in recent)

    # ---- sub-goals ----
    def set_subgoal(self, name: str, done: bool = False) -> None:
        self.subgoals[name] = done

    # ---- compact view for the planner ----
    def render(self, max_attempts: int = 8) -> dict:
        return {
            "facts": {k: (v if isinstance(v, (int, float, bool)) else str(v)[:80])
                      for k, v in self.facts.items()},
            "subgoals": self.subgoals,
            "recent_attempts": self.attempts[-max_attempts:],
            "strategies_tried": sorted(self.strategies_tried()),
        }
