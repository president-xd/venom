"""
The engagement Objective — what "success" means, made checkable.

Gives the agent a goal to drive toward and a generic win-oracle (so it can tell
when it's done without a per-lab hack). Defaults recognize common winning states
(order placed, lab solved); a custom signal/url can be supplied via the scope.
"""

from __future__ import annotations

from dataclasses import dataclass

_DEFAULT_SIGNALS = ("is-solved", "congratulations", "you solved the lab",
                    "order placed", "order confirmed", "thank you for your purchase")


@dataclass
class Objective:
    description: str = "achieve the engagement objective"
    win_url: str = "/"
    win_signals: tuple[str, ...] = _DEFAULT_SIGNALS
    win_status: tuple[int, ...] = ()       # optional: a status that means success

    async def check(self, toolbox) -> bool:
        """Generic oracle: fetch the win URL and look for a winning signal."""
        await toolbox.http_get(self.win_url)
        text = (toolbox.last_text or "").lower()
        if self.win_status and toolbox.last_status in self.win_status:
            return True
        return any(s in text for s in self.win_signals)

    @classmethod
    def from_scope(cls, scope, fallback: str = "") -> "Objective":
        obj = dict(getattr(scope, "objective", {}) or {})
        return cls(
            description=obj.get("description") or fallback or "achieve the engagement objective",
            win_url=obj.get("win_url", "/"),
            win_signals=tuple(obj.get("win_signals", _DEFAULT_SIGNALS)),
            win_status=tuple(obj.get("win_status", ())),
        )
