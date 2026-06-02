"""
Skill library — long-term memory of confirmed exploit chains.

On a confirmed solve, the agent persists the winning tool-call sequence as a
parameterized, retrievable Skill. Future engagements retrieve relevant skills (by
goal + observed surface keywords) and feed them to the planner as priors — so
VENOM gets faster and more autonomous over time. This is the bridge from
hand-coded flows to self-authored ones.

Storage: JSON under <data_dir>/skills/skills.json (override for tests).
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger("venom.memory.skills")

_WORD = re.compile(r"[a-z0-9]+")


def _kw(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


@dataclass
class Skill:
    name: str
    vuln_class: str
    goal: str                      # the objective this skill achieves
    keywords: list[str]            # surface signals that suggest it applies
    steps: list[dict]              # ordered tool calls: {tool, args, note}
    created: float = field(default_factory=time.time)
    uses: int = 0

    def score(self, goal: str, surface: str) -> float:
        q = _kw(goal) | _kw(surface)
        s = set(self.keywords) | _kw(self.goal)
        if not q or not s:
            return 0.0
        return len(q & s) / len(q | s)


class SkillLibrary:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else self._default_path()
        self.skills: list[Skill] = []
        self._load()

    @staticmethod
    def _default_path() -> Path:
        try:
            from ..config import SETTINGS
            return SETTINGS.data_dir / "skills" / "skills.json"
        except Exception:  # noqa: BLE001
            return Path("./venom_data/skills/skills.json")

    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.skills = [Skill(**s) for s in data]
            except Exception as exc:  # noqa: BLE001
                logger.warning("skill library load failed: %s", exc)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([asdict(s) for s in self.skills], indent=2), encoding="utf-8")

    def add(self, skill: Skill) -> None:
        # Replace a same-name skill rather than duplicating.
        self.skills = [s for s in self.skills if s.name != skill.name]
        self.skills.append(skill)
        self.save()
        logger.info("learned skill '%s' (%s)", skill.name, skill.vuln_class)

    def retrieve(self, goal: str, surface: str, k: int = 3) -> list[Skill]:
        scored = sorted(self.skills, key=lambda s: s.score(goal, surface), reverse=True)
        return [s for s in scored if s.score(goal, surface) > 0][:k]
