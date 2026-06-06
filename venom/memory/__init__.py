"""
VENOM memory subsystem.

- Notebook: per-engagement working memory (scratchpad) the agent reads/writes
  during a run - facts, sub-goals, what's been tried. Enables multi-step reasoning.
- SkillLibrary: long-term store of confirmed exploit chains, retrievable as priors
  for future engagements (this is how VENOM learns and stops depending on humans).
"""

from .notebook import Notebook
from .skills import SkillLibrary, Skill

__all__ = ["Notebook", "SkillLibrary", "Skill"]
