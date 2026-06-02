"""
Adaptive reasoning layer — VENOM's "think before you exploit" loop.

Instead of only firing pre-coded playbooks, the Reasoner observes the target,
takes a *cheap probe*, reads the actual response, re-thinks, and only then
attempts an exploit — verifying from the response. The decision ("brain") is a
pluggable callable: an LLM in production, a deterministic stub in tests. This is
what gives VENOM a shot at vulnerabilities no one wrote a playbook for.
"""

from .reasoner import Reasoner, Action
from .llm_brain import make_llm_brain
from .agent import Agent
from .agent_brain import make_agent_brain
from .objective import Objective

__all__ = ["Reasoner", "Action", "make_llm_brain",
           "Agent", "make_agent_brain", "Objective"]
