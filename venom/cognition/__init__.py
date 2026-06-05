"""
Adaptive reasoning layer — VENOM's autonomous "think before you exploit" loop.

Instead of only firing pre-coded playbooks, the agent observes the target, takes
cheap probes, reads the actual responses, re-thinks, and only then attempts an
exploit — verifying from a model-independent oracle. The decision ("brain") is a
pluggable callable: an LLM in production, a deterministic stub in tests. Two entry
points share the same toolbox/oracle/grounding:
  - `oneshot_hunt`: recon -> one (capped) synthesis call -> self-verified exploit,
  - `Agent`: step-by-step loop for multi-step exploits, with memory + backtracking.
"""

from .agent import Agent
from .agent_brain import make_agent_brain
from .objective import Objective
from .evaluate import success_rate, RunStats
from .oneshot import oneshot_hunt, make_oneshot_synthesizer, build_brief
from .campaign import run_campaign, derive_objectives, CampaignResult

__all__ = ["Agent", "make_agent_brain", "Objective", "success_rate", "RunStats",
           "oneshot_hunt", "make_oneshot_synthesizer", "build_brief",
           "run_campaign", "derive_objectives", "CampaignResult"]
