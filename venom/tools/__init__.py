"""
Composable, scope-guarded tools the reasoning agent invokes to act on a target.

These are the primitives that used to be welded inside the deterministic flows
(HTTP, scrape, arithmetic, email-read, state-diff). Exposing them as a Toolbox
lets the agent *compose* an exploit per its plan, instead of a human pre-coding it.
"""

from .base import Toolbox, ToolResult

__all__ = ["Toolbox", "ToolResult"]
