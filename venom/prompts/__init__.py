"""Bundled prompt assets."""

from pathlib import Path

_DIR = Path(__file__).parent


def agent_system_prompt() -> str:
    """The VENOM master system prompt used to drive LLM reasoning."""
    return (_DIR / "agent_system_prompt.md").read_text(encoding="utf-8")


__all__ = ["agent_system_prompt"]
