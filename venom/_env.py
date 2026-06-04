"""Minimal .env loader (no external dependency).

Loads KEY=VALUE pairs from a .env file into os.environ if not already set, so the
CLI and scripts pick up provider keys without the operator exporting them by hand.
Existing environment variables always win (never override a real env var).
"""

from __future__ import annotations

import os
from pathlib import Path

_loaded = False


def load_dotenv(path: str | Path | None = None) -> bool:
    """Load .env once. Searches the given path, then ./.env, then the repo root."""
    global _loaded
    if _loaded:
        return False
    candidates = [Path(path)] if path else []
    candidates += [Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"]
    for env in candidates:
        if env and env.is_file():
            for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
            _loaded = True
            return True
    return False
