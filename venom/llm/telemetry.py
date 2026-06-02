"""
LLM robustness layer: response cache, token/cost budget, and call tracing.
All optional and attached to the LLMRouter; when unset the router
behaves exactly as before (zero overhead, no behavior change).

- ResponseCache: content-hash cache of (task, provider, model, system, messages)
  so identical calls (common in agent loops) don't re-hit the provider.
- Budget: per-engagement token ceiling with a hard stop (raises BudgetExceeded).
- Tracer: structured per-call record (provider, model, tokens, latency, cached)
  exportable to agent_trace.jsonl for reproducibility/observability.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path


class BudgetExceeded(RuntimeError):
    """Raised when an engagement's token budget is exhausted."""


@dataclass
class Budget:
    max_tokens: int = 300_000
    used_input: int = 0
    used_output: int = 0

    @property
    def total(self) -> int:
        return self.used_input + self.used_output

    def check(self) -> None:
        if self.total >= self.max_tokens:
            raise BudgetExceeded(
                f"token budget exhausted ({self.total}/{self.max_tokens})")

    def add(self, input_tokens: int, output_tokens: int) -> None:
        self.used_input += int(input_tokens or 0)
        self.used_output += int(output_tokens or 0)

    def summary(self) -> dict:
        return {"used_input": self.used_input, "used_output": self.used_output,
                "total": self.total, "max": self.max_tokens}


class ResponseCache:
    def __init__(self) -> None:
        self._store: dict[str, dict] = {}
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(task, model, system, messages) -> str:
        blob = json.dumps([str(task), model, system, messages], sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def get(self, key: str) -> dict | None:
        hit = self._store.get(key)
        if hit is not None:
            self.hits += 1
        else:
            self.misses += 1
        return hit

    def put(self, key: str, result: dict) -> None:
        self._store[key] = result


@dataclass
class Tracer:
    calls: list[dict] = field(default_factory=list)

    def record(self, **kw) -> None:
        self.calls.append({"ts": time.time(), **kw})

    def dump(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(json.dumps(c) for c in self.calls) + "\n", encoding="utf-8")

    def summary(self) -> dict:
        cached = sum(1 for c in self.calls if c.get("cached"))
        return {"llm_calls": len(self.calls), "cached": cached,
                "providers": sorted({c.get("provider") for c in self.calls if c.get("provider")})}
