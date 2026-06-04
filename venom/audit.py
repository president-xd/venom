"""
Enterprise audit & observability primitives.

- RunMetrics: per-run observability (run_id, timings, LLM calls, requests, tokens,
  estimated cost) so every engagement is measurable, billable, and debuggable.
- sign_records / verify_audit: HMAC-SHA256 tamper-evident signing of the request
  audit trail, so a finding's evidence chain can be proven unaltered.

The audit key comes from VENOM_AUDIT_KEY (env / secret manager). A default is used
only if unset, and that fact is recorded so unsigned-in-practice runs are obvious.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field

# Rough public per-1K-token prices (USD); override via VENOM_COST_PER_1K_*.
_COST_IN = float(os.getenv("VENOM_COST_PER_1K_IN", "0.0"))
_COST_OUT = float(os.getenv("VENOM_COST_PER_1K_OUT", "0.0"))


@dataclass
class RunMetrics:
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started: float = field(default_factory=time.time)
    llm_calls: int = 0
    requests: int = 0
    exploit_runs: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def elapsed_s(self) -> float:
        return round(time.time() - self.started, 2)

    def est_cost_usd(self) -> float:
        return round(self.input_tokens / 1000 * _COST_IN + self.output_tokens / 1000 * _COST_OUT, 4)

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "elapsed_s": self.elapsed_s(),
                "llm_calls": self.llm_calls, "requests": self.requests,
                "exploit_runs": self.exploit_runs,
                "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "est_cost_usd": self.est_cost_usd()}


def _audit_key() -> tuple[bytes, bool]:
    """Return (key, is_default). is_default flags an unconfigured (weak) signature."""
    env = os.getenv("VENOM_AUDIT_KEY")
    return (env.encode(), False) if env else (b"venom-default-unsigned", True)


def _canon(records) -> bytes:
    return json.dumps(records, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_records(records: list[dict]) -> dict:
    """Tamper-evident envelope around the request audit trail."""
    key, is_default = _audit_key()
    digest = hmac.new(key, _canon(records), hashlib.sha256).hexdigest()
    return {"records": records, "count": len(records),
            "hmac_sha256": digest, "key_configured": not is_default,
            "signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def verify_audit(signed: dict) -> bool:
    """True iff the records match the stored HMAC (detects any tampering)."""
    key, _ = _audit_key()
    expected = hmac.new(key, _canon(signed.get("records", [])), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signed.get("hmac_sha256", ""))
