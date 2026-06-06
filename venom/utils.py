"""Small shared helpers: JSONPath-ish extraction and sandboxed expression eval."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("venom.utils")

_TOKEN = re.compile(r"[a-zA-Z0-9_]+|\[\d+\]")


def jsonpath(obj: Any, expr: str) -> Any:
    """Resolve a minimal JSONPath like `$.a.b[0].c`. Returns None if not found."""
    if not expr or not expr.startswith("$"):
        return None
    cur = obj
    for token in _TOKEN.findall(expr[1:].lstrip(".")):
        try:
            if token.startswith("["):
                cur = cur[int(token[1:-1])]
            else:
                cur = cur[token]
        except (KeyError, IndexError, TypeError):
            return None
    return cur


# A deliberately tiny, safe builtin set for success-condition expressions.
_SAFE_BUILTINS = {
    "len": len, "abs": abs, "min": min, "max": max, "sum": sum,
    "any": any, "all": all, "int": int, "float": float, "str": str,
    "round": round, "sorted": sorted, "bool": bool,
}


def safe_eval(condition: str, namespace: dict) -> bool:
    """Evaluate a boolean success condition with no access to real builtins.

    The namespace is merged into *globals* (not passed as locals) so that
    generator expressions / comprehensions inside the condition - e.g.
    `any(w in text for w in [...])` - can resolve free variables like `text`.
    (In eval, a comprehension's own scope looks free names up in globals.)"""
    scope = {"__builtins__": _SAFE_BUILTINS, **namespace}
    try:
        return bool(eval(condition, scope))  # noqa: S307
    except Exception as exc:  # noqa: BLE001
        logger.debug("success_condition eval error (%r): %s", condition, exc)
        return False


_NUM_IN_TEXT = re.compile(r"-?\d[\d,]*(?:\.\d+)?")


def coerce_number(value: Any) -> float | None:
    """Best-effort numeric coercion for state-delta tracking. Handles currency
    and HTML text like '£100.00', '$5', 'Total: 1,234.50'."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        m = _NUM_IN_TEXT.search(value)
        if not m:
            return None
        try:
            return float(m.group(0).replace(",", ""))
        except ValueError:
            return None
    return None


def regex_extract(text: str, pattern: str, group: int = 1) -> str | None:
    """First regex match group from HTML/text (used for web-mode extraction)."""
    try:
        m = re.search(pattern, text or "", re.IGNORECASE | re.DOTALL)
    except re.error:
        return None
    if not m:
        return None
    try:
        return m.group(group)
    except IndexError:
        return m.group(0)


# --- PII redaction (never let real user data land in artifacts/logs) ---------
_PII_PATTERNS = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<redacted-email>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted-pan>"),          # card numbers
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted-ssn>"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "<redacted-jwt>"),
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9]{16,}\b"), "<redacted-key>"),
    (re.compile(r"(?i)(authorization|cookie|set-cookie|token|password)\s*[:=]\s*\S+"),
     r"\1=<redacted>"),
]


def redact(text: str | None, *, allow: bool = False) -> str | None:
    """Redact obvious PII/secrets from a string unless explicitly allowed."""
    if text is None or allow:
        return text
    out = text
    for pat, repl in _PII_PATTERNS:
        out = pat.sub(repl, out)
    return out


# --- Provider/API secret redaction (ALWAYS on, even when PII capture is allowed) ---
_SECRET_PATTERNS = [
    (re.compile(r"\b(?:nvapi|sk-or-v1|sk-ant|sk|pk|rk)-[A-Za-z0-9_\-]{12,}"), "<redacted-key>"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer <redacted>"),
    (re.compile(r"(?i)(api[_-]?key|authorization|x-api-key)\s*[:=]\s*\S+"), r"\1=<redacted>"),
]


def redact_secrets(text):
    """Strip provider API keys / bearer tokens from any string. Never disabled -
    a secret must not reach logs or artifacts regardless of PII settings."""
    if not text:
        return text
    out = str(text)
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


class SecretLogFilter(logging.Filter):
    """logging.Filter that redacts API keys/tokens from every emitted record."""

    def filter(self, record):  # noqa: A003
        try:
            msg = record.getMessage()
            red = redact_secrets(msg)
            if red != msg:
                record.msg, record.args = red, ()
        except Exception:  # noqa: BLE001 - logging must never raise
            pass
        return True
