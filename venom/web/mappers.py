"""
Mappers - translate real engine objects into the exact JSON shapes the React UI
(``dESIGN/`` components) already expects, so the frontend is reused verbatim.

Pure functions only (no I/O) so they are trivially unit-testable.
"""

from __future__ import annotations

import re
from typing import Any

# ---- severity: engine (UPPER) -> UI (lower short codes the CSS keys on) ----
SEV_MAP = {
    "CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info",
}

# ---- vuln class -> the metadata the finding cards render (CWE/OWASP/name) ----
# Mirrors the prototype's VULN_CLASSES labels so live findings read identically.
VCLASS_META: dict[str, dict[str, str]] = {
    "BOLA_IDOR":          {"name": "Broken Object-Level Auth (BOLA / IDOR)", "cwe": "CWE-639", "owasp": "API1:2023"},
    "MASS_ASSIGNMENT":    {"name": "Mass-assignment privilege escalation",   "cwe": "CWE-915", "owasp": "API3:2023"},
    "RACE_CONDITION":     {"name": "Race condition / TOCTOU",                "cwe": "CWE-362", "owasp": "n/a"},
    "PARAM_POLLUTION":    {"name": "Client-side price & parameter tampering", "cwe": "CWE-602", "owasp": "n/a"},
    "PRIV_ESCALATION":    {"name": "Privilege escalation",                   "cwe": "CWE-269", "owasp": "API5:2023"},
    "SEQUENCE_VIOLATION": {"name": "Workflow / sequence bypass",            "cwe": "CWE-840", "owasp": "n/a"},
    "STATE_BYPASS":       {"name": "State / precondition bypass",           "cwe": "CWE-840", "owasp": "n/a"},
    "TYPE_CONFUSION":     {"name": "Type confusion",                        "cwe": "CWE-843", "owasp": "n/a"},
    "ECONOMIC_ABUSE":     {"name": "Economic abuse / arbitrage",           "cwe": "CWE-840", "owasp": "n/a"},
    "FAITH_BASED_RULE":   {"name": "Faith-based business rule (unenforced)", "cwe": "CWE-840", "owasp": "n/a"},
}

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_BALANCE_HINTS = ("balance", "credit", "amount", "total", "wallet", "fund", "points", "loyalty")


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    """'GET /api/v1/wallet/{id}' -> ('GET', '/api/v1/wallet/{id}'); '/x' -> ('GET','/x')."""
    parts = (endpoint or "").strip().split(None, 1)
    if len(parts) == 2 and parts[0].upper() in _HTTP_METHODS:
        return parts[0].upper(), parts[1]
    return "GET", endpoint or "/"


def _status_kind(status: Any) -> str:
    try:
        s = int(status)
    except (TypeError, ValueError):
        return ""
    if s in (401, 403):
        return "deny"
    if 200 <= s < 300:
        return "win"
    return ""


def _build_log(finding: dict) -> list[dict]:
    """Request log rows for the evidence panel - from reproduction steps, falling
    back to the runner's evidence['requests'] summaries."""
    rows: list[dict] = []
    for s in finding.get("reproduction_steps") or []:
        method = (s.get("method") or "GET").upper()
        path = s.get("path") or "/"
        status = s.get("actual_status") if s.get("actual_status") is not None else s.get("expected_status")
        rows.append({"m": method, "p": path, "s": status if status is not None else "-",
                     "note": s.get("description") or "", "kind": _status_kind(status)})
    if rows:
        return rows
    for r in (finding.get("evidence") or {}).get("requests", []) or []:
        m, p = _split_endpoint(r.get("summary") or "")
        rows.append({"m": m, "p": p, "s": r.get("status", "-"), "note": "", "kind": _status_kind(r.get("status"))})
    return rows


def _build_state(finding: dict) -> dict | None:
    """The REAL before/after state delta, or ``None`` when this finding was NOT
    confirmed by a measured state change. We never invent a 'baseline -> violated'
    delta: if no value actually moved, the UI shows no state-delta card."""
    ev = finding.get("evidence") or {}
    deltas = ev.get("deltas") or {}
    before, after = ev.get("state_before") or {}, ev.get("state_after") or {}
    key = None
    for k in deltas:
        if abs(deltas.get(k) or 0) > 1e-9 and any(h in k.lower() for h in _BALANCE_HINTS):
            key = k
            break
    if key is None:
        nonzero = [k for k in deltas if abs(deltas.get(k) or 0) > 1e-9]
        key = max(nonzero, key=lambda k: abs(deltas.get(k) or 0)) if nonzero else None
    if key is None:
        return None
    d = deltas.get(key) or 0
    sign = "+" if d >= 0 else ""
    return {"label": key, "before": _fmt(before.get(key, "-")),
            "after": _fmt(after.get(key, "-")), "note": f"{sign}{_fmt(d)}"}


def _fmt(v: Any) -> str:
    if isinstance(v, float):
        return f"{v:g}"
    return str(v)


def _oracle_rows(confirmation: str, state: dict | None) -> list[dict]:
    """Oracle-card rows that describe the ACTUAL confirmation method - not a canned
    differential story. Each row is literally true for the method used."""
    if confirmation == "differential oracle":
        return [
            {"ok": True, "t": "Baseline: the win action was DENIED to the un-escalated user"},
            {"ok": True, "t": "Post-exploit: the SAME action SUCCEEDED after the exploit ran"},
            {"ok": True, "t": "Differential confirmed - the state transition proves the violation"},
        ]
    if confirmation == "state-delta differential":
        what = f"{state['label']} ({state['note']})" if state else "a protected value"
        return [
            {"ok": True, "t": f"A protected value changed measurably: {what}"},
            {"ok": True, "t": "The change is impossible under the intended business rule"},
        ]
    if confirmation == "cross-identity differential":
        return [
            {"ok": True, "t": "Provisioned as one identity, accessed as another (cross-tenant)"},
            {"ok": True, "t": "The object was reachable across the ownership boundary"},
        ]
    if confirmation == "response-content match":
        return [
            {"ok": True, "t": "The forbidden action returned its success / privileged content"},
            {"ok": False, "t": "No state probe on this endpoint - confirmation is response-content based"},
        ]
    return [
        {"ok": True, "t": "The forbidden request was accepted (HTTP success)"},
        {"ok": False, "t": "Status-level signal only - corroborate before treating as proven"},
    ]


def finding_to_ui(finding: dict) -> dict:
    """A real ``Finding.to_dict()`` -> the object the React FindingDetail reads.
    Everything here is derived from the finding's REAL evidence: the confirmation
    method, the (optional) measured state delta, and the exploit code ONLY when the
    agent actually authored one. Nothing is fabricated."""
    vc = finding.get("vulnerability_class", "")
    meta = VCLASS_META.get(vc, {"name": vc.replace("_", " ").title() or "Business-logic flaw",
                                 "cwe": "CWE-840", "owasp": "-"})
    method, path = _split_endpoint(finding.get("affected_endpoint", ""))
    rem = finding.get("remediation") or {}
    remediation = [r for r in (rem.get("short_term"), rem.get("long_term")) if r]
    ev = finding.get("evidence") or {}
    code = ev.get("exploit_code") or ""                 # ONLY real, agent-authored code
    origin = finding.get("origin") or "playbook"
    confirmation = finding.get("confirmation") or "status response"
    state = _build_state(finding)
    impact = finding.get("business_impact") or finding.get("title", "")
    description = finding.get("description") or finding.get("title", "") or impact
    return {
        "id": finding.get("finding_id", "BL-000"),
        "title": finding.get("title", "Business-logic finding"),
        "description": description,         # full, untruncated technical explanation
        "vclass": meta["name"],
        "severity": SEV_MAP.get(finding.get("severity", "MEDIUM"), "med"),
        "cwe": meta["cwe"],
        "owasp": meta["owasp"],
        "method": method,
        "path": path,
        "confirmed": True,
        "oracle": confirmation,             # the REAL method (not always "differential")
        "origin": origin,                   # agent | oneshot | flow | playbook
        "authored": bool(code),             # was exploit code actually written?
        "summary": impact,
        "impact": impact,
        "log": _build_log(finding),
        "state": state,                     # None when no value measurably changed
        "oracleRows": _oracle_rows(confirmation, state),
        "code": code,                       # "" when no code was authored (deterministic path)
        "references": finding.get("references") or [],
        "remediation": remediation or ["Enforce the rule server-side.", "Add regression coverage."],
        "cvss": finding.get("cvss_vector", ""),
    }


def findings_payload(findings_json: dict) -> list[dict]:
    return [finding_to_ui(f) for f in (findings_json.get("findings") or [])]


# ---- knowledge base: business_logic.py KB -> the UI vuln-class cards ----
# CWE/OWASP hints per KB id (the KB itself carries refs, not CWE numbers).
_KB_HINTS: dict[str, str] = {
    "client-side-trust":      "CWE-602",
    "unconventional-input":   "CWE-20",
    "trust-decay":            "CWE-290",
    "mandatory-input-removed": "CWE-840",
    "sequence-bypass":        "CWE-840 · WSTG-BUSL-06",
    "domain-specific":        "CWE-840",
    "infinite-money":         "CWE-840 · WSTG-BUSL-02",
    "idor-bola":              "CWE-639 · OWASP API1",
    "mass-assignment":        "CWE-915 · OWASP API3",
    "race-condition":         "CWE-362",
    "trusted-identity":       "CWE-290",
    "integer-overflow":       "CWE-190",
}


def kb_to_ui(kb: list[dict]) -> list[dict]:
    """KB priors -> {id, name, desc, cwe} cards for the wizard + knowledge base."""
    out = []
    for entry in kb:
        signals = entry.get("signals") or []
        desc = signals[0] if signals else entry.get("exploit", "")
        cwe = _KB_HINTS.get(entry.get("id", ""), "WSTG-BUSL")
        out.append({
            "id": entry.get("id", ""),
            "name": entry.get("name", ""),
            "desc": desc,
            "cwe": cwe,
            "probe": entry.get("probe", ""),
            "exploit": entry.get("exploit", ""),
            "refs": entry.get("refs", []),
        })
    return out


# ---- live trace: a log line -> a console line type (for coloring in the UI) ----
def classify_log(msg: str) -> str:
    m = (msg or "").strip()
    if re.match(r"^\[[a-z_]+\]", m):
        return "stage"
    if "‼" in m or "confirmed" in m.lower():
        return "hit"
    if re.search(r"\b(GET|POST|PUT|PATCH|DELETE)\b\s+\S*/", m):
        return "req"
    if m.startswith("✓"):
        return "ok"
    if m.startswith("lens=") or m.startswith("entit") or m.startswith("transition") or "->" in m:
        return "think"
    return "info"


# ---- pipeline stage inference from engagement log markers ----
# 7 stages mirror the design: scope, discover, model, hypothesize, exploit, confirm, report.
_STAGE_MARKERS: list[tuple[str, int]] = [
    ("loaded scope", 0), ("scope guard", 0),
    ("discovery", 1), ("crawl", 1), ("registered", 1), ("endpoints", 1),
    ("business model", 2), ("reconstruct", 2), ("heuristic", 2), ("graph", 2),
    ("generated", 3), ("test case", 3), ("hypoth", 3),
    ("executing", 4), ("exploit", 4), ("running", 4),
    ("confirmed", 5), ("finding", 5), ("verdict", 5),
    ("report written", 6), ("report:", 6),
]


def stage_order(msg: str, current: int = 0) -> int:
    """Highest pipeline stage implied by this log line (monotonic, never decreases)."""
    m = (msg or "").lower()
    order = current
    for marker, idx in _STAGE_MARKERS:
        if marker in m and idx > order:
            order = idx
    return order
