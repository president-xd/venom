"""
Reporting. Convert confirmed test cases into structured Findings and render a
Markdown report plus a machine-readable JSON artifact.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from itertools import count
from pathlib import Path

from ..core.scope import Scope
from ..core.registry import EndpointRegistry
from ..core.graph import BusinessModelGraph
from ..testing.schema import Finding, Severity, TestCase, Verdict

_fid = count(1)

_CVSS_HINT = {
    "RACE_CONDITION": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "BOLA_IDOR": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "PARAM_POLLUTION": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "MASS_ASSIGNMENT": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "ECONOMIC_ABUSE": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
}
_REMEDIATION = {
    "RACE_CONDITION": ("Add DB-level row locking / atomic compare-and-swap on the mutation.",
                       "Require idempotency keys for all financial mutations."),
    "BOLA_IDOR": ("Enforce per-object ownership checks on every read/write.",
                  "Adopt centralized object-level authorization middleware."),
    "PARAM_POLLUTION": ("Validate numeric bounds and types server-side; reject duplicates.",
                        "Use a strict schema validator at the API boundary."),
    "MASS_ASSIGNMENT": ("Whitelist writable fields; strip privileged keys server-side.",
                        "Separate input DTOs from persistence models."),
    "SEQUENCE_VIOLATION": ("Validate state preconditions before every transition.",
                           "Model the state machine explicitly and reject illegal edges."),
    "ECONOMIC_ABUSE": ("Make conversions atomic and check rate symmetry/rounding.",
                       "Add anti-abuse limits and reconciliation on economic flows."),
    "FAITH_BASED_RULE": ("Add explicit server-side enforcement for the documented rule.",
                         "Add a regression test asserting the rule is enforced."),
}


def build_findings(cases: list[TestCase]) -> list[Finding]:
    findings: list[Finding] = []
    for c in cases:
        if c.verdict != Verdict.CONFIRMED_EXPLOIT:
            continue
        vc = c.vulnerability_class.value
        short, long = _REMEDIATION.get(vc, ("Review and enforce server-side.", "Add regression coverage."))
        # Prefer the runner's rich evidence (state deltas + request log); fall back
        # to per-step excerpts for cases without a state probe.
        evidence = dict(c.evidence) if c.evidence else {}
        for s in c.steps:
            if s.actual_status is not None:
                evidence[f"step_{s.step}_status"] = s.actual_status
                if s.response_excerpt:
                    evidence[f"step_{s.step}_response"] = s.response_excerpt
        findings.append(Finding(
            finding_id=f"BL-{next(_fid):03d}",
            title=c.hypothesis[:120],
            severity=c.risk_rating,
            vulnerability_class=c.vulnerability_class,
            affected_endpoint=c.affected_endpoint,
            business_impact=c.business_impact,
            reproduction_steps=[s.to_dict() for s in c.steps],
            evidence=evidence,
            cvss_vector=_CVSS_HINT.get(vc, ""),
            remediation={"short_term": short, "long_term": long},
            references=(c.rag_refs or ([c.rag_source] if c.rag_source else [])),
            source_test_id=c.test_id,
        ))
    return findings


_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _markdown(scope: Scope, registry: EndpointRegistry, cases: list[TestCase],
              findings: list[Finding], exec_summary: str = "") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    by_sev = {s: [f for f in findings if f.severity == s] for s in _SEV_ORDER}
    confirmed = len(findings)
    total = len(cases)

    default_summary = (
        f"VENOM executed **{total}** business-logic test cases against "
        f"`{scope.target_name}` and confirmed **{confirmed}** exploitable findings. "
        "Findings below are ordered by business risk. Each represents a way the "
        "application can be made to behave against its intended business rules."
    )

    lines = [
        "# VENOM Business-Logic Pentest Report",
        f"**Engagement:** {scope.engagement_id} — {scope.target_name}  ",
        f"**Generated:** {now}  ",
        f"**Authorized by:** {scope.authorized_by or '(unspecified)'}  ",
        f"**Window:** {scope.authorization_date or '?'} → {scope.expiry_date or '?'}",
        "",
        "## 1. Executive Summary",
        exec_summary or default_summary,
        "",
        "| Severity | Confirmed |",
        "|----------|-----------|",
    ]
    for s in _SEV_ORDER:
        if by_sev[s]:
            lines.append(f"| {s.value} | {len(by_sev[s])} |")
    lines += [
        "",
        "## 2. Scope & Methodology",
        "```",
        scope.summary(),
        "```",
        f"- Endpoints in registry: **{len(registry)}** "
        f"({len(registry.shadow())} shadow, {len(registry.with_tag('financial'))} financial)",
        "- Method: business-model reconstruction → adversarial hypothesis generation "
        "→ scope-guarded execution → verdict analysis.",
        "",
        "## 3. Findings",
    ]
    if not findings:
        lines.append("_No exploitable findings confirmed in this run._")
    for f in findings:
        lines += [
            f"### {f.finding_id} — {f.title}",
            f"**Severity:** {f.severity.value}  |  **Class:** {f.vulnerability_class.value}  "
            f"|  **Endpoint:** `{f.affected_endpoint}`",
            "",
            f"**Business impact:** {f.business_impact}",
            "",
            f"**CVSS:** `{f.cvss_vector or 'n/a'}`",
            "",
            "**Reproduction:**",
        ]
        for s in f.reproduction_steps:
            lines.append(f"- Step {s['step']}: `{s['method']} {s['path']}` — {s['description']} "
                         f"(got {s.get('actual_status')})")
        lines += [
            "",
            "**Evidence:**",
            "```json",
            json.dumps(f.evidence, indent=2)[:1500],
            "```",
            f"**Remediation (short-term):** {f.remediation.get('short_term','')}  ",
            f"**Remediation (long-term):** {f.remediation.get('long_term','')}",
            f"**References:** {', '.join(f.references) or 'n/a'}",
            "",
        ]
    lines += [
        "## 4. Appendix — All Test Cases (incl. negatives)",
        "| Test | Class | Endpoint | Verdict |",
        "|------|-------|----------|---------|",
    ]
    for c in cases:
        lines.append(f"| {c.test_id} | {c.vulnerability_class.value} | "
                     f"`{c.affected_endpoint}` | {c.verdict.value} |")
    return "\n".join(lines) + "\n"


async def _exec_summary(reporter, scope, findings, total) -> str:
    """Have the Reporter agent (DeepSeek) write the executive summary, if available."""
    if reporter is None or not findings:
        return ""
    brief = [{"title": f.title, "severity": f.severity.value,
              "class": f.vulnerability_class.value, "impact": f.business_impact}
             for f in findings]
    try:
        return await reporter.complete_text(
            f"Target: {scope.target_name}. {total} tests run, {len(findings)} confirmed "
            f"business-logic findings:\n{brief}\n\nWrite a 4-6 sentence executive summary "
            "framing the business risk for a mixed exec/engineer audience. No hype."
        )
    except Exception:  # noqa: BLE001
        return ""


def _sarif(scope: Scope, findings: list[Finding]) -> dict:
    """Minimal SARIF 2.1.0 — lets CI gate on VENOM findings."""
    sev_map = {Severity.CRITICAL: "error", Severity.HIGH: "error",
               Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
    rules, results = {}, []
    for f in findings:
        rid = f.vulnerability_class.value
        rules.setdefault(rid, {"id": rid, "name": rid,
                               "shortDescription": {"text": rid.replace("_", " ").title()}})
        results.append({
            "ruleId": rid,
            "level": sev_map.get(f.severity, "warning"),
            "message": {"text": f"{f.title} — {f.business_impact}"},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": f.affected_endpoint or scope.target_name}}}],
            "properties": {"severity": f.severity.value, "cvss": f.cvss_vector,
                           "finding_id": f.finding_id},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "VENOM", "version": "0.1.0",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }


async def write_report(out_dir: str | Path, scope: Scope, registry: EndpointRegistry,
                       graph: BusinessModelGraph, cases: list[TestCase],
                       reporter=None, audit: list[dict] | None = None) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = build_findings(cases)
    exec_summary = await _exec_summary(reporter, scope, findings, len(cases))

    md_path = out_dir / "report.md"
    md_path.write_text(_markdown(scope, registry, cases, findings, exec_summary), encoding="utf-8")

    json_path = out_dir / "findings.json"
    json_path.write_text(json.dumps({
        "engagement_id": scope.engagement_id,
        "target": scope.target_name,
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_tests": len(cases),
            "confirmed": len(findings),
            "registry_size": len(registry),
        },
        "findings": [f.to_dict() for f in findings],
        "test_cases": [c.to_dict() for c in cases],
    }, indent=2), encoding="utf-8")

    graph_path = out_dir / "business_model.json"
    graph_path.write_text(json.dumps(graph.to_dict(), indent=2), encoding="utf-8")

    sarif_path = out_dir / "findings.sarif"
    sarif_path.write_text(json.dumps(_sarif(scope, findings), indent=2), encoding="utf-8")

    paths = {"report": md_path, "findings": json_path, "graph": graph_path, "sarif": sarif_path}

    if audit:
        audit_path = out_dir / "audit.jsonl"
        audit_path.write_text("\n".join(json.dumps(r) for r in audit) + "\n", encoding="utf-8")
        paths["audit"] = audit_path

    return paths
# (report artifacts: report.md, findings.json, findings.sarif, business_model.json, audit.jsonl)
