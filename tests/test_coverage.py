"""
Per-lab coverage hunt (web demo) — must hunt EVERY lab in isolation and aggregate
all that are proven, so the demo surfaces many vulnerabilities, not one.
"""

from types import SimpleNamespace

import pytest

from venom.web import coverage
from venom.web.coverage import vulnlab_coverage, _vuln_class
from venom.testing.schema import Severity, TestCase, VulnClass, Verdict


def _lab(name):
    return SimpleNamespace(name=name, vuln_id="x", seeds=["/"], objective="o",
                           win_action={"method": "POST", "path": "/" + name}, win_url="/",
                           success_text="", title=name)


def _finding(name):
    return TestCase(test_id="ONE-001", vulnerability_class=VulnClass.FAITH_BASED_RULE,
                    hypothesis="h", risk_rating=Severity.HIGH, affected_endpoint="/" + name,
                    verdict=Verdict.CONFIRMED_EXPLOIT)


async def test_coverage_hunts_every_lab_and_aggregates(monkeypatch):
    labs = [_lab("price"), _lab("idor"), _lab("coupon"), _lab("bola")]
    winners = {"idor", "bola"}

    async def fake_hunt(lab, scope_dict, per_lab_calls, sem):
        async with sem:
            return lab, ([_finding(lab.name)] if lab.name in winners else [])
    monkeypatch.setattr(coverage, "_hunt_lab", fake_hunt)

    seen = []
    cases = await vulnlab_coverage({}, labs=labs, concurrency=2,
                                   on_lab=lambda *a: seen.append(a))
    assert {c.affected_endpoint for c in cases} == {"/idor", "/bola"}     # both winners aggregated
    assert len(seen) == 4                                                  # every lab attempted
    assert len(cases) == 2


async def test_coverage_continues_when_a_lab_returns_nothing(monkeypatch):
    labs = [_lab("a"), _lab("b"), _lab("c")]

    async def fake_hunt(lab, scope_dict, per_lab_calls, sem):
        async with sem:
            return lab, ([_finding(lab.name)] if lab.name == "b" else [])
    monkeypatch.setattr(coverage, "_hunt_lab", fake_hunt)

    cases = await vulnlab_coverage({}, labs=labs, concurrency=3)
    assert len(cases) == 1 and cases[0].affected_endpoint == "/b"


def test_vuln_class_mapping():
    assert _vuln_class("broken-object-level-auth") == VulnClass.BOLA_IDOR
    assert _vuln_class("mass-assignment") == VulnClass.MASS_ASSIGNMENT
    assert _vuln_class("trusted-identity-param") == VulnClass.PRIV_ESCALATION
    assert _vuln_class("totally-unknown") == VulnClass.FAITH_BASED_RULE


def test_merge_cases_dedups_confirmed():
    from venom.web.runs import _merge_cases
    a = _finding("idor")                       # /idor confirmed
    b = _finding("idor")                       # duplicate (same class+endpoint)
    b.vulnerability_class = a.vulnerability_class
    c = _finding("price")                       # distinct
    merged = _merge_cases([a], [b, c])
    confirmed = [x for x in merged if x.verdict == Verdict.CONFIRMED_EXPLOIT]
    endpoints = sorted({x.affected_endpoint for x in confirmed})
    assert endpoints == ["/idor", "/price"]     # duplicate /idor collapsed
