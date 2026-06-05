"""
Proof for the verdict gate (venom/engine/runner.py :: TestRunner._judge).

The deterministic engine used to report a finding as CONFIRMED_EXPLOIT whenever a
step's success_condition was met — including the degenerate `status in (200, 201)`.
On a forgiving app (200 on every landing page) that turned a mere `GET -> 200` into
a "confirmed exploit": a false positive.

The gate now separates PROOF from a LEAD:
  - CONFIRMED_EXPLOIT  -> the pass is corroborated by a real state delta, a
                          response-content assertion, or a cross-identity differential.
  - NEEDS_REVIEW       -> the condition was met by HTTP status ALONE (no state
                          change, no content proof): a lead to verify, not a finding.
  - FALSE_POSITIVE     -> no condition met.

These tests lock that behavior in with a real in-memory target (httpx.MockTransport).
"""

import json

import httpx
import pytest

from venom.core.graph import BusinessModelGraph, Rule
from venom.core.scope import Scope
from venom.engine.runner import TestRunner
from venom.testing.playbooks import faith_based_rules
from venom.testing.schema import Severity, TestCase, TestStep, Verdict, VulnClass

_VC = VulnClass.FAITH_BASED_RULE
_SEV = Severity.HIGH

BASE = "https://app.example.com"


def _app():
    """A deliberately forgiving app: every landing page and bare mutation returns
    200, but only /wallet/redeem actually changes server state."""
    state = {"balance": 100}

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/landing" and method == "GET":
            return httpx.Response(200, json={"page": "refund desk"})       # a 200 page, no effect
        if path == "/mutate" and method == "POST":
            return httpx.Response(200, json={"ok": True, "echo": "done"})   # 200 + body, no state effect
        if path == "/wallet" and method == "GET":
            return httpx.Response(200, json={"balance": state["balance"]})
        if path == "/wallet/redeem" and method == "POST":
            state["balance"] -= 40                                         # REAL state change
            return httpx.Response(200, json={"balance": state["balance"]})
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


def _scope() -> Scope:
    return Scope.from_dict({
        "engagement_id": "ENG-GATE-TEST",
        "target_name": "GateApp",
        "authorized_base_urls": [BASE],
        "rate_limit_per_second": 200,
        "authorization_date": "2026-01-01T00:00:00Z",
        "expiry_date": "2030-01-01T00:00:00Z",
    })


async def _judge_case(case: TestCase) -> Verdict:
    runner = TestRunner(_scope(), dry_run=False, transport=_app())
    try:
        await runner.run_case(case)
    finally:
        await runner.aclose()
    return case.verdict


# --------------------------------------------------------------------------- gate
async def test_status_only_pass_with_no_state_change_is_a_lead_not_a_finding():
    """The exact historical false positive: GET a 200 landing page, condition is
    `status in (200, 201)`. No state delta, no content proof -> NEEDS_REVIEW."""
    case = TestCase(
        test_id="GT-001", vulnerability_class=_VC, risk_rating=_SEV, hypothesis="landing page returns 200",
        affected_endpoint="GET /landing",
        steps=[TestStep(step=1, description="GET landing", method="GET", path="/landing",
                        success_condition="status in (200, 201)")],
    )
    verdict = await _judge_case(case)
    assert verdict == Verdict.NEEDS_REVIEW
    assert verdict != Verdict.CONFIRMED_EXPLOIT     # must NOT be reported as a finding


async def test_status_only_pass_with_real_state_delta_is_confirmed():
    """Same status-only condition, but the action genuinely moves a balance. The
    measured delta corroborates the pass -> CONFIRMED_EXPLOIT."""
    case = TestCase(
        test_id="GT-002", vulnerability_class=_VC, risk_rating=_SEV, hypothesis="redeem changes balance",
        affected_endpoint="POST /wallet/redeem",
        state_probe=TestStep(step=0, description="probe balance", method="GET",
                             path="/wallet", extract={"balance": "$.balance"}),
        steps=[TestStep(step=1, description="redeem", method="POST", path="/wallet/redeem",
                        body={"amount": 40}, success_condition="status in (200, 201)")],
    )
    verdict = await _judge_case(case)
    assert verdict == Verdict.CONFIRMED_EXPLOIT
    assert case.evidence["net_balance_delta"] != 0.0


async def test_content_backed_condition_is_confirmed():
    """A condition that asserts response CONTENT (body) is proof, not just a status."""
    case = TestCase(
        test_id="GT-003", vulnerability_class=_VC, risk_rating=_SEV, hypothesis="mutation reflected",
        affected_endpoint="POST /mutate",
        steps=[TestStep(step=1, description="mutate", method="POST", path="/mutate",
                        success_condition="status == 200 and bool(body)")],
    )
    assert await _judge_case(case) == Verdict.CONFIRMED_EXPLOIT


async def test_cross_identity_differential_is_confirmed():
    """Provisioned as one identity, abused as another: a cross-tenant differential
    makes even a status-only pass a genuine finding."""
    case = TestCase(
        test_id="GT-004", vulnerability_class=_VC, risk_rating=_SEV, hypothesis="cross-tenant read",
        affected_endpoint="GET /landing",
        setup_steps=[TestStep(step=1, description="victim provisions", method="POST",
                              path="/mutate", identity="victim")],
        steps=[TestStep(step=2, description="attacker reads", method="GET", path="/landing",
                        identity="attacker", success_condition="status == 200")],
    )
    assert await _judge_case(case) == Verdict.CONFIRMED_EXPLOIT


async def test_no_condition_met_is_false_positive():
    case = TestCase(
        test_id="GT-005", vulnerability_class=_VC, risk_rating=_SEV, hypothesis="nothing matches",
        affected_endpoint="GET /landing",
        steps=[TestStep(step=1, description="GET landing", method="GET", path="/landing",
                        success_condition="status == 500")],
    )
    assert await _judge_case(case) == Verdict.FALSE_POSITIVE


# ------------------------------------------------------------------ generator fix
def test_faith_based_rules_skips_get_reads():
    """A faith-based CONSTRAINT is violated by a forbidden ACTION (a mutation), not
    by reading a page. The generator must not emit a GET-read case (a guaranteed
    false positive); it still emits the mutating one."""
    g = BusinessModelGraph()
    g.add_rule(Rule(rule_id="FB-GET", rule_type="THRESHOLD",
                    description="Implicit constraint on GET /refund", attached_to="GET /refund",
                    enforced=False))
    g.add_rule(Rule(rule_id="FB-POST", rule_type="THRESHOLD",
                    description="Implicit constraint on POST /pay/credit",
                    attached_to="POST /pay/credit", enforced=False))
    cases = faith_based_rules(g, identities=[{"name": "attacker"}])
    endpoints = {c.affected_endpoint for c in cases}
    assert "GET /refund" not in endpoints          # the noisy read is gone
    assert "POST /pay/credit" in endpoints          # the real mutating lead remains
