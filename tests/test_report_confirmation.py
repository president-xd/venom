"""
The report must describe HOW each finding was actually confirmed — never asserting
a differential/state-delta where the evidence shows none. These tests pin the
`Finding.confirmation` / `origin` derivation in venom.report.builder.
"""

from venom.report.builder import build_findings, _confirmation_method
from venom.testing.schema import Severity, TestCase, TestStep, Verdict, VulnClass


def _case(**kw):
    base = dict(test_id="TC-1", vulnerability_class=VulnClass.PRIV_ESCALATION,
                hypothesis="h", risk_rating=Severity.HIGH, affected_endpoint="GET /x",
                verdict=Verdict.CONFIRMED_EXPLOIT)
    base.update(kw)
    return TestCase(**base)


def test_confirmation_differential_when_agent_authored_code():
    c = _case(evidence={"exploit_code": "async def exploit(http): ...",
                        "differential": {"baseline_denied": True}})
    assert _confirmation_method(c, c.evidence) == "differential oracle"


def test_confirmation_state_delta_when_balance_moved():
    c = _case(evidence={"deltas": {"balance": -50.0}, "net_balance_delta": -50.0})
    assert _confirmation_method(c, c.evidence) == "state-delta differential"


def test_confirmation_response_content_when_condition_inspects_text():
    c = _case(steps=[TestStep(step=1, description="browse", method="GET", path="/adminpanel",
                              success_condition="status == 200 and 'admin' in text")],
              evidence={"deltas": {}, "net_balance_delta": 0.0})
    assert _confirmation_method(c, c.evidence) == "response-content match"


def test_confirmation_status_only_when_no_corroboration():
    c = _case(steps=[TestStep(step=1, description="x", method="POST", path="/x",
                              success_condition="status in (200, 201)")],
              evidence={"deltas": {}, "net_balance_delta": 0.0})
    assert _confirmation_method(c, c.evidence) == "status response"


def test_build_findings_threads_confirmation_and_origin():
    c = _case(origin="oneshot",
              steps=[TestStep(step=1, description="x", method="GET", path="/adminpanel",
                              success_condition="status == 200 and 'admin' in text")],
              evidence={"deltas": {}, "net_balance_delta": 0.0})
    findings = build_findings([c])
    assert len(findings) == 1
    d = findings[0].to_dict()
    assert d["confirmation"] == "response-content match"
    assert d["origin"] == "oneshot"
