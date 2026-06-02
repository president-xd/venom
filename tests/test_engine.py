"""Runner-level safety: destructive methods must be blocked even in dry-run,
regardless of the per-step `destructive` flag default (regression guard)."""

import asyncio

from venom.core.scope import Scope
from venom.engine.runner import TestRunner
from venom.testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict


def _scope(allow_destructive=False):
    return Scope.from_dict({
        "engagement_id": "ENG-TEST",
        "target_name": "T",
        "authorized_base_urls": ["https://api-staging.acmepay.example.com"],
        "authorization_date": "2026-01-01T00:00:00Z",
        "expiry_date": "2030-01-01T00:00:00Z",
        "allow_destructive": allow_destructive,
    })


def _put_case():
    return TestCase(
        test_id="TC-PUT", vulnerability_class=VulnClass.MASS_ASSIGNMENT,
        hypothesis="PUT mass assignment", risk_rating=Severity.HIGH,
        affected_endpoint="PUT /api/v1/admin/users/{id}/role",
        steps=[TestStep(step=1, description="put", method="PUT",
                        path="/api/v1/admin/users/5/role", body={"role": "admin"})],
    )


def test_put_blocked_when_destructive_disallowed():
    runner = TestRunner(_scope(allow_destructive=False), dry_run=True)
    case = asyncio.run(runner.run_case(_put_case()))
    asyncio.run(runner.aclose())
    assert case.verdict == Verdict.ENVIRONMENTAL_ERROR
    assert any("SCOPE GUARD" in n for n in case.notes)


def test_put_allowed_when_destructive_enabled():
    runner = TestRunner(_scope(allow_destructive=True), dry_run=True)
    case = asyncio.run(runner.run_case(_put_case()))
    asyncio.run(runner.aclose())
    # In dry-run nothing is sent, so a permitted destructive op ends NOT_RUN, not blocked.
    assert case.verdict == Verdict.NOT_RUN
