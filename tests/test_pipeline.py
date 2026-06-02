"""Ingestion + business-model + playbook generation, fully offline."""

import asyncio
from pathlib import Path

from venom.ingest import ingest
from venom.inference import infer_business_model
from venom.testing import generate_test_cases

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_ingest_openapi_and_traffic():
    res = ingest([EXAMPLES / "acmepay_openapi.json", EXAMPLES / "acmepay_traffic.har",
                  EXAMPLES / "app.bundle.js"])
    assert len(res.registry) > 0
    # Refund endpoint should be present and tagged financial.
    refund = res.registry.get("POST", "/api/v1/orders/{id}/refund")
    assert refund is not None
    assert "financial" in refund.business_rule_tags
    # The /internal/api/v1/promo/apply path appears only in traffic/JS -> shadow.
    assert any(e.shadow_endpoint for e in res.registry)


def test_secret_redacted():
    res = ingest([EXAMPLES / "app.bundle.js"])
    # A secret-looking token exists but must be redacted (never full value).
    assert all("notreal" not in s for s in res.secrets)


def test_offline_generation_produces_cases():
    res = ingest([EXAMPLES / "acmepay_openapi.json"])
    graph = asyncio.run(infer_business_model(res.registry, router=None))
    cases = asyncio.run(generate_test_cases(res.registry, graph, router=None))
    assert len(cases) > 0
    classes = {c.vulnerability_class.value for c in cases}
    # Financial POST endpoints should yield race + param + mass-assignment tests.
    assert "RACE_CONDITION" in classes
    assert "MASS_ASSIGNMENT" in classes
