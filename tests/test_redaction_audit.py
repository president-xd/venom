"""PII redaction + audit trail (compliance-relevant)."""

import asyncio
import json
from pathlib import Path

from venom.utils import redact, coerce_number, regex_extract
import tests.test_web_app as web


def test_redact_pii():
    s = ("contact john.doe@acme.com card 4111 1111 1111 1111 "
         "Authorization: Bearer eyJhbGciOi.JeyJzdWIiOiADf.SflKxwRJSMeKKF2QT")
    out = redact(s)
    assert "john.doe@acme.com" not in out
    assert "4111 1111 1111 1111" not in out
    assert "<redacted-email>" in out
    # allow=True must pass the original through unchanged (opt-in raw capture).
    assert redact(s, allow=True) == s


def test_coerce_number_currency_and_text():
    assert coerce_number("£1,337.00") == 1337.0
    assert coerce_number("Total: -50") == -50.0
    assert coerce_number("none here") is None


def test_regex_extract():
    assert regex_extract('value="TOKEN123"', r'value="([^"]+)"') == "TOKEN123"
    assert regex_extract("nope", r"value=\"([^\"]+)\"") is None


def test_engagement_writes_audit_trail(tmp_path):
    result = web._run(tmp_path)
    assert "audit" in result.artifacts
    lines = Path(result.artifacts["audit"]).read_text(encoding="utf-8").strip().splitlines()
    assert lines
    rec = json.loads(lines[0])
    assert {"ts", "engagement", "method", "url"} <= set(rec)
    assert rec["engagement"] == "ENG-WEB-TEST"
