"""
Enterprise trust & operability layer:
  - secret redaction (API keys never reach logs/artifacts),
  - tamper-evident HMAC audit signing,
  - run observability metrics,
  - destructive-action governance (budget cap + kill-switch).
"""

import logging
import os

import pytest

from venom.utils import redact_secrets, SecretLogFilter
from venom.audit import RunMetrics, sign_records, verify_audit
from venom.core.scope import Scope, ScopeError


# --------------------------- secret redaction -------------------------------
def test_redact_secrets_strips_provider_keys():
    s = ("NVIDIA_API_KEY=nvapi-_5KLyeD6XlLZdFrwLBaQabcdef123456 and "
         "OPENROUTER_API_KEY=sk-or-v1-3ac0783e3074411bf05436abcdef0123456789 "
         "Authorization: Bearer eyJabc.def123456789.ghi")
    out = redact_secrets(s)
    # the actual secret material is gone, replaced by a redaction marker
    assert "nvapi-_5KL" not in out and "sk-or-v1-3ac0" not in out and "eyJabc" not in out
    assert "redacted" in out


def test_secret_log_filter_redacts_records():
    flt = SecretLogFilter()
    rec = logging.LogRecord("t", logging.INFO, __file__, 1,
                            "key=nvapi-ABCDEFGHIJKLMNOP123456", None, None)
    assert flt.filter(rec) is True
    assert "nvapi-ABCDEFGH" not in rec.getMessage()


# --------------------------- signed audit -----------------------------------
def test_signed_audit_roundtrip_and_tamper_detection():
    records = [{"method": "POST", "url": "https://t/admin/delete", "status": 200}]
    signed = sign_records(records)
    assert verify_audit(signed) is True
    signed["records"][0]["status"] = 403          # tamper
    assert verify_audit(signed) is False


def test_audit_key_configured_flag(monkeypatch):
    monkeypatch.delenv("VENOM_AUDIT_KEY", raising=False)
    assert sign_records([])["key_configured"] is False
    monkeypatch.setenv("VENOM_AUDIT_KEY", "real-secret-key")
    s = sign_records([{"a": 1}])
    assert s["key_configured"] is True and verify_audit(s) is True


# --------------------------- observability metrics --------------------------
def test_run_metrics_shape():
    m = RunMetrics()
    m.llm_calls = 2; m.requests = 9; m.input_tokens = 100; m.output_tokens = 50
    d = m.to_dict()
    assert d["run_id"] and d["llm_calls"] == 2 and d["requests"] == 9
    assert "elapsed_s" in d and "est_cost_usd" in d


# --------------------------- destructive governance -------------------------
def _scope(**kw):
    base = {"engagement_id": "E", "target_name": "T", "authorized_base_urls": ["https://t.example"],
            "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z"}
    base.update(kw)
    return Scope.from_dict(base)


def test_destructive_budget_caps_actions():
    s = _scope(allow_destructive=True, max_destructive_actions=2)
    u = "https://t.example/admin/delete"
    s.assert_request_allowed("POST", u, destructive=True)   # 1
    s.assert_request_allowed("POST", u, destructive=True)   # 2
    with pytest.raises(ScopeError, match="budget exhausted"):
        s.assert_request_allowed("POST", u, destructive=True)   # 3 -> blocked


def test_destructive_blocked_without_permission():
    s = _scope(allow_destructive=False)
    with pytest.raises(ScopeError, match="DESTRUCTIVE"):
        s.assert_request_allowed("POST", "https://t.example/x", destructive=True)


def test_kill_switch_halts_all_requests(monkeypatch):
    s = _scope(allow_destructive=True)
    monkeypatch.setenv("VENOM_KILL_SWITCH", "1")
    with pytest.raises(ScopeError, match="KILL SWITCH"):
        s.assert_request_allowed("GET", "https://t.example/", destructive=False)
