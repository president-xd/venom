"""
Security-hardening regression tests:

1. Web-console login does a constant-cost password verification even for unknown
   usernames, so login response time cannot be used to enumerate which operator
   accounts exist (the PBKDF2 cost is paid either way).
2. The (signed, persisted) request audit trail always strips provider API keys /
   bearer tokens embedded in a URL - even when the operator opted into PII capture -
   because secret redaction is always-on, independent of the PII setting.
"""

from __future__ import annotations

from venom.core.scope import Scope
from venom.memory import Notebook
from venom.tools import Toolbox
from venom.web import auth


# --------------------------------------------------------------- 1. login timing
def test_authenticate_unknown_user_still_runs_password_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    auth._fail_log.clear()
    # spy on verify_password to prove the KDF runs even when the user does not exist
    calls: list = []
    real = auth.verify_password
    monkeypatch.setattr(auth, "verify_password",
                        lambda pw, stored: (calls.append(stored), real(pw, stored))[1])

    assert auth.authenticate("ghost-user-never-created", "whatever") is None
    assert calls, "verify_password must run for an unknown user (timing equalization)"
    # the equalizer compares against the dummy hash, not an empty string
    assert calls[-1] == auth._DUMMY_HASH


def test_authenticate_real_user_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    auth._fail_log.clear()
    assert auth.add_user("operator1", "correct horse battery", name="Op One", role="lead")
    assert auth.authenticate("operator1", "wrong") is None
    acct = auth.authenticate("operator1", "correct horse battery")
    assert acct and acct["username"] == "operator1" and acct["role"] == "lead"


# --------------------------------------------------- 2. audit trail secret redaction
def _scope(allow_pii: bool):
    return Scope.from_dict({
        "engagement_id": "E", "target_name": "T",
        "authorized_base_urls": ["https://app.example"],
        "allow_pii_capture": allow_pii,
        "authorization_date": "2026-01-01T00:00:00Z",
        "expiry_date": "2030-01-01T00:00:00Z"})


def test_audit_trail_redacts_secrets_even_with_pii_capture_enabled():
    # PII capture ON means redact() (PII) is intentionally disengaged; the always-on
    # secret redaction must STILL strip a provider key embedded in the URL.
    tb = Toolbox(_scope(allow_pii=True), Notebook())
    tb.requests.append({"method": "GET",
                        "path": "/oauth/callback?api_key=sk-abcdef0123456789abcdef&u=1",
                        "status": 200})
    audited = tb.audit()
    blob = str(audited)
    assert "sk-abcdef0123456789abcdef" not in blob, blob
    assert "redacted" in blob.lower()


def test_audit_trail_redacts_secrets_when_pii_capture_disabled():
    tb = Toolbox(_scope(allow_pii=False), Notebook())
    tb.requests.append({"method": "GET",
                        "path": "/cb?authorization=Bearer%20sk-or-v1-deadbeefdeadbeef00",
                        "status": 200})
    blob = str(tb.audit())
    assert "sk-or-v1-deadbeefdeadbeef00" not in blob, blob
