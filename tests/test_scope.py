"""Scope guard is the safety boundary — test it hard."""

import pytest

from venom.core.scope import Scope, ScopeError


def _scope(**over):
    base = dict(
        engagement_id="ENG-TEST",
        target_name="T",
        authorized_base_urls=["https://api-staging.acmepay.example.com/api"],
        out_of_scope=["stripe.com"],
        authorization_date="2026-01-01T00:00:00Z",
        expiry_date="2030-01-01T00:00:00Z",
    )
    base.update(over)
    return Scope.from_dict(base)


def test_in_scope_url_allowed():
    s = _scope()
    s.assert_request_allowed("GET", "https://api-staging.acmepay.example.com/api/v1/orders")


def test_out_of_host_blocked():
    s = _scope()
    with pytest.raises(ScopeError):
        s.assert_request_allowed("GET", "https://evil.example.com/api/v1/orders")


def test_explicit_out_of_scope_blocked():
    s = _scope(authorized_base_urls=["https://stripe.com"], out_of_scope=["stripe.com"])
    with pytest.raises(ScopeError):
        s.assert_request_allowed("GET", "https://stripe.com/v1/charges")


def test_path_prefix_enforced():
    s = _scope()
    # /api authorized; /admin outside the prefix must be blocked
    with pytest.raises(ScopeError):
        s.assert_request_allowed("GET", "https://api-staging.acmepay.example.com/admin")


def test_destructive_blocked_by_default():
    s = _scope()
    with pytest.raises(ScopeError):
        s.assert_request_allowed("DELETE", "https://api-staging.acmepay.example.com/api/v1/orders/1",
                                 destructive=True)


def test_destructive_allowed_with_flag():
    s = _scope(allow_destructive=True)
    s.assert_request_allowed("DELETE", "https://api-staging.acmepay.example.com/api/v1/orders/1",
                             destructive=True)


def test_expired_engagement_blocks():
    s = _scope(expiry_date="2020-01-01T00:00:00Z")
    with pytest.raises(ScopeError):
        s.validate_window()


def test_missing_required_field():
    with pytest.raises(ScopeError):
        Scope.from_dict({"engagement_id": "x", "target_name": "y"})
