"""
Recon enrichment: probing the discovered surface as the current user yields an
accessible/denied action map. This is the senior-tester situational picture that
lets the agent reason about which forbidden action to bridge to.
"""

import asyncio

from venom.core.scope import Scope
from venom.core.registry import EndpointRegistry, Endpoint
from venom.ingest.recon import enrich_recon
from venom.cognition.oneshot import build_brief
from venom.cognition import Objective

import pytest
pytest.importorskip("vulnlab")   # dev-only proving ground (gitignored); skip if absent
from vulnlab.app import make_transport, new_state

BASE = "https://vuln.local"


def _scope(with_login=True):
    s = {"engagement_id": "E", "target_name": "VulnLab", "authorized_base_urls": [BASE],
         "rate_limit_per_second": 100000, "allow_destructive": True,
         "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z"}
    if with_login:
        s["identities"] = [{"name": "wiener", "role": "user", "auth": {
            "type": "form_login", "login_url": "/login", "method": "POST",
            "username_field": "username", "password_field": "password",
            "username": "wiener", "password": "peter", "csrf_field": "csrf"}}]
    return Scope.from_dict(s)


def _mass_registry():
    reg = EndpointRegistry()
    for p, m in [("/login", "POST"), ("/mass", "GET"), ("/mass/account", "GET"),
                 ("/mass/update", "POST"), ("/mass/delete", "POST")]:
        reg.add(Endpoint(path=p, method=m, source=["crawl"]))
    return reg


def test_enrich_maps_denied_action():
    transport, _ = make_transport(new_state())
    scope = _scope()
    reg = _mass_registry()
    enr = asyncio.run(enrich_recon(scope, reg, transport=transport))
    # The privileged delete is DENIED to the low-priv user (its authz gate fires).
    assert "POST /mass/delete" in enr["denied_to_you"], enr
    # Pages the user can see are accessible.
    assert any(a.startswith("GET /mass") for a in enr["accessible_to_you"]), enr
    assert enr["authenticated_as"] == "wiener"


def test_brief_includes_forbidden_map():
    transport, _ = make_transport(new_state())
    scope = _scope()
    reg = _mass_registry()
    enr = asyncio.run(enrich_recon(scope, reg, transport=transport))
    obj = Objective(description="delete carlos",
                    win_action={"method": "POST", "path": "/mass/delete", "data": {"username": "carlos"}})
    brief = build_brief(reg, obj, enrichment=enr)
    assert "denied_to_you" in brief and "POST /mass/delete" in brief["denied_to_you"]
    assert "accessible_to_you" in brief
