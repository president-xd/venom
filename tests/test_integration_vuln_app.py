"""
End-to-end proof: run a full engagement against an in-memory *vulnerable* API
(via httpx.MockTransport) and assert VENOM actually CONFIRMS the exploits —
authenticated, with provisioning, concurrency, and state-delta confirmation.

This is the test that distinguishes "generates attack shapes" from
"detects and exploits business-logic vulnerabilities".
"""

import asyncio
import json
import re
from pathlib import Path

import httpx
import pytest

from venom.engagement import run_engagement
from venom.testing.schema import VulnClass, Verdict

BASE = "https://api-staging.acmepay.example.com"


# --------------------------------------------------------------------------- mock
def make_vulnerable_app():
    """A deliberately vulnerable API: no ownership check (IDOR), no atomic
    redemption (race), no state-machine check (sequence), reflects all input
    (mass assignment), no numeric bounds (param pollution)."""
    state = {"orders": {}, "next_id": 1, "balances": {}}

    def user_of(req):
        auth = req.headers.get("Authorization", "")
        return auth.replace("Bearer ", "").replace("-tok", "") or None

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        body = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except Exception:
                body = {}
        user = user_of(request)

        if path == "/api/v1/login" and method == "POST":
            return httpx.Response(200, json={"token": f"{body.get('username','anon')}-tok"})

        if path == "/api/v1/orders" and method == "POST":
            oid = str(state["next_id"]); state["next_id"] += 1
            order = {"id": oid, "status": "paid", "owner": user}
            order.update(body)  # VULN: mass assignment — binds every field sent
            state["orders"][oid] = order
            return httpx.Response(201, json=order)

        m = re.match(r"^/api/v1/orders/([^/]+)$", path)
        if m and method == "GET":
            o = state["orders"].get(m.group(1))
            return httpx.Response(200, json=o) if o else httpx.Response(404, json={})

        if re.match(r"^/api/v1/orders/([^/]+)/refund$", path) and method == "POST":
            return httpx.Response(200, json={"refunded": True})  # VULN: no 'shipped' check

        if path == "/api/v1/wallet" and method == "GET":
            return httpx.Response(200, json={"balance": state["balances"].setdefault(user, 3)})

        if path == "/api/v1/wallet/redeem" and method == "POST":
            amt = body.get("amount", 1)
            state["balances"][user] = state["balances"].setdefault(user, 3) - amt  # VULN: not atomic, no bounds
            return httpx.Response(200, json={"ok": True, "balance": state["balances"][user]})

        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "VulnPay", "version": "1.0.0"},
    "servers": [{"url": BASE}],
    "security": [{"bearerAuth": []}],
    "paths": {
        "/api/v1/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"username": {"type": "string"}, "password": {"type": "string"}}}}}}}},
        "/api/v1/orders": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"product_id": {"type": "string"}}}}}}}},
        "/api/v1/orders/{id}": {"get": {"parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]}},
        "/api/v1/orders/{id}/refund": {"post": {"parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]}},
        "/api/v1/wallet": {"get": {}},
        "/api/v1/wallet/redeem": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "required": ["amount"], "properties": {"amount": {"type": "integer"}}}}}}}},
    },
}


def _scope() -> dict:
    def ident(name):
        return {"name": name, "role": name, "auth": {
            "type": "login", "method": "POST", "path": "/api/v1/login",
            "body": {"username": name, "password": "pw"}, "token_path": "$.token",
            "place": "header", "header": "Authorization", "scheme": "Bearer"}}
    return {
        "engagement_id": "ENG-VULN-TEST",
        "target_name": "VulnPay",
        "authorized_base_urls": [BASE],
        "identities": [ident("attacker"), ident("victim")],
        "rate_limit_per_second": 200,
        "authorization_date": "2026-01-01T00:00:00Z",
        "expiry_date": "2030-01-01T00:00:00Z",
    }


def _run(tmp_path: Path):
    (tmp_path / "spec.json").write_text(json.dumps(SPEC), encoding="utf-8")
    (tmp_path / "scope.json").write_text(json.dumps(_scope()), encoding="utf-8")
    return asyncio.run(run_engagement(
        scope_path=tmp_path / "scope.json",
        artifact_paths=[tmp_path / "spec.json"],
        out_dir=tmp_path / "out",
        dry_run=False,         # LIVE against the in-memory target
        use_llm=False,         # offline: deterministic playbooks
        transport=make_vulnerable_app(),
    ))


def _confirmed(result, vclass) -> bool:
    return any(c.vulnerability_class == vclass and c.verdict == Verdict.CONFIRMED_EXPLOIT
               for c in result.cases)


def test_detects_idor(tmp_path):
    assert _confirmed(_run(tmp_path), VulnClass.BOLA_IDOR)


def test_detects_race_via_state_delta(tmp_path):
    result = _run(tmp_path)
    race = [c for c in result.cases if c.vulnerability_class == VulnClass.RACE_CONDITION]
    assert any(c.verdict == Verdict.CONFIRMED_EXPLOIT for c in race)
    # Confirmation must be grounded in real negative balance, not 2xx count alone.
    confirmed = next(c for c in race if c.verdict == Verdict.CONFIRMED_EXPLOIT)
    assert confirmed.evidence["state_after"].get("balance", 0) < 0


def test_detects_sequence_bypass(tmp_path):
    assert _confirmed(_run(tmp_path), VulnClass.SEQUENCE_VIOLATION)


def test_detects_mass_assignment(tmp_path):
    assert _confirmed(_run(tmp_path), VulnClass.MASS_ASSIGNMENT)


def test_authenticated_and_reported(tmp_path):
    result = _run(tmp_path)
    confirmed = [c for c in result.cases if c.verdict == Verdict.CONFIRMED_EXPLOIT]
    assert len(confirmed) >= 3
    # Report artifacts exist and findings.json records the confirmed exploits.
    findings = json.loads((result.artifacts["findings"]).read_text(encoding="utf-8"))
    assert findings["summary"]["confirmed"] >= 3
