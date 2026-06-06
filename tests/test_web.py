"""
Proof for the web console layer (venom/web).

The web layer is additive — it only *consumes* the real engine. These tests prove
the JSON API is backed by real venom modules (the knowledge base, the agent fleet,
the scope guard), that the engine->UI mappers produce the exact shapes the React
components read, and — the key end-to-end proof — that launching a run executes a
REAL in-process engagement against VulnLab and confirms findings with evidence.

Deterministic and offline (no network, no LLM key).
"""

import os
import time

import pytest

from venom.web import api, mappers, routes, server
from venom.web.runs import MANAGER


# --------------------------------------------------------------------------- API
def test_vuln_classes_from_real_kb():
    from venom.knowledge.business_logic import BUSINESS_LOGIC_KB

    status, body, _, _ = routes.handle("GET", "/api/vuln-classes", {}, {})
    assert status == 200
    classes = body["classes"]
    assert len(classes) == len(BUSINESS_LOGIC_KB)        # backed by the real KB
    assert all({"id", "name", "desc", "cwe"} <= set(c) for c in classes)


def test_agents_and_providers_and_status():
    _, agents, _, _ = routes.handle("GET", "/api/agents", {}, {})
    roles = {a["role"] for a in agents["fleet"]}
    assert {"orchestrator", "codegen", "hypothesis"} <= roles
    # models mirror the real fleet (and the prototype's run screen)
    models = {a["model"] for a in agents["fleet"]}
    assert any("deepseek" in m for m in models)

    _, providers, _, _ = routes.handle("GET", "/api/providers", {}, {})
    assert "providers" in providers
    # secrets must never leak through the API
    for p in providers["providers"]:
        assert "api_key" not in p and "key" not in p

    _, status, _, _ = routes.handle("GET", "/api/status", {}, {})
    assert status["scope_guard"] == "armed"
    assert status["redaction"] is True


def test_scope_validate_ok_and_rejected():
    _, ok, _, _ = routes.handle("POST", "/api/scope/validate", {}, {"url": "https://x.example.com"})
    assert ok["ok"] is True and "summary" in ok

    _, missing, _, _ = routes.handle("POST", "/api/scope/validate", {}, {"url": ""})
    assert missing["ok"] is False

    _, expired, _, _ = routes.handle("POST", "/api/scope/validate", {},
                                  {"url": "https://x.example.com", "expiry_date": "2000-01-01T00:00:00Z"})
    assert expired["ok"] is False and "expired" in expired["error"].lower()


def _login(username="op", password="pw"):
    """Seed + log in a user; return the session cookie for protected-endpoint calls."""
    from venom.web import auth
    auth.add_user(username, password)
    _, _, _, hdr = routes.handle("POST", "/api/login", {}, {"username": username, "password": password}, "")
    return hdr["Set-Cookie"].split(";")[0]


def test_engagements_requires_auth_and_filters(tmp_path, monkeypatch):
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VENOM_WEB_SECRET", "t")
    # unauthenticated -> 401 (per-user data is gated)
    st, _, _, _ = routes.handle("GET", "/api/engagements", {}, {}, "")
    assert st == 401
    # authenticated -> 200, a list, and never any demo rows
    st, body, _, _ = routes.handle("GET", "/api/engagements", {}, {}, _login())
    assert st == 200 and isinstance(body["engagements"], list)
    assert not any(e.get("demo") for e in body["engagements"])


def test_unknown_route_404():
    status, _, _, _ = routes.handle("GET", "/api/nope", {}, {})
    assert status == 404


# --------------------------------------------------------------------- mappers
def test_classify_log():
    assert mappers.classify_log("[scope] loading") == "stage"
    assert mappers.classify_log("‼ H1 BOLA confirmed — read victim wallet") == "hit"
    assert mappers.classify_log("GET  /api/v1/openapi.json   200") == "req"
    assert mappers.classify_log("✓ scope guard armed") == "ok"


def test_stage_order_is_monotonic():
    assert mappers.stage_order("Loaded scope ENG", 0) == 0
    assert mappers.stage_order("Discovery crawl: 41 pages", 0) == 1
    # never decreases
    assert mappers.stage_order("nothing here", 4) == 4
    assert mappers.stage_order("Report written to out/", 0) == 6


def test_finding_to_ui_shape():
    finding = {
        "finding_id": "BL-001",
        "title": "Cross-account wallet disclosure",
        "severity": "CRITICAL",
        "vulnerability_class": "BOLA_IDOR",
        "affected_endpoint": "GET /api/v1/wallet/{id}",
        "business_impact": "Reads any user's wallet.",
        "reproduction_steps": [
            {"step": 1, "description": "baseline denied", "method": "GET",
             "path": "/api/v1/wallet/5", "actual_status": 403},
            {"step": 2, "description": "cross-account read", "method": "GET",
             "path": "/api/v1/wallet/5", "actual_status": 200},
        ],
        "evidence": {"state_before": {"balance": 250.0}, "state_after": {"balance": -1840.0},
                     "deltas": {"balance": -2090.0}},
        "remediation": {"short_term": "ownership check", "long_term": "UUID ids"},
        "cvss_vector": "CVSS:3.1/...",
    }
    ui = mappers.finding_to_ui(finding)
    required = {"id", "title", "vclass", "severity", "cwe", "owasp", "method", "path",
                "confirmed", "oracle", "origin", "authored", "summary", "impact", "log",
                "state", "oracleRows", "code", "remediation"}
    assert required <= set(ui)
    assert ui["severity"] == "crit"
    assert ui["method"] == "GET" and ui["path"] == "/api/v1/wallet/{id}"
    assert ui["cwe"] == "CWE-639"
    assert len(ui["log"]) == 2 and ui["log"][0]["kind"] == "deny" and ui["log"][1]["kind"] == "win"
    # REAL state delta is surfaced (this finding measured balance: 250 -> -1840).
    assert ui["state"]["before"] == "250" and ui["state"]["after"] == "-1840"
    assert isinstance(ui["remediation"], list) and len(ui["remediation"]) == 2
    # HONEST: no agent authored an exploit for this finding -> no fabricated code.
    assert ui["code"] == "" and ui["authored"] is False


def test_finding_to_ui_no_fabrication_without_evidence():
    """A status-confirmed finding with NO state delta and NO exploit code must not
    show a fabricated state-delta or invented exploit script."""
    finding = {
        "finding_id": "BL-009", "title": "Privileged page reachable",
        "severity": "HIGH", "vulnerability_class": "PRIV_ESCALATION",
        "affected_endpoint": "GET /adminpanel", "business_impact": "BFLA",
        "reproduction_steps": [{"step": 1, "method": "GET", "path": "/adminpanel", "actual_status": 200}],
        "evidence": {"state_before": {}, "state_after": {}, "deltas": {}, "net_balance_delta": 0.0},
        "confirmation": "response-content match", "origin": "playbook",
    }
    ui = mappers.finding_to_ui(finding)
    assert ui["state"] is None                 # no fabricated baseline->violated delta
    assert ui["code"] == "" and ui["authored"] is False
    assert ui["oracle"] == "response-content match"   # the REAL method, not "differential"


def test_finding_to_ui_surfaces_real_agent_code():
    """When the agent DID author an exploit, the UI shows that real code + differential."""
    finding = {
        "finding_id": "BL-010", "title": "Account takeover via trusted id",
        "severity": "HIGH", "vulnerability_class": "PRIV_ESCALATION",
        "affected_endpoint": "POST /account/promote", "business_impact": "ATO",
        "reproduction_steps": [], "origin": "oneshot",
        "confirmation": "differential oracle",
        "evidence": {"exploit_code": "async def exploit(http):\n    await http('POST', '/account/promote')\n    return True",
                     "differential": {"baseline_denied": True, "post_exploit_allowed": True}},
    }
    ui = mappers.finding_to_ui(finding)
    assert ui["authored"] is True and "async def exploit" in ui["code"]
    assert ui["oracle"] == "differential oracle" and ui["origin"] == "oneshot"


# ------------------------------------------------------------------ editable scope
def test_base_urls_additive_prefixes():
    out = api.base_urls("http://localhost:8000", ["/shop/*", "/api/*", "/"])
    assert out[0] == "http://localhost:8000"                 # bare host stays in scope
    assert "http://localhost:8000/shop" in out and "http://localhost:8000/api" in out
    assert out.count("http://localhost:8000") == 1           # "/" prefix doesn't duplicate


def test_scope_validate_honors_out_of_scope_and_prefixes():
    res = api.api_scope_validate({"url": "http://localhost:8000",
                                  "out_of_scope": ["stripe.com", "auth0.com"],
                                  "scope_paths": ["/shop/*"], "authorized_by": "tester"})
    assert res["ok"] is True
    assert "stripe.com" in res["summary"]                    # hard-block recorded in scope


def test_start_run_carries_scope_edits(monkeypatch):
    """The wizard's editable scope (hosts/prefixes) must reach the run options."""
    captured = {}
    monkeypatch.setattr(api.MANAGER, "start", lambda opts: captured.update(opts) or "ENG-TEST")
    api.api_start_run({"out_of_scope": ["evil.com"], "scope_paths": ["/admin/*"],
                       "authorized_by": "x"})
    assert captured["out_of_scope"] == ["evil.com"]
    assert captured["scope_paths"] == ["/admin/*"]


def test_engagements_lists_running_runs(tmp_path, monkeypatch):
    """A run must appear in the engagement list while it is RUNNING (in memory),
    not only after it is persisted — otherwise the dashboard can't show it live."""
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    from venom.web.runs import RunManager, Run
    mgr = RunManager()
    run = Run("ENG-LIVE-TEST", {"target_name": "X", "authorized_by": "t"})
    run.status = "running"
    mgr.runs[run.id] = run
    rows = mgr.engagements()
    row = next((r for r in rows if r["id"] == "ENG-LIVE-TEST"), None)
    assert row is not None and row["status"] == "live"     # visible + flagged running


def test_scope_targets_the_entered_url_not_a_hardcoded_host(tmp_path, monkeypatch):
    """The engagement MUST target the URL the operator entered — never silently
    swap in the bundled demo host. (Regression: an external lab hunted localhost.)"""
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    from venom.web.runs import RunManager, Run
    mgr = RunManager()
    run = Run("ENG-EXT", {"target_url": "https://lab.web-security-academy.net",
                          "target_name": "BurpSuite Test", "authorized_by": "t"})
    sd = mgr._scope_dict(run)
    assert sd["authorized_base_urls"][0] == "https://lab.web-security-academy.net"
    assert all("localhost" not in u for u in sd["authorized_base_urls"])
    # an external target gets NO bundled VulnLab credentials
    assert sd["identities"] == []


def test_bundled_demo_target_keeps_demo_identities(tmp_path, monkeypatch):
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    from venom.web.runs import RunManager, Run
    mgr = RunManager()
    run = Run("ENG-DEMO", {"target_url": "localhost:8000", "authorized_by": "t"})
    sd = mgr._scope_dict(run)
    assert sd["authorized_base_urls"][0] == "http://localhost:8000"
    assert [i["name"] for i in sd["identities"]] == ["attacker", "victim"]


def test_external_target_uses_operator_credentials(tmp_path, monkeypatch):
    """Operator-supplied login credentials must reach the scope so the agent can
    authenticate to a real target (the reason an external lab found nothing: no auth)."""
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    from venom.web.runs import RunManager, Run
    ident = {"name": "wiener", "role": "attacker",
             "auth": {"type": "form_login", "login_url": "/login", "method": "POST",
                      "username": "wiener", "password": "peter",
                      "username_field": "username", "password_field": "password"}}
    run = Run("ENG-EXT2", {"target_url": "https://lab.web-security-academy.net",
                           "identities": [ident], "authorized_by": "t"})
    sd = RunManager()._scope_dict(run)
    assert sd["identities"] == [ident]                       # real creds carried through
    assert sd["identities"][0]["auth"]["username"] == "wiener"


def test_start_run_carries_identities(monkeypatch):
    captured = {}
    monkeypatch.setattr(api.MANAGER, "start", lambda opts: captured.update(opts) or "ENG-T")
    api.api_start_run({"identities": [{"name": "u", "auth": {"username": "u"}}],
                       "authorized_by": "x"})
    assert captured["identities"] == [{"name": "u", "auth": {"username": "u"}}]


def test_email_registration_lab_scope(tmp_path, monkeypatch):
    """A registration / email-parser lab needs: the inbox URL set + authorized, and
    the 'delete <user>' objective extracted — the missing inputs that left the
    email_parser flow gated off (so the lab couldn't be solved)."""
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    from venom.web.runs import RunManager, Run
    run = Run("ENG-MAIL", {
        "target_url": "https://lab.web-security-academy.net",
        "email_client_url": "https://exploit-abc.exploit-server.net/email",
        # NOTE the trailing period — regression: it was captured as "carlos." and
        # the delete hit a non-existent user, so the lab never registered the solve.
        "objective": "register an account and delete carlos.",
        "destructive": True, "authorized_by": "t"})
    sd = RunManager()._scope_dict(run)
    assert sd["email_client_url"] == "https://exploit-abc.exploit-server.net/email"
    assert "https://exploit-abc.exploit-server.net" in sd["authorized_base_urls"]  # inbox host authorized
    assert sd["objective_delete_user"] == "carlos"                                 # NOT "carlos."
    assert sd["allow_destructive"] is True


def test_is_bundled_target_detection():
    from venom.web.runs import RunManager
    assert RunManager.is_bundled_target("http://localhost:8000")
    assert RunManager.is_bundled_target("localhost:8000")
    assert RunManager.is_bundled_target("http://127.0.0.1:8000")
    assert not RunManager.is_bundled_target("https://lab.web-security-academy.net")
    assert not RunManager.is_bundled_target("http://localhost:3000")
    assert not RunManager.is_bundled_target("http://evil.com:8000")


# ------------------------------------------------------------------ static guard
def test_static_traversal_is_rejected():
    escaped = (server.UI_DIR / ".." / ".." / "secret.txt").resolve()
    assert not escaped.is_relative_to(server.UI_DIR)
    inside = (server.UI_DIR / "index.html").resolve()
    assert inside.is_relative_to(server.UI_DIR)


# ---------------------------------------------------------------- end-to-end run
def test_launch_without_provider_fails_honestly(tmp_path, monkeypatch):
    """The live engagement is an LLM-driven hunt. With NO provider configured it must
    fail HONESTLY (no silent degrade to a status scanner dressed up as a real hunt)."""
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))

    # Force "no provider": the router reports nothing enabled (runs.py imports
    # LLMRouter locally, so patch the class method it actually calls).
    monkeypatch.setattr("venom.llm.LLMRouter.any_enabled", lambda self: False)

    run_id = MANAGER.start({"target_name": "VulnLab", "rate": 50,
                            "objective": "find a business-logic flaw"})
    run = MANAGER.get(run_id)
    deadline = time.time() + 30
    while not run.finished and time.time() < deadline:
        time.sleep(0.05)
    assert run.finished and run.status == "error"
    assert "LLM provider" in (run.error or "")
    # the trace still recorded the honest failure, not a fake success
    assert any(e["t"] in ("error", "done") for e in run.events)


@pytest.mark.skipif(not os.getenv("VENOM_LIVE_LLM"),
                    reason="live LLM hunt — set VENOM_LIVE_LLM=1 (uses the configured provider)")
def test_launch_runs_real_llm_hunt(tmp_path, monkeypatch):
    """End-to-end LLM-driven hunt against VulnLab (recon -> infer -> hypothesize ->
    exploit -> verify). Gated: it makes real model calls."""
    monkeypatch.setenv("VENOM_DATA_DIR", str(tmp_path))
    cookie = _login("op", "pw")            # per-run endpoints are owner-gated
    run_id = MANAGER.start({"target_name": "VulnLab", "rate": 50, "destructive": True,
                            "owner": "op", "objective": "find and exploit a business-logic flaw"})
    run = MANAGER.get(run_id)
    deadline = time.time() + 300
    while not run.finished and time.time() < deadline:
        time.sleep(0.2)
    assert run.finished, "engagement did not finish within the timeout"
    assert run.status == "done", f"run errored: {run.error}"
    types = {e["t"] for e in run.events}
    assert "stage" in types and any(e["t"] == "done" for e in run.events)
    for f0 in run.findings:    # every reported finding carries honest, real evidence
        assert f0["confirmed"] is True
        assert f0["oracle"] and isinstance(f0["log"], list)

    # the findings endpoint resolves the run via the shared manager
    status, body, _, _ = routes.handle("GET", f"/api/runs/{run_id}/findings", {}, {}, cookie)
    assert status == 200
    assert len(body["findings"]) == len(run.findings)

    # the real artifacts were written and are downloadable
    rstatus, report, ctype, _ = routes.handle("GET", f"/api/runs/{run_id}/report.md", {}, {}, cookie)
    assert rstatus == 200 and "VENOM" in report
