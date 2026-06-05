"""
Attack-class playbooks — now generate CONCRETE, runnable exploits.

Where the registry exposes the right relationships and the scope provides test
identities, a playbook emits a full chain: provision prerequisites (setup_steps,
often as the victim), perform the attack (as the attacker), and confirm via
HTTP status, response-body reflection, or before/after state deltas.

When identities or relationships are missing, it still emits shape-only probes
(status-based) so offline/registry-only runs retain coverage.
"""

from __future__ import annotations

import re
from itertools import count

from ..core.graph import BusinessModelGraph
from ..core.registry import Endpoint, EndpointRegistry
from .schema import Severity, TestCase, TestStep, VulnClass

_counter = count(1)


def _tid() -> str:
    return f"TC-{next(_counter):03d}"


def _is_web_form(ep: Endpoint) -> bool:
    """A crawled HTML form — handled by web_playbooks, not the JSON-API playbooks."""
    return "crawl" in ep.source or any(p.location == "form" for p in ep.parameters)


# --------------------------------------------------------------------------- utils
def _resource_keyword(path: str) -> str:
    """The collection name before the id, e.g. /api/v1/orders/{id} -> 'orders'."""
    segs = [s for s in path.split("/") if s and "{" not in s]
    return segs[-1] if segs else ""


def _bind_last_id(path: str, var: str) -> str:
    """Replace the LAST {param} in a path with {var} for runtime substitution."""
    matches = list(re.finditer(r"\{[^}]+\}", path))
    if not matches:
        return path
    m = matches[-1]
    return path[:m.start()] + "{" + var + "}" + path[m.end():]


_SAMPLE = {"string": "venom-test", "integer": 1, "number": 1, "boolean": True, "array": []}


def _dummy_body(ep: Endpoint) -> dict:
    body = {}
    for p in ep.parameters:
        if p.location == "body":
            body[p.name] = _SAMPLE.get(p.type, "venom-test")
    return body


_STATE_HINTS = ("wallet", "balance", "points", "loyalty", "credit", "account")
_BALANCE_FIELDS = ("$.balance", "$.points", "$.credits", "$.amount")
_ACTION_HINTS = ("redeem", "withdraw", "transfer", "claim", "apply", "spend", "purchase")
_TERMINAL_HINTS = ("refund", "cancel", "complete", "approve", "payout", "release")


def _identities(identities):
    ids = list(identities or [])
    attacker = ids[0] if ids else None
    victim = ids[1] if len(ids) > 1 else None
    return attacker, victim


# ----------------------------------------------------------------- 1. BOLA / IDOR
def bola_idor(registry: EndpointRegistry, identities) -> list[TestCase]:
    attacker, victim = _identities(identities)
    cases: list[TestCase] = []
    for getter in (e for e in registry if e.method.upper() == "GET" and "{" in e.path):
        kw = _resource_keyword(getter.path)
        creator = registry.find_create(kw)
        financial = "financial" in getter.business_rule_tags
        sev = Severity.HIGH if financial else Severity.MEDIUM

        if creator and victim and attacker and victim != attacker:
            # Concrete cross-tenant IDOR: victim creates, attacker reads it.
            attack_path = _bind_last_id(getter.path, "victim_obj")
            cases.append(TestCase(
                test_id=_tid(),
                vulnerability_class=VulnClass.BOLA_IDOR,
                hypothesis=(f"{getter.key} authorizes by id without ownership check — "
                            f"'{attacker}' can read an object owned by '{victim}'."),
                risk_rating=sev,
                affected_endpoint=getter.key,
                business_impact=("Cross-tenant read of an economically valuable object"
                                 if financial else "Cross-tenant data exposure"),
                preconditions=[f"identities '{attacker}' and '{victim}'"],
                setup_steps=[TestStep(step=1, description=f"{victim} provisions a {kw}",
                                      method=creator.method, path=creator.path,
                                      identity=victim, body=_dummy_body(creator),
                                      extract={"victim_obj": "$.id"})],
                steps=[TestStep(step=2, description=f"{attacker} reads {victim}'s {kw}",
                                method="GET", path=attack_path, identity=attacker,
                                success_condition="status == 200 and bool(body)")],
                rag_source="OWASP API1:2023 BOLA",
            ))
        else:
            # Shape-only fallback (no second identity / no creator).
            cases.append(TestCase(
                test_id=_tid(),
                vulnerability_class=VulnClass.BOLA_IDOR,
                hypothesis=f"{getter.key} may expose other users' objects via id manipulation.",
                risk_rating=sev,
                affected_endpoint=getter.key,
                business_impact="Potential cross-tenant object access (needs 2 identities to confirm).",
                steps=[TestStep(step=1, description="Access object by id as attacker",
                                method="GET", path=_bind_last_id(getter.path, "probe_id"),
                                identity=attacker, success_condition="status == 200")],
                rag_source="OWASP API1:2023 BOLA",
            ))
    return cases


# ------------------------------------------------------------- 2. Sequence bypass
def sequence_bypass(registry: EndpointRegistry, graph: BusinessModelGraph, identities) -> list[TestCase]:
    attacker, _ = _identities(identities)
    cases: list[TestCase] = []
    terminal = registry.find_action(_TERMINAL_HINTS)
    if not terminal:
        return cases
    kw = _resource_keyword(terminal.path)
    creator = registry.find_create(kw)
    setup, attack_path = [], _bind_last_id(terminal.path, "obj_id")
    if creator:
        setup = [TestStep(step=1, description=f"{attacker} creates a {kw} (initial state)",
                          method=creator.method, path=creator.path, identity=attacker,
                          body=_dummy_body(creator), extract={"obj_id": "$.id"})]
    cases.append(TestCase(
        test_id=_tid(),
        vulnerability_class=VulnClass.SEQUENCE_VIOLATION,
        hypothesis=(f"{terminal.key} can be triggered directly, skipping required "
                    "intermediate state transitions (e.g. refund before shipment)."),
        risk_rating=Severity.HIGH,
        affected_endpoint=terminal.key,
        business_impact=f"Illegal state transition on {kw} yields an unearned outcome.",
        setup_steps=setup,
        # Confirmation is PROOF, not a bare 200: the illegal transition must be
        # ACCEPTED (success body, no error) on a resource we provisioned and never
        # advanced through its precondition state — a genuine sequence differential.
        steps=[TestStep(step=2, description="Invoke terminal transition out of sequence",
                        method=terminal.method, path=attack_path, identity=attacker,
                        body={"reason": "venom-test"},
                        success_condition=("status in (200, 201) and bool(body) and "
                                           "'error' not in text.lower()"))],
        rag_source="OWASP WSTG-BUSL-06",
    ))
    return cases


# ------------------------------------------------------------- 3. Race conditions
def race_conditions(registry: EndpointRegistry, identities) -> list[TestCase]:
    attacker, _ = _identities(identities)
    action = registry.find_action(_ACTION_HINTS)
    state = registry.find_state_read(_STATE_HINTS)
    if not action:
        return []
    probe = None
    if state:
        probe = TestStep(step=0, description="probe balance", method="GET",
                         path=state.path, identity=attacker, extract={"balance": "$.balance"})
    body = _dummy_body(action) or {"amount": 1}
    cases = []
    for threads in (10, 25):
        cases.append(TestCase(
            test_id=_tid(),
            vulnerability_class=VulnClass.RACE_CONDITION,
            hypothesis=(f"{action.key} is non-atomic — {threads} concurrent calls apply "
                        "more than once (TOCTOU double-spend)."),
            risk_rating=Severity.CRITICAL,
            affected_endpoint=action.key,
            business_impact="Double-spend / over-redemption of a financial resource.",
            state_probe=probe,
            steps=[TestStep(step=1, description=f"Fire {threads} identical requests at once",
                            method=action.method, path=action.path, identity=attacker,
                            body=body, concurrency=threads, rate_limited=False,
                            # Confirmed when more than one succeeded AND the balance
                            # was driven below zero (impossible if access were atomic).
                            success_condition="results_2xx > 1 and balance_after < 0")],
            rag_source="HackerOne race-condition class (TOCTOU)",
        ))
    return cases


# --------------------------------------------------- 4. Mass assignment / priv-esc
_PRIV_FIELDS = {"role": "admin", "is_admin": True, "admin": True, "tier": "premium",
                "verified": True, "balance": 999999, "permissions": ["*"]}


def mass_assignment(registry: EndpointRegistry, identities) -> list[TestCase]:
    attacker, _ = _identities(identities)
    cases = []
    for ep in registry:
        if ep.method.upper() not in {"POST", "PUT", "PATCH"}:
            continue
        if _is_web_form(ep):       # web (HTML/form) endpoints are handled by web_playbooks
            continue
        body = {**_dummy_body(ep), **_PRIV_FIELDS}
        path = _bind_last_id(ep.path, "obj_id") if "{" in ep.path else ep.path
        setup = []
        if "{" in ep.path:
            creator = registry.find_create(_resource_keyword(ep.path))
            if creator:
                setup = [TestStep(step=1, description="provision target object",
                                  method=creator.method, path=creator.path, identity=attacker,
                                  body=_dummy_body(creator), extract={"obj_id": "$.id"})]
        cases.append(TestCase(
            test_id=_tid(),
            vulnerability_class=VulnClass.MASS_ASSIGNMENT,
            hypothesis=(f"{ep.key}: privileged fields ({', '.join(list(_PRIV_FIELDS)[:4])}…) "
                        "are not stripped server-side (mass assignment)."),
            risk_rating=Severity.HIGH,
            affected_endpoint=ep.key,
            business_impact="Self-promotion to a higher role/tier or balance tampering.",
            setup_steps=setup,
            steps=[TestStep(step=2, description="Submit undocumented privileged fields",
                            method=ep.method, path=path, identity=attacker, body=body,
                            # Confirmed only if the server REFLECTS an injected field.
                            success_condition=("status in (200, 201) and ("
                                               "body.get('role') == 'admin' or "
                                               "body.get('is_admin') == True or "
                                               "body.get('tier') == 'premium')"))],
            rag_source="OWASP API3:2023 BOPLA",
        ))
    return cases


# ------------------------------------------------------------- 5. Param / type
_NUM_HINTS = ("amount", "price", "quantity", "qty", "total", "balance", "points", "count")


def param_pollution(registry: EndpointRegistry, identities) -> list[TestCase]:
    attacker, _ = _identities(identities)
    cases = []
    for ep in registry:
        if ep.method.upper() not in {"POST", "PUT", "PATCH"}:
            continue
        if _is_web_form(ep):       # web forms handled by web_playbooks
            continue
        numeric = [p for p in ep.parameters
                   if p.type in {"number", "integer"} or any(h in p.name.lower() for h in _NUM_HINTS)]
        if not numeric:
            continue
        p = numeric[0]
        cases.append(TestCase(
            test_id=_tid(),
            vulnerability_class=VulnClass.PARAM_POLLUTION,
            hypothesis=f"{ep.key}: '{p.name}' lacks server-side bounds (negative/zero/overflow).",
            risk_rating=Severity.HIGH,
            affected_endpoint=ep.key,
            business_impact=f"Manipulating '{p.name}' yields free goods or earned money.",
            steps=[
                TestStep(step=1, description=f"Negative {p.name}", method=ep.method,
                         path=ep.path, identity=attacker, body={**_dummy_body(ep), p.name: -50},
                         success_condition="status in (200, 201)"),
                TestStep(step=2, description=f"Zero {p.name}", method=ep.method,
                         path=ep.path, identity=attacker, body={**_dummy_body(ep), p.name: 0},
                         success_condition="status in (200, 201)"),
            ],
        ))
    return cases


# ------------------------------------------------------------- 6. Economic / rules
_CONVERT_HINTS = ("convert", "exchange", "redeem", "topup", "top-up", "cashout", "cash-out", "transfer")


def economic_abuse(graph: BusinessModelGraph, registry: EndpointRegistry, identities) -> list[TestCase]:
    """Round-trip an asymmetric economic flow through a REAL conversion endpoint
    discovered in the registry. If no such endpoint exists, emit nothing (no
    bogus placeholder paths)."""
    attacker, _ = _identities(identities)
    convert = registry.find_action(_CONVERT_HINTS)
    state = registry.find_state_read(_STATE_HINTS)
    if convert is None:
        return []
    probe = None
    if state:
        probe = TestStep(step=0, description="probe balance", method="GET",
                         path=state.path, identity=attacker, extract={"balance": "$.balance"})
    cases = []
    for flow in (graph.asymmetric_flows() or [None]):
        note = (flow.abuse_note if flow else "") or "Asymmetric round-trip / rounding gain."
        cases.append(TestCase(
            test_id=_tid(),
            vulnerability_class=VulnClass.ECONOMIC_ABUSE,
            hypothesis=(f"Round-trip conversion via {convert.key} yields net gain "
                        "(rate asymmetry / rounding)."),
            risk_rating=Severity.HIGH,
            affected_endpoint=convert.key,
            business_impact=note,
            state_probe=probe,
            steps=[
                TestStep(step=1, description="Convert forward", method=convert.method,
                         path=convert.path, identity=attacker, body=_dummy_body(convert)),
                TestStep(step=2, description="Convert back and measure net balance",
                         method=convert.method, path=convert.path, identity=attacker,
                         body=_dummy_body(convert),
                         success_condition="net_balance_delta > 0"),
            ],
        ))
    return cases


def faith_based_rules(graph: BusinessModelGraph, identities) -> list[TestCase]:
    attacker, _ = _identities(identities)
    cases = []
    for rule in graph.faith_based_rules():
        path = rule.attached_to.split(" ")[-1] if " " in rule.attached_to else "/"
        method = rule.attached_to.split(" ")[0] if " " in rule.attached_to else "POST"
        # A business-CONSTRAINT is violated by performing a forbidden ACTION (a
        # state-changing request), not by READING a page. A GET that returns 200 is
        # just a landing page rendering — never proof of a logic flaw — so skip it
        # rather than emit a guaranteed false positive. (Mutating faith-based rules
        # are still emitted; the runner's verdict gate records them as leads unless a
        # real state change / content proof corroborates them.)
        if method.upper() == "GET":
            continue
        cases.append(TestCase(
            test_id=_tid(),
            vulnerability_class=VulnClass.FAITH_BASED_RULE,
            hypothesis=(f"Documented rule '{rule.description}' ({rule.rule_type}) has no "
                        "visible server-side enforcement — attempt the forbidden action."),
            risk_rating=Severity.HIGH,
            affected_endpoint=rule.attached_to or "(unmapped)",
            business_impact=f"Violation of intended constraint: {rule.description}",
            steps=[TestStep(step=1, description=f"Perform action '{rule.rule_id}' should block",
                            method=method, path=_bind_last_id(path, "obj_id") if "{" in path else path,
                            identity=attacker, success_condition="status in (200, 201)")],
        ))
    return cases


def run_all(registry: EndpointRegistry, graph: BusinessModelGraph, identities=None) -> list[TestCase]:
    cases: list[TestCase] = []
    cases += sequence_bypass(registry, graph, identities)
    cases += faith_based_rules(graph, identities)
    cases += economic_abuse(graph, registry, identities)
    cases += bola_idor(registry, identities)
    cases += race_conditions(registry, identities)
    cases += mass_assignment(registry, identities)
    cases += param_pollution(registry, identities)
    return cases
