"""
Business-logic vulnerability knowledge base.

Curated from OWASP WSTG §4.10 (Business Logic Testing) and PortSwigger's
"Examples of business logic vulnerabilities". This is used as *priors* for the
reasoning agent — not as rigid playbooks. Each entry tells the agent what to look
for (signals), how to probe cheaply, and the shape of the exploit — so it can
reason about a target it has never seen rather than only matching coded patterns.

Sources:
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
  https://portswigger.net/web-security/logic-flaws/examples
"""

from __future__ import annotations

# Each: id, name, where it lives, signals to look for, a cheap probe, the exploit idea.
BUSINESS_LOGIC_KB: list[dict] = [
    {
        "id": "client-side-trust",
        "name": "Excessive trust in client-side controls",
        "signals": ["price/amount/total in a request body or hidden form field",
                    "values that should be server-authoritative sent by the client"],
        "probe": "Submit the form/request with the price (or other server-owned value) changed.",
        "exploit": "Set the client-supplied price to a tiny value, then complete checkout.",
        "refs": ["PortSwigger: Excessive trust in client-side controls", "WSTG-BUSL-01"],
    },
    {
        "id": "unconventional-input",
        "name": "Failing to handle unconventional input",
        "signals": ["numeric fields (quantity, amount, points)", "no visible server bounds"],
        "probe": "Send negative, zero, very large, fractional, or string-typed values.",
        "exploit": "Negative quantity/price deflates a total; overflow wraps a total; "
                   "balance the cart with a negative-quantity cheap item to afford an expensive one.",
        "refs": ["PortSwigger: Failing to handle unconventional input", "WSTG-BUSL-01"],
    },
    {
        "id": "trust-decay",
        "name": "Trusted users won't always remain trustworthy",
        "signals": ["a control enforced only at one step (e.g. registration) but not later",
                    "role/tier/email checked once, then trusted"],
        "probe": "Repeat or revisit a privileged action after the initial check.",
        "exploit": "Use a later, laxly-enforced endpoint to change something the first check guarded.",
        "refs": ["PortSwigger: Trusted users won't always remain trustworthy"],
    },
    {
        "id": "mandatory-input-removed",
        "name": "Users won't always supply mandatory input",
        "signals": ["required params/fields", "multi-field forms"],
        "probe": "Remove a parameter entirely (not just blank it) and resubmit.",
        "exploit": "Dropping a field reaches an unintended code path / skips validation.",
        "refs": ["PortSwigger: Users won't always supply mandatory input"],
    },
    {
        "id": "sequence-bypass",
        "name": "Users won't always follow the intended sequence",
        "signals": ["multi-step flow (cart→checkout, register→verify→use, 2FA)",
                    "state-changing endpoints reachable directly",
                    "a confirmation/success endpoint gated only by a query flag "
                    "(e.g. order-confirmation?order-confirmed=true)"],
        "probe": "Call a later step directly, or out of order, skipping a prior step; "
                 "GET the order-confirmation endpoint with its success flag set.",
        "exploit": "Skip payment/shipment/2FA/verification by jumping to the next-state endpoint; "
                   "add an unaffordable item then hit order-confirmation directly to finalize it "
                   "without the funds/payment check.",
        "refs": ["PortSwigger: insufficient workflow validation", "WSTG-BUSL-06"],
    },
    {
        "id": "domain-specific",
        "name": "Domain-specific flaws (discounts, loyalty, referrals)",
        "signals": ["discount thresholds, coupons, loyalty points, referral bonuses"],
        "probe": "Meet a threshold then change the order; redeem/refer in unexpected ways.",
        "exploit": "Qualify for a discount then remove items; self-refer; stack single-use coupons.",
        "refs": ["PortSwigger: Domain-specific flaws", "WSTG-BUSL-02/07"],
    },
    {
        "id": "infinite-money",
        "name": "Infinite money (gift-card / store-credit arbitrage)",
        "signals": ["a reusable discount coupon (often via newsletter sign-up)",
                    "a gift card / store-credit product that can be bought then redeemed",
                    "redeemed value > discounted purchase price"],
        "probe": "Buy a gift card with the coupon applied (pay < face value); redeem it and "
                 "check whether store credit rises by more than you spent.",
        "exploit": "Each cycle nets (face - discounted_price) credit; buy gift cards in bulk "
                   "within current credit and redeem, growing credit until the target is affordable.",
        "refs": ["PortSwigger: Infinite money logic flaw", "WSTG-BUSL-02"],
    },
    {
        "id": "idor-bola",
        "name": "Broken object-level authorization (IDOR/BOLA)",
        "signals": ["object id/username in URL, query, or body (e.g. ?id=2)",
                    "per-user resources; sequential or guessable identifiers"],
        "probe": "Swap your object id/username for another user's (try id=1, id=administrator) "
                 "and request it; read the FULL response body for fields you shouldn't see.",
        "exploit": "Request another user's object (e.g. GET /api/account?id=1 — pass it via "
                   "params={'id':'1'}, NOT data). Their response often leaks a secret "
                   "(api_key, token, reset code): extract() it from the response text and reuse it "
                   "in the privileged action (header or body) to act as them.",
        "refs": ["OWASP API1:2023"],
    },
    {
        "id": "secret-in-response",
        "name": "Sensitive value disclosed in a response, then reused",
        "signals": ["a token / api_key / reset code / OTP echoed in an HTTP response or JSON",
                    "a 'debug' field, an account/profile read, a password-reset request"],
        "probe": "Read the body of every step; password-reset/request and account reads often "
                 "DISCLOSE the secret that a later step trusts.",
        "exploit": "extract() the disclosed token from the response, then submit it to the "
                   "confirm/use endpoint (e.g. POST /reset/confirm with the leaked token to set a "
                   "victim's password), then login() as the victim and use their privileges.",
        "refs": ["OWASP API3:2023 (Excessive Data Exposure)", "WSTG-ATHN-09"],
    },
    {
        "id": "jwt-alg-none",
        "name": "JWT algorithm confusion / unsecured 'none' token",
        "signals": ["auth via a JSON Web Token in an Authorization: Bearer header or a cookie",
                    "JWT claims include role/user/admin"],
        "probe": "Decode the JWT (base64url of header.payload.sig). Forge a NEW token whose "
                 "header alg is 'none' (no signature) with your desired claims.",
        "exploit": "Build header={'alg':'none','typ':'JWT'}, payload with role=administrator, "
                   "join base64url(header)+'.'+base64url(payload)+'.' (empty signature), and send it "
                   "as Authorization: Bearer <token>. Servers that honor alg:none accept the unsigned, "
                   "attacker-controlled claims. (Do NOT need the HS256 secret.)",
        "refs": ["OWASP API2:2023", "PortSwigger: JWT attacks (alg:none)"],
    },
    {
        "id": "missing-rate-limit",
        "name": "Missing rate limit / lockout on a short secret (brute force)",
        "signals": ["a short secret gates an action: 4-digit PIN, OTP, 2FA code, voucher",
                    "no lockout / no attempt counter mentioned"],
        "probe": "Submit a couple of wrong values — if there is no lockout, the field is brute-able.",
        "exploit": "Loop over the full keyspace (e.g. for n in range(10000): pin=str(n).zfill(4)) "
                   "calling the verify endpoint until the response indicates success, then proceed "
                   "to the gated privileged action in the SAME session.",
        "refs": ["OWASP API4:2023", "WSTG-ATHN-03"],
    },
    {
        "id": "integer-overflow",
        "name": "Integer overflow / wraparound on a total or balance",
        "signals": ["a total computed as price*quantity (or sum) with no upper bound",
                    "the server echoes the computed total; large inputs accepted"],
        "probe": "Send a large quantity and read the echoed total — if it goes negative or tiny, "
                 "the total wraps a fixed-width integer.",
        "exploit": "Find a quantity that wraps the total into an affordable/zero/negative value: use "
                   "the pre-imported find_overflow_qty(price) (searches qty where price*qty wraps a "
                   "32-bit int into [0,100]), then buy with that quantity.",
        "refs": ["PortSwigger: Failing to handle unconventional input", "WSTG-BUSL-01"],
    },
    {
        "id": "bfla-access-control",
        "name": "Broken function-level authorization (forced browsing)",
        "signals": ["admin/manage/internal/staff paths", "privileged actions"],
        "probe": "As a low-privileged user, request privileged URLs directly.",
        "exploit": "Reach admin/management functionality without authorization.",
        "refs": ["OWASP API5:2023", "WSTG-ATHZ-01"],
    },
    {
        "id": "mass-assignment",
        "name": "Mass assignment / BOPLA",
        "signals": ["create/update endpoints", "objects with role/tier/balance fields"],
        "probe": "Add undocumented privileged fields (role, is_admin, tier, balance) to the body.",
        "exploit": "Server binds the extra fields → self-promotion or balance tampering.",
        "refs": ["OWASP API3:2023"],
    },
    {
        "id": "race-condition",
        "name": "Race condition on a limited resource",
        "signals": ["non-idempotent action on a balance/counter/limit",
                    "redeem/withdraw/claim/apply once-only"],
        "probe": "Fire the same request many times concurrently; check the final state.",
        "exploit": "Double-spend / over-redeem before the counter commits (TOCTOU).",
        "refs": ["WSTG-BUSL-09"],
    },
    {
        "id": "encryption-oracle",
        "name": "Providing an encryption oracle",
        "signals": ["user-controlled input is encrypted and the ciphertext returned to the user"],
        "probe": "Feed chosen plaintext, observe ciphertext; reuse it in another field.",
        "exploit": "Encrypt attacker-chosen data for use where the app trusts its own ciphertext.",
        "refs": ["PortSwigger: encryption oracle"],
    },
    {
        "id": "email-parser-discrepancy",
        "name": "Email address parser discrepancies",
        "signals": ["domain-restricted signup/verification (only @company allowed)",
                    "validator accepts RFC 2047 encoded-words in the email"],
        "probe": "Keep the literal domain @company (validator passes) but put an encoded-word "
                 "local part the MAILER decodes+re-parses; check if mail reaches your inbox.",
        "exploit": "UTF-7 atom split: =?utf-7?q?you&AEA-<your-inbox>&ACA-?=@company — validator "
                   "reads @company, mailer decodes '@'(&AEA-)+space(&ACA-) and delivers to your "
                   "inbox, so you register a privileged @company account you actually control.",
        "refs": ["PortSwigger: email parser discrepancies", "Splitting the email atom (Gareth Heyes)"],
    },
    {
        "id": "exceptional-input-truncation",
        "name": "Inconsistent handling of exceptional input (length truncation)",
        "signals": ["registration/profile email that gates privilege by domain",
                    "a privileged company/staff domain mentioned on the site (e.g. an admin contact)",
                    "fixed-width storage (often 255 chars) that may silently truncate"],
        "probe": "Register with an over-long email whose local part is padded so the FULL "
                 "address is a deliverable subdomain of your own inbox, but the string truncated "
                 "to the storage limit ends exactly at '@<privileged-domain>'.",
        "exploit": "Pad the local part to (limit - len('@'+priv_domain)) chars, then append "
                   "'@<priv_domain>.<your-inbox-domain>'. The mailer uses the full address "
                   "(confirmation arrives in your inbox); the app stores the truncated value and "
                   "treats you as belonging to the privileged domain → admin access.",
        "refs": ["PortSwigger: Inconsistent handling of exceptional input", "WSTG-BUSL-03"],
    },
    {
        "id": "login-state-machine",
        "name": "Flawed login state machine (skip a step → privileged default)",
        "signals": ["multi-step login (POST /login redirects to a second step like "
                    "/role-selector, /mfa, /select-role)",
                    "a privileged page reachable right after step 1"],
        "probe": "Complete only login step 1, then request the privileged page directly "
                 "WITHOUT visiting the intermediate step (which may downgrade your role).",
        "exploit": "The session's default role before the second step is privileged: after "
                   "POST /login go straight to /admin (never touch the role-selector) to act as admin.",
        "refs": ["PortSwigger: Authentication bypass via flawed state machine", "WSTG-ATHN-09"],
    },
    {
        "id": "trusted-identity-param",
        "name": "Flawed privilege assumption from a trusted identity parameter",
        "signals": ["account-management action (change-password / change-email / delete) that "
                    "carries the account owner as a request field (hidden 'username'/'id')",
                    "a verification step (current-password, token) that can be omitted or skipped"],
        "probe": "Replay the action with the identity field set to another account (e.g. "
                 "'administrator') and try dropping the verification field entirely.",
        "exploit": "Server acts on the attacker-supplied identity instead of the session owner: "
                   "set username=administrator and OMIT current-password to overwrite the admin's "
                   "password, then log in as admin and use privileged functions (delete users).",
        "refs": ["PortSwigger: flawed account-management logic",
                 "OWASP API1:2023 (BOLA)", "WSTG-ATHZ-02"],
    },
]


import re as _re

_TOK = _re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return {t for t in _TOK.findall((text or "").lower()) if len(t) > 2}


def rank_kb(surface: str, top: int = 6) -> list[dict]:
    """Rank KB priors by overlap with the observed surface — so the prompt is
    STEERED toward what the target actually exposes instead of dumping all classes
    (which makes weak models anchor on the wrong one)."""
    q = _tokens(surface)
    if not q:
        return list(BUSINESS_LOGIC_KB)[:top]
    scored = []
    for k in BUSINESS_LOGIC_KB:
        hay = _tokens(" ".join(k["signals"]) + " " + k["name"] + " " + k.get("probe", "") +
                      " " + k.get("exploit", ""))
        scored.append((len(q & hay), k))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [k for _, k in scored[:top]]


def kb_prompt(limit: int | None = None, surface: str = "") -> str:
    """Compact KB rendering for an LLM prompt. With `surface`, only the most
    relevant priors are included (ranked), keeping the prompt focused and cheap."""
    if surface:
        items = rank_kb(surface, top=limit or 6)
    else:
        items = BUSINESS_LOGIC_KB[: limit or len(BUSINESS_LOGIC_KB)]
    lines = []
    for k in items:
        lines.append(f"- {k['id']} ({k['name']}): signals={'; '.join(k['signals'])}. "
                     f"probe={k['probe']} exploit={k['exploit']}")
    return "\n".join(lines)
