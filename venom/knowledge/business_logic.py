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
                    "state-changing endpoints reachable directly"],
        "probe": "Call a later step directly, or out of order, skipping a prior step.",
        "exploit": "Skip payment/shipment/2FA/verification by jumping to the next-state endpoint.",
        "refs": ["PortSwigger: intended sequence", "WSTG-BUSL-06"],
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
        "id": "idor-bola",
        "name": "Broken object-level authorization (IDOR/BOLA)",
        "signals": ["object id/username in URL, query, or body", "per-user resources"],
        "probe": "Swap your object id/username for another user's and request it.",
        "exploit": "Read/modify another tenant's order, account, invoice, or wallet.",
        "refs": ["OWASP API1:2023"],
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
        "signals": ["domain-restricted signup/verification", "email normalization"],
        "probe": "Use encoding/sub-addressing tricks so the validator and mailer disagree.",
        "exploit": "Bypass domain allow-lists to register/verify as a privileged domain.",
        "refs": ["PortSwigger: email parser discrepancies"],
    },
]


def kb_prompt(limit: int | None = None) -> str:
    """Compact, token-cheap rendering of the KB for an LLM reasoning prompt."""
    items = BUSINESS_LOGIC_KB[: limit or len(BUSINESS_LOGIC_KB)]
    lines = []
    for k in items:
        lines.append(f"- {k['id']} ({k['name']}): signals={'; '.join(k['signals'])}. "
                     f"probe={k['probe']} exploit={k['exploit']}")
    return "\n".join(lines)
