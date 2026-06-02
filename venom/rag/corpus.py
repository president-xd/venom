"""
Built-in business-logic vulnerability writeup corpus. Compact, curated summaries
keyed by vulnerability class. Extend at runtime via VENOM_DATA_DIR/rag/corpus.json
(same shape: list of {title, vuln_class, keywords, technique, reference}).
"""

from __future__ import annotations

BUILTIN_CORPUS: list[dict] = [
    {
        "title": "Race condition in coupon redemption allowed unlimited discounts",
        "vuln_class": "RACE_CONDITION",
        "keywords": "coupon discount redeem concurrent parallel balance points wallet limit",
        "technique": "Fire N concurrent redeem requests before the usage counter commits (TOCTOU).",
        "reference": "HackerOne #157996 (Shopify gift-card race)",
    },
    {
        "title": "Concurrent withdrawal requests drained wallet below zero",
        "vuln_class": "RACE_CONDITION",
        "keywords": "withdraw wallet balance negative transfer concurrent double-spend",
        "technique": "20 parallel withdrawals share one balance read; final balance goes negative.",
        "reference": "OWASP WSTG-BUSL-09; PortSwigger race-conditions labs",
    },
    {
        "title": "BOLA: order id enumeration exposed other tenants' invoices",
        "vuln_class": "BOLA_IDOR",
        "keywords": "order invoice id idor bola tenant ownership object reference",
        "technique": "Authenticate as low-priv user, swap object id for a victim's id; no ownership check.",
        "reference": "OWASP API1:2023; HackerOne #2730746",
    },
    {
        "title": "GraphQL nested resolver leaked private user nodes",
        "vuln_class": "BOLA_IDOR",
        "keywords": "graphql node id resolver nested idor user account",
        "technique": "Query node(id:) for a victim's global id; resolver skips per-object authz.",
        "reference": "GraphQL IDOR — HackerOne GitLab reports",
    },
    {
        "title": "Mass assignment of is_admin during profile update",
        "vuln_class": "MASS_ASSIGNMENT",
        "keywords": "mass assignment role is_admin tier privilege update profile fields",
        "technique": "Add undocumented role/is_admin fields to an update body; server binds them.",
        "reference": "OWASP API3:2023 BOPLA; classic Rails mass-assignment",
    },
    {
        "title": "Negative quantity in cart produced a credit instead of a charge",
        "vuln_class": "PARAM_POLLUTION",
        "keywords": "negative quantity amount price refund credit checkout integer bounds",
        "technique": "Set amount/quantity negative; total underflows and credits the buyer.",
        "reference": "WSTG-BUSL-01; numerous bug-bounty disclosures",
    },
    {
        "title": "Refund issued on unshipped order by skipping the shipment state",
        "vuln_class": "SEQUENCE_VIOLATION",
        "keywords": "refund shipped state machine sequence transition order skip precondition",
        "technique": "Call /refund directly on a 'paid' order; the 'shipped' precondition is unenforced.",
        "reference": "WSTG-BUSL-06; state-machine abuse writeups",
    },
    {
        "title": "Referral self-referral bonus farmed for free credit",
        "vuln_class": "ECONOMIC_ABUSE",
        "keywords": "referral bonus self credit points economic loop conversion reward",
        "technique": "Refer your own secondary account; relational rule (no self-refer) unenforced.",
        "reference": "WSTG-BUSL-02; loyalty-abuse disclosures",
    },
    {
        "title": "Points<->cash asymmetry enabled an infinite-money round-trip",
        "vuln_class": "ECONOMIC_ABUSE",
        "keywords": "points cash conversion rate asymmetry rounding loyalty arbitrage",
        "technique": "Convert cash->points->cash exploiting rounding/rate asymmetry for net gain.",
        "reference": "Economic-flow abuse case studies",
    },
    {
        "title": "Coupon stacking bypassed one-per-customer rule",
        "vuln_class": "FAITH_BASED_RULE",
        "keywords": "coupon promo uniqueness one per customer faith based unenforced rule",
        "technique": "Apply the same single-use promo twice; UNIQUE(user,promo) constraint missing.",
        "reference": "WSTG-BUSL-07",
    },
]
