"""
Unified endpoint registry — the canonical view of the target's API surface,
merged from every ingestion source (OpenAPI, traffic, JS bundles, ...).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Heuristic keyword -> business-rule tag mapping used during risk scoring.
FINANCIAL_HINTS = (
    "refund", "payment", "pay", "charge", "wallet", "balance", "withdraw",
    "deposit", "transfer", "checkout", "order", "invoice", "credit", "coupon",
    "discount", "promo", "loyalty", "points", "reward", "referral", "subscription",
)
STATE_HINTS = ("status", "approve", "confirm", "cancel", "ship", "complete", "activate")
ADMIN_HINTS = ("admin", "internal", "manage", "role", "permission", "grant", "impersonate")


@dataclass
class Parameter:
    name: str
    location: str = "query"  # query | path | header | body
    type: str = "string"
    required: bool = False


@dataclass
class Endpoint:
    path: str
    method: str
    source: list[str] = field(default_factory=list)
    auth_required: bool = True
    roles_observed: list[str] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    state_preconditions: list[str] = field(default_factory=list)
    business_rule_tags: list[str] = field(default_factory=list)
    shadow_endpoint: bool = False
    deprecated: bool = False
    risk_tier: RiskTier = RiskTier.LOW
    form_defaults: dict = field(default_factory=dict)   # input name -> default value (web forms)
    discovered_on: str = ""                              # page path where a form was found

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"

    def tag(self) -> None:
        """Derive business_rule_tags and risk_tier from the path/method/params."""
        p = self.path.lower()
        tags = set(self.business_rule_tags)

        if any(h in p for h in FINANCIAL_HINTS):
            tags.add("financial")
        if any(h in p for h in STATE_HINTS) or self.method.upper() in {"PUT", "PATCH"}:
            tags.add("state_transition")
        if any(h in p for h in ADMIN_HINTS):
            tags.add("privileged")
        if "{" in self.path or any(pp.location == "path" for pp in self.parameters):
            tags.add("object_reference")  # IDOR/BOLA candidate
        if self.method.upper() == "POST" and "financial" in tags:
            tags.add("idempotency_risk")  # race-condition candidate
        if self.deprecated:
            tags.add("deprecated")
        if self.shadow_endpoint:
            tags.add("shadow")

        self.business_rule_tags = sorted(tags)
        self.risk_tier = self._score(tags)

    @staticmethod
    def _score(tags: set[str]) -> RiskTier:
        if {"financial", "idempotency_risk"} <= tags or "privileged" in tags:
            return RiskTier.CRITICAL
        if "financial" in tags or "object_reference" in tags or "shadow" in tags:
            return RiskTier.HIGH
        if "state_transition" in tags or "deprecated" in tags:
            return RiskTier.MEDIUM
        return RiskTier.LOW

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_tier"] = self.risk_tier.value
        return d


class EndpointRegistry:
    def __init__(self) -> None:
        self._endpoints: dict[str, Endpoint] = {}
        # Web-shop intelligence captured during discovery (minor units, e.g. pence).
        self.catalog: dict[str, int] = {}      # productId -> price
        self.store_credit: int | None = None   # buyer's available credit

    def __len__(self) -> int:
        return len(self._endpoints)

    def __iter__(self):
        return iter(self._endpoints.values())

    def add(self, ep: Endpoint) -> Endpoint:
        """Add or merge an endpoint (same method+path merges sources/roles)."""
        existing = self._endpoints.get(ep.key)
        if existing:
            existing.source = sorted(set(existing.source) | set(ep.source))
            existing.roles_observed = sorted(set(existing.roles_observed) | set(ep.roles_observed))
            existing.shadow_endpoint = existing.shadow_endpoint and ep.shadow_endpoint
            existing.deprecated = existing.deprecated or ep.deprecated
            if ep.parameters and not existing.parameters:
                existing.parameters = ep.parameters
            if ep.form_defaults and not existing.form_defaults:
                existing.form_defaults = ep.form_defaults
            if ep.discovered_on and not existing.discovered_on:
                existing.discovered_on = ep.discovered_on
            existing.state_preconditions = sorted(
                set(existing.state_preconditions) | set(ep.state_preconditions)
            )
            existing.tag()
            return existing
        ep.tag()
        self._endpoints[ep.key] = ep
        return ep

    def get(self, method: str, path: str) -> Endpoint | None:
        return self._endpoints.get(f"{method.upper()} {path}")

    def all(self) -> list[Endpoint]:
        return list(self._endpoints.values())

    def by_risk(self) -> list[Endpoint]:
        order = {RiskTier.CRITICAL: 0, RiskTier.HIGH: 1, RiskTier.MEDIUM: 2, RiskTier.LOW: 3}
        return sorted(self._endpoints.values(), key=lambda e: order[e.risk_tier])

    def with_tag(self, tag: str) -> list[Endpoint]:
        return [e for e in self._endpoints.values() if tag in e.business_rule_tags]

    def shadow(self) -> list[Endpoint]:
        return [e for e in self._endpoints.values() if e.shadow_endpoint]

    # --- relationship discovery (used to build concrete, runnable exploits) ---
    def find_create(self, keyword: str = "") -> "Endpoint | None":
        """POST to a collection (no path param) — i.e. a 'create' endpoint."""
        for e in self._endpoints.values():
            if e.method.upper() == "POST" and "{" not in e.path and keyword in e.path.lower():
                return e
        return None

    def find_get_by_id(self, keyword: str = "") -> "Endpoint | None":
        """GET on an object by id (path has a parameter)."""
        for e in self._endpoints.values():
            if e.method.upper() == "GET" and "{" in e.path and keyword in e.path.lower():
                return e
        return None

    def find_action(self, keywords: tuple[str, ...]) -> "Endpoint | None":
        """A state/financial mutation (POST/PUT/PATCH) matching any keyword."""
        for e in self._endpoints.values():
            if e.method.upper() in {"POST", "PUT", "PATCH"} and any(k in e.path.lower() for k in keywords):
                return e
        return None

    def find_state_read(self, keywords: tuple[str, ...]) -> "Endpoint | None":
        """A GET that exposes a balance/counter (state probe target)."""
        for e in self._endpoints.values():
            if e.method.upper() == "GET" and any(k in e.path.lower() for k in keywords):
                return e
        return None

    def to_dict(self) -> dict:
        return {
            "count": len(self._endpoints),
            "endpoints": [e.to_dict() for e in self.by_risk()],
        }
