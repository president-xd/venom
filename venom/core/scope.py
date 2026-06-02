"""
Authorization scope — the hard safety boundary for the entire agent.

Per the CIPHER system prompt, the scope object is the FIRST thing loaded before
any action, and these rules are non-negotiable:

  - Never send a request to a host not in `authorized_base_urls`.
  - Never exceed `rate_limit_per_second`.
  - Never perform destructive actions unless `allow_destructive` is true.
  - Never act after `expiry_date`.
  - Always attach `X-Pentest-ID: <engagement_id>` to every request.

Enforcement lives here and is invoked by the HTTP client on every request. There
is intentionally no bypass flag.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when an action would violate the authorized engagement scope."""


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    # Accept trailing 'Z' (UTC) which fromisoformat historically rejected.
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class Scope:
    engagement_id: str
    target_name: str
    authorized_base_urls: list[str]
    authorized_user_roles: list[str] = field(default_factory=list)
    # Authenticated test identities. Each: {"name","role","auth":{...}} — see
    # venom.engine.auth.Identity for the supported auth types (login/bearer/cookie/basic).
    identities: list[dict] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    rate_limit_per_second: float = 5.0
    allow_destructive: bool = False
    allow_pii_capture: bool = False     # if False, PII is redacted from evidence/logs
    # Account-lifecycle flow (registration + email verification):
    email_client_url: str = ""          # inbox URL to read confirmation links from
    privileged_email_domain: str = ""   # company/staff domain (else scraped from /register)
    objective_delete_user: str = ""     # opt-in destructive objective (needs allow_destructive)
    authorized_by: str = ""
    authorization_date: str | None = None
    expiry_date: str | None = None
    burp_mcp_enabled: bool = False
    air_gap_mode: bool = False
    llm_mode: str = "default"
    # Live discovery (web-app mode). e.g. {"enabled": true, "seeds": ["/"],
    # "max_pages": 60, "forced_browse": true}
    discovery: dict = field(default_factory=dict)
    # Agent objective / win-oracle. e.g. {"description":"buy the jacket",
    # "win_url":"/", "win_signals":["is-solved"]}
    objective: dict = field(default_factory=dict)

    # --------------------------------------------------------------- loading
    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        required = ("engagement_id", "target_name", "authorized_base_urls")
        missing = [k for k in required if not data.get(k)]
        if missing:
            raise ScopeError(f"Scope is missing required field(s): {', '.join(missing)}")
        if not isinstance(data["authorized_base_urls"], list) or not data["authorized_base_urls"]:
            raise ScopeError("authorized_base_urls must be a non-empty list")
        known = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in known})

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        path = Path(path)
        if not path.exists():
            raise ScopeError(f"Scope file not found: {path}")
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    # --------------------------------------------------------------- checks
    def is_expired(self, now: datetime | None = None) -> bool:
        expiry = _parse_iso(self.expiry_date)
        if expiry is None:
            return False
        return (now or datetime.now(timezone.utc)) > expiry

    def validate_window(self) -> None:
        """Confirm we're inside the authorized time window."""
        now = datetime.now(timezone.utc)
        start = _parse_iso(self.authorization_date)
        if start and now < start:
            raise ScopeError(
                f"Engagement {self.engagement_id} has not started yet "
                f"(authorization_date={self.authorization_date})"
            )
        if self.is_expired(now):
            raise ScopeError(
                f"Engagement {self.engagement_id} expired on {self.expiry_date}. "
                "Testing must stop."
            )

    def _host_matches(self, candidate: str, authorized: str) -> bool:
        c = urlparse(candidate if "://" in candidate else f"//{candidate}")
        a = urlparse(authorized if "://" in authorized else f"//{authorized}")
        if a.scheme and c.scheme and a.scheme != c.scheme:
            return False
        if (c.hostname or "").lower() != (a.hostname or "").lower():
            return False
        if (c.port or 0) != (a.port or 0) and a.port:
            return False
        # Path prefix: authorized "/api" gates everything under it; "/" gates all.
        a_path = a.path.rstrip("/")
        if a_path and not c.path.startswith(a_path):
            return False
        return True

    def is_url_in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        for blocked in self.out_of_scope:
            blocked_host = (urlparse(blocked if "://" in blocked else f"//{blocked}").hostname
                            or blocked).lower()
            if blocked_host and (host == blocked_host or host.endswith("." + blocked_host)):
                return False
        return any(self._host_matches(url, base) for base in self.authorized_base_urls)

    DESTRUCTIVE_METHODS = {"DELETE", "PUT", "PATCH"}

    def assert_request_allowed(self, method: str, url: str, *, destructive: bool = False) -> None:
        """The single chokepoint. Raises ScopeError if the request is not allowed."""
        self.validate_window()
        if not self.is_url_in_scope(url):
            raise ScopeError(
                f"OUT OF SCOPE: {method} {url} is not within authorized_base_urls "
                f"{self.authorized_base_urls} (or is explicitly out_of_scope). Request blocked."
            )
        if destructive and not self.allow_destructive:
            raise ScopeError(
                f"DESTRUCTIVE action blocked: {method} {url}. "
                "Set allow_destructive=true in the scope to permit this."
            )

    def pentest_header(self) -> dict[str, str]:
        return {"X-Pentest-ID": self.engagement_id}

    def summary(self) -> str:
        return (
            f"Engagement {self.engagement_id} — target '{self.target_name}'\n"
            f"  Authorized hosts : {', '.join(self.authorized_base_urls)}\n"
            f"  Out of scope     : {', '.join(self.out_of_scope) or '(none)'}\n"
            f"  Roles            : {', '.join(self.authorized_user_roles) or '(none)'}\n"
            f"  Rate limit       : {self.rate_limit_per_second} req/s\n"
            f"  Destructive ops  : {'ALLOWED' if self.allow_destructive else 'blocked'}\n"
            f"  Authorized by    : {self.authorized_by or '(unspecified)'}\n"
            f"  Window           : {self.authorization_date or '?'} -> {self.expiry_date or '?'}\n"
            f"  Air-gap mode     : {self.air_gap_mode}"
        )
