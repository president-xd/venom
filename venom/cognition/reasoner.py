"""
The reasoning loop. Bounded, scope-guarded, budget-aware.

    observe → decide (brain) → act (scoped HTTP) → observe response → re-decide …
    → verify exploit → record finding

`decide(observation, history) -> Action` is injected: an LLM brain in production
(see llm_brain.py), a deterministic stub in tests. Every request still goes
through the scope guard and rate limiter; responses are compacted before they
re-enter the observation so free-tier context limits are respected.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, fields as _fields
from itertools import count

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..llm.budget import compact_html, trim
from ..testing.schema import TestCase, TestStep, VulnClass, Severity, Verdict

logger = logging.getLogger("venom.cognition")
_counter = count(1)

_VC = {v.value: v for v in VulnClass}
_WIN = ("is-solved", "congratulations", "you solved", "order placed", "order confirmed",
        "thank you for your purchase")


def _vclass(name: str) -> VulnClass:
    return _VC.get((name or "").upper(), VulnClass.STATE_BYPASS)


@dataclass
class Action:
    type: str = "conclude"           # "probe" | "exploit" | "conclude"
    method: str = "GET"
    path: str = "/"
    form: dict | None = None         # form-encoded body
    json: dict | None = None         # JSON body
    identity: str | None = None
    follow_redirects: bool = True
    rationale: str = ""
    success_signal: str = ""         # substring proving the exploit, if present
    vuln_class: str = "PARAM_POLLUTION"
    title: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Action":
        known = {f.name for f in _fields(cls)}
        return cls(**{k: v for k, v in (d or {}).items() if k in known})


class Reasoner:
    def __init__(self, scope: Scope, decide, *, transport=None, max_steps: int = 12,
                 identities: list[str] | None = None):
        self.scope = scope
        self.decide = decide
        self.transport = transport
        self.max_steps = max_steps
        self.auth = AuthManager(scope, dry_run=False, transport=transport)
        self._limiter = RateLimiter(scope.rate_limit_per_second)
        self._clients: dict[str, ScopedClient] = {}
        names = identities or [i.get("name") for i in scope.identities if i.get("name")]
        self.default_identity = names[0] if names else None

    async def _client(self, identity: str | None) -> ScopedClient:
        identity = identity or self.default_identity
        key = identity or "anon"
        if key not in self._clients:
            c = ScopedClient(self.scope, self.scope.authorized_base_urls[0],
                             role=f"reasoner:{key}", limiter=self._limiter, transport=self.transport)
            if self.auth.has(identity):
                c.apply_auth(await self.auth.ensure(identity))  # type: ignore[arg-type]
            self._clients[key] = c
        return self._clients[key]

    async def _execute(self, action: Action):
        c = await self._client(action.identity)
        return await c.request(action.method, action.path, json=action.json, data=action.form,
                               follow_redirects=action.follow_redirects)

    def _initial_observation(self, registry) -> dict:
        eps = []
        for e in registry.by_risk()[:40]:
            item = {"method": e.method, "path": e.path, "tags": e.business_rule_tags}
            if e.form_defaults:
                item["form_defaults"] = e.form_defaults
            eps.append(item)
        return {
            "target": self.scope.target_name,
            "base": self.scope.authorized_base_urls[0],
            "identities": [i.get("name") for i in self.scope.identities],
            "endpoints": eps,
            "catalog": registry.catalog,
            "store_credit": registry.store_credit,
            "history": [],
        }

    async def investigate(self, registry, *, observation: dict | None = None) -> list[TestCase]:
        obs = observation or self._initial_observation(registry)
        history: list[dict] = []
        findings: list[TestCase] = []
        try:
            for i in range(self.max_steps):
                action = await self.decide(obs, history)
                if not action or action.type == "conclude":
                    break
                try:
                    resp = await self._execute(action)
                except ScopeError as exc:
                    history.append({"step": i + 1, "path": action.path, "blocked": str(exc)})
                    obs["history"] = history[-6:]
                    continue
                status = getattr(resp, "status_code", None)
                text = resp.text if resp is not None else ""
                history.append({
                    "step": i + 1, "type": action.type, "method": action.method,
                    "path": action.path, "status": status,
                    "rationale": trim(action.rationale, 200), "view": compact_html(text),
                })
                obs["history"] = history[-6:]      # bounded recent context (budget)
                if action.type == "exploit" and self._won(action, text):
                    findings.append(self._finding(action, history))
                    break                          # stop on first confirmed win to save budget
        finally:
            await self._close()
        logger.info("Reasoner finished: %d step(s), %d finding(s)", len(history), len(findings))
        return findings

    @staticmethod
    def _won(action: Action, text: str) -> bool:
        low = (text or "").lower()
        if action.success_signal and action.success_signal.lower() in low:
            return True
        return any(w in low for w in _WIN)

    def _finding(self, action: Action, history: list[dict]) -> TestCase:
        steps = [TestStep(step=h.get("step", n + 1),
                          description=(h.get("rationale") or h.get("type") or "step"),
                          method=h.get("method", "GET"), path=h.get("path", "/"),
                          actual_status=h.get("status"))
                 for n, h in enumerate(history)]
        return TestCase(
            test_id=f"RSN-{next(_counter):03d}",
            vulnerability_class=_vclass(action.vuln_class),
            hypothesis=action.title or action.rationale or "Reasoned business-logic exploit",
            risk_rating=Severity.HIGH,
            affected_endpoint=f"{action.method} {action.path}",
            business_impact="Business-logic exploit discovered by adaptive reasoning and confirmed.",
            steps=steps,
            origin="reasoner",
            verdict=Verdict.CONFIRMED_EXPLOIT,
            notes=[f"Reasoned over {len(history)} step(s); confirmed via response signal."],
        )

    async def _close(self) -> None:
        for c in self._clients.values():
            await c.aclose()
