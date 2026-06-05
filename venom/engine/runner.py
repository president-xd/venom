"""
Test runner — executes TestCase objects against an authorized target.

Capabilities that make findings real (not just request shapes):

  - Authenticated, isolated sessions per identity (AuthManager), with automatic
    re-login + single retry on 401/403.
  - Provisioning: `setup_steps` create prerequisites (e.g. an order owned by the
    victim) and extract their ids into shared variables.
  - State-delta confirmation: an optional `state_probe` GET is run BEFORE and
    AFTER the attack; numeric deltas (balances/counters) are exposed to success
    conditions as `<var>_before/_after/_delta` and `net_balance_delta`.
  - True concurrency for race tests: burst steps fire with the rate limiter
    bypassed, then are confirmed by final state — not by 2xx count.
  - Evidence capture: request summaries, statuses, response excerpts, and the
    before/after state are attached to the case.

In dry-run nothing is sent; every case is reported NOT_RUN.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from ..core.scope import Scope, ScopeError
from ..utils import jsonpath, safe_eval, coerce_number, regex_extract, redact
from .auth import AuthManager
from .http_client import RateLimiter, ScopedClient
from ..testing.schema import TestCase, TestStep, Verdict

logger = logging.getLogger("venom.engine.runner")

_VAR = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
_BALANCE_HINTS = ("balance", "points", "credit", "amount", "total", "count", "quota")


class TestRunner:
    __test__ = False  # not a pytest test class

    def __init__(self, scope: Scope, *, dry_run: bool = False, transport=None,
                 burp=None):
        self.scope = scope
        self.dry_run = dry_run
        self._transport = transport
        self.base_url = scope.authorized_base_urls[0]
        self._limiter = RateLimiter(scope.rate_limit_per_second)
        self._clients: dict[str, ScopedClient] = {}
        self.auth = AuthManager(scope, dry_run=dry_run, transport=transport)
        self.burp = burp  # optional BurpExecutor for routing/OOB (see integrations)

    # ------------------------------------------------------------- sessions
    async def _client_for(self, identity: str | None) -> ScopedClient:
        key = identity or "default"
        if key not in self._clients:
            c = ScopedClient(self.scope, self.base_url, role=key,
                             limiter=self._limiter, dry_run=self.dry_run,
                             transport=self._transport)
            if self.auth.has(identity):
                c.apply_auth(await self.auth.ensure(identity))  # type: ignore[arg-type]
            self._clients[key] = c
        return self._clients[key]

    @staticmethod
    def _subst(value, variables: dict):
        if isinstance(value, str):
            return _VAR.sub(lambda m: str(variables.get(m.group(1), m.group(0))), value)
        if isinstance(value, dict):
            return {k: TestRunner._subst(v, variables) for k, v in value.items()}
        if isinstance(value, list):
            return [TestRunner._subst(v, variables) for v in value]
        return value

    # ------------------------------------------------------------- step exec
    async def _send(self, client: ScopedClient, step: TestStep, path, body, form):
        """Single request (JSON or form-encoded) with one auth-refresh retry."""
        kw = dict(params=step.query, headers=step.headers, destructive=step.destructive,
                  rate_limited=step.rate_limited, follow_redirects=step.follow_redirects)
        resp = await client.request(step.method, path, json=body, data=form, **kw)
        if (resp is not None and resp.status_code in (401, 403)
                and self.auth.has(step.who)):
            state = await self.auth.refresh(step.who)  # type: ignore[arg-type]
            client.apply_auth(state)
            resp = await client.request(step.method, path, json=body, data=form, **kw)
        return resp

    async def _exec_step(self, step: TestStep, variables: dict) -> dict:
        client = await self._client_for(step.who)
        path = self._subst(step.path, variables)
        body = self._subst(step.body, variables) if step.body is not None else None
        form = self._subst(step.form, variables) if step.form is not None else None
        step.request_summary = f"{step.method} {path}" + (f" as {step.who}" if step.who else "")
        allow_pii = self.scope.allow_pii_capture

        # --- concurrency burst (race) -------------------------------------
        if step.concurrency > 1:
            await self._limiter.acquire()  # one polite slot, then fire all at once
            tasks = [client.request(step.method, path, json=body, data=form, params=step.query,
                                    headers=step.headers, destructive=step.destructive,
                                    rate_limited=False, follow_redirects=step.follow_redirects)
                     for _ in range(step.concurrency)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            statuses = [r.status_code for r in responses if hasattr(r, "status_code")]
            results_2xx = sum(1 for s in statuses if 200 <= s < 300)
            step.actual_status = statuses[0] if statuses else None
            step.response_excerpt = f"{len(statuses)}x fired; statuses={statuses}"
            return {"status": step.actual_status, "results_2xx": results_2xx,
                    "statuses": statuses, "body": {}, "text": "", "concurrency": step.concurrency}

        # --- single request -----------------------------------------------
        resp = await self._send(client, step, path, body, form)
        if resp is None:  # dry-run
            return {"status": None, "body": {}, "text": "", "results_2xx": 0}
        step.actual_status = resp.status_code
        try:
            parsed = resp.json()
        except Exception:  # noqa: BLE001
            parsed = {}
        text = resp.text or ""
        step.response_excerpt = redact(text[:600], allow=allow_pii)
        for var, expr in step.extract.items():
            variables[var] = jsonpath(parsed, expr)
        for var, pat in step.extract_regex.items():     # web-mode HTML extraction
            variables[var] = regex_extract(text, pat)
        return {"status": resp.status_code,
                "results_2xx": 1 if 200 <= resp.status_code < 300 else 0,
                "body": parsed, "text": text}

    async def _run_probe(self, probe: TestStep | None, variables: dict) -> dict[str, float]:
        """Run a state probe; return its extracted numeric values."""
        if probe is None or self.dry_run:
            return {}
        try:
            client = await self._client_for(probe.who)
            path = self._subst(probe.path, variables)
            resp = await self._send(client, probe, path, None, None)
            if resp is None:
                return {}
            try:
                data = resp.json()
            except Exception:  # noqa: BLE001
                data = {}
            text = resp.text or ""
        except Exception as exc:  # noqa: BLE001
            logger.debug("state probe failed: %s", exc)
            return {}
        out: dict[str, float] = {}
        for var, expr in probe.extract.items():                   # JSON state
            num = coerce_number(jsonpath(data, expr))
            if num is not None:
                out[var] = num
        for var, pat in probe.extract_regex.items():              # HTML state
            num = coerce_number(regex_extract(text, pat))
            if num is not None:
                out[var] = num
        return out

    # ------------------------------------------------------------- case exec
    async def run_case(self, case: TestCase) -> TestCase:
        variables: dict[str, Any] = {}
        step_ctxs: list[tuple[TestStep, dict]] = []
        try:
            # 1. Provision prerequisites.
            for s in case.setup_steps:
                await self._exec_step(s, variables)

            # 2. Baseline state.
            before = await self._run_probe(case.state_probe, variables)

            # 3. Attack steps.
            for step in case.steps:
                ctx = await self._exec_step(step, variables)
                step_ctxs.append((step, ctx))

            # 4. Post-attack state + deltas.
            after = await self._run_probe(case.state_probe, variables)
            deltas = {k: after.get(k, 0.0) - before.get(k, 0.0) for k in (set(before) | set(after))}
            net_balance_delta = self._net_delta(deltas)

            case.evidence = {
                "state_before": before, "state_after": after, "deltas": deltas,
                "net_balance_delta": net_balance_delta,
                "requests": [{"summary": s.request_summary, "status": s.actual_status,
                              "response": s.response_excerpt} for s, _ in step_ctxs],
            }

            if self.dry_run:
                case.verdict = Verdict.NOT_RUN
                case.notes.append("dry-run: requests generated but not sent")
            else:
                case.verdict = self._judge(case, step_ctxs, before, after, deltas,
                                           net_balance_delta, variables)
        except ScopeError as exc:
            case.verdict = Verdict.ENVIRONMENTAL_ERROR
            case.notes.append(f"BLOCKED BY SCOPE GUARD: {exc}")
        except Exception as exc:  # noqa: BLE001
            case.verdict = Verdict.NEEDS_REVIEW
            case.notes.append(f"Runtime error: {exc}")
        finally:
            await self._run_cleanup(case, variables)
        return case

    @staticmethod
    def _net_delta(deltas: dict[str, float]) -> float:
        """Pick the most balance-like delta (so economic conditions are meaningful)."""
        for name, val in deltas.items():
            if any(h in name.lower() for h in _BALANCE_HINTS):
                return val
        return next(iter(deltas.values()), 0.0)

    # Tokens whose presence in a success_condition means the verdict depends on
    # real PROOF — response content (body/text) or a measured state delta — not
    # merely on the server having RESPONDED. A bare `status in (200, 201)` proves
    # only that a page/endpoint answered, which is never a business-logic win:
    # that is exactly how a forgiving app (200 on every landing page) produced the
    # historical false positives. See _judge.
    _PROOF_TOKENS = ("body", "text", "net_balance_delta", "deltas",
                     "_delta", "_after", "_before")

    @staticmethod
    def _has_cross_identity_differential(case) -> bool:
        """True when the case provisions a resource as ONE identity and attacks it
        as ANOTHER (victim creates, attacker reads). A success there is a genuine
        cross-tenant differential, not just 'the server answered'."""
        return any(s.who and a.who and s.who != a.who
                   for s in case.setup_steps for a in case.steps)

    def _judge(self, case, step_ctxs, before, after, deltas, net_balance_delta, variables) -> Verdict:
        """Decide the verdict, distinguishing PROVEN exploits from mere LEADS.

        A success_condition that is met is only a CONFIRMED_EXPLOIT when the pass
        is corroborated by hard evidence:
          - a real state change (a non-zero balance/counter delta), OR
          - a response-content assertion in the condition (body/text/delta), OR
          - a cross-identity differential (provisioned as victim, abused as attacker).

        A condition met by HTTP status alone — with no state change and no content
        proof — is recorded as NEEDS_REVIEW (a lead for the agent/operator to
        verify), NOT a confirmed finding. This is the enterprise rule the differential
        oracle encodes: a 200 is not a vulnerability. It is what stops a landing-page
        GET that returns 200 from being reported as an exploit."""
        state_changed = abs(net_balance_delta) > 1e-9 or any(abs(v) > 1e-9 for v in deltas.values())
        cross_identity = self._has_cross_identity_differential(case)
        substantive = False
        weak = False
        for step, ctx in step_ctxs:
            if not step.success_condition:
                continue
            ns = {
                "status": ctx.get("status"),
                "body": ctx.get("body", {}),
                "text": ctx.get("text", ""),
                "results_2xx": ctx.get("results_2xx", 0),
                "statuses": ctx.get("statuses", []),
                "concurrency": ctx.get("concurrency", 1),
                "net_balance_delta": net_balance_delta,
                "deltas": deltas,
                "vars": variables,
                **{f"{k}_delta": v for k, v in deltas.items()},
                **{f"{k}_before": v for k, v in before.items()},
                **{f"{k}_after": v for k, v in after.items()},
                **variables,
            }
            if not safe_eval(step.success_condition, ns):
                continue
            content_backed = any(tok in step.success_condition for tok in self._PROOF_TOKENS)
            if content_backed or state_changed or cross_identity:
                substantive = True
                case.notes.append(
                    f"Step {step.step}: '{step.success_condition}' MET with corroboration "
                    f"(status={ctx.get('status')}, net_delta={net_balance_delta}, "
                    f"state_changed={state_changed}, cross_identity={cross_identity}) — CONFIRMED"
                )
            else:
                weak = True
                case.notes.append(
                    f"Step {step.step}: '{step.success_condition}' MET but status-only "
                    f"(status={ctx.get('status')}, no state delta, no response-content proof) — "
                    f"recorded as a LEAD requiring verification, NOT a confirmed exploit"
                )
        if substantive:
            return Verdict.CONFIRMED_EXPLOIT
        if weak:
            return Verdict.NEEDS_REVIEW
        return Verdict.FALSE_POSITIVE

    async def _run_cleanup(self, case: TestCase, variables: dict) -> None:
        for step in case.cleanup_steps:
            try:
                await self._exec_step(step, variables)
            except Exception as exc:  # noqa: BLE001
                case.notes.append(f"cleanup step {step.step} failed: {exc}")

    async def run_all(self, cases: list[TestCase]) -> list[TestCase]:
        try:
            for case in cases:
                await self.run_case(case)
        finally:
            await self.aclose()
        return cases

    def audit_records(self) -> list[dict]:
        """Aggregate every outbound request across all sessions for the audit trail."""
        records: list[dict] = []
        for c in self._clients.values():
            for entry in c.request_log:
                records.append({**entry, "url": redact(entry.get("url"),
                                                        allow=self.scope.allow_pii_capture)})
        records.sort(key=lambda r: r.get("ts", 0))
        return records

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
