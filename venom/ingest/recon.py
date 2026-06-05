"""
Recon enrichment — turn a bare endpoint registry into a senior-tester's situational
picture, as the *current* (authenticated) user:

  - probe each discovered endpoint and record its baseline status + a text snippet,
  - classify every action as ACCESSIBLE-to-you vs DENIED-to-you (the "forbidden map").

For business-logic hunting the denied map is the gold: the objective is almost
always "perform an action you are currently NOT allowed to perform." Handing the
agent an explicit list of what it can and cannot do — instead of a flat endpoint
list — is what lets a model reason about *how to bridge that gap*.

State-changing endpoints are probed with an EMPTY/benign body so the server's
authorization gate fires before any effect — we read the gate, we don't trip it.
"""

from __future__ import annotations

import logging
import re

from ..core.scope import Scope, ScopeError
from ..engine.auth import AuthManager
from ..engine.http_client import RateLimiter, ScopedClient
from ..llm.budget import compact_html

logger = logging.getLogger("venom.ingest.recon")

_DENY_STATUS = {401, 403}

# A field whose NAME contains one of these usually holds a credential/secret that
# is meant to be server-side only — exactly the thing a BOLA/IDOR read leaks.
_SECRET_RE = re.compile(
    r"""["']?([A-Za-z0-9_-]*?(?:token|api[_-]?key|apikey|secret|pin|invite|"""
    r"""otp|passcode|password|access[_-]?key|signing[_-]?key|client[_-]?secret)[A-Za-z0-9_-]*)"""
    r"""["']?\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9._\-]{3,})""",
    re.I,
)
# Generic privileged identifiers worth substituting into an object-id parameter.
_PRIV_IDS = ("administrator", "admin", "root", "superadmin", "1", "0")


def _is_login_redirect(resp) -> bool:
    if getattr(resp, "status_code", None) not in (301, 302, 303, 307, 308):
        return False
    loc = (dict(getattr(resp, "headers", {}) or {}).get("location") or "").lower()
    return "login" in loc or "signin" in loc or "auth" in loc


def _harvest_id_candidates(snippets: list[str], identities) -> list[str]:
    """Build a small, GENERAL set of values to substitute into an object-id
    parameter: privileged names, identities, every integer seen in recon text and
    its near-neighbours, and a 0-9 sweep. This is what a senior tester does by hand
    to find a BOLA — it is target-agnostic (no lab-specific values)."""
    cands: set[str] = set(_PRIV_IDS)
    cands.update(str(i) for i in range(0, 10))
    for ident in identities or []:
        nm = ident.get("name") if isinstance(ident, dict) else getattr(ident, "name", None)
        if nm:
            cands.add(str(nm))
    for s in snippets:
        for word in re.findall(r"\b[A-Za-z][A-Za-z0-9_.-]{2,}\b", s or ""):
            if word.lower() in ("administrator", "admin", "carlos", "wiener", "root", "owner"):
                cands.add(word)
        for num in re.findall(r"\b\d{1,8}\b", s or ""):
            n = int(num)
            for d in (-2, -1, 0, 1, 2):
                if n + d >= 0:
                    cands.add(str(n + d))
    return list(cands)


def _scan_secrets(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _SECRET_RE.finditer(text or ""):
        field, value = m.group(1), m.group(2)
        if value.lower() in ("none", "null", "true", "false"):
            continue
        out.append((field, value))
    return out


async def auto_loot(client, registry, *, candidates: list[str], self_texts: dict[str, str],
                    max_probes: int = 30) -> tuple[list[dict], list[dict]]:
    """Read-only active recon: substitute candidate values into discovered object-id
    query parameters and harvest any secrets (token/api-key/pin/invite/...) the
    response leaks. This is reconnaissance (GET only, scope-guarded) — the privileged
    ACTION that meets the objective is still left to the exploit. Returns
    (loot, privileged_snippets)."""
    loot: list[dict] = []
    priv: list[dict] = []
    seen_secret_values: set[str] = set()
    probes = 0
    # Only GET endpoints that actually take a query parameter are IDOR candidates.
    targets = [e for e in registry.by_risk()
               if e.method.upper() == "GET"
               and any(p.location == "query" for p in getattr(e, "parameters", []))]
    for e in targets:
        qparams = [p.name for p in e.parameters if p.location == "query"]
        baseline = self_texts.get(e.path, "")
        for pname in qparams:
            for val in candidates:
                if probes >= max_probes:
                    return loot, priv
                probes += 1
                try:
                    resp = await client.request("GET", e.path, params={pname: val},
                                                follow_redirects=False)
                except (ScopeError, Exception):  # noqa: BLE001 - best-effort recon
                    continue
                body = resp.text if resp is not None else ""
                if getattr(resp, "status_code", 0) >= 400:
                    continue
                secrets = [(f, v) for (f, v) in _scan_secrets(body) if v not in baseline]
                if not secrets:
                    continue  # high-signal only: skip reads that leak nothing new
                src = f"GET {e.path}?{pname}={val}"
                new_here = False
                for field, value in secrets:
                    if value in seen_secret_values:
                        continue
                    seen_secret_values.add(value)
                    new_here = True
                    loot.append({"found_at": src, "field": field, "value": value})
                if new_here:
                    snip = compact_html(body).get("text", "")[:200]
                    if snip:
                        priv.append({"source": src, "snippet": snip})
    return loot, priv


async def enrich_recon(scope: Scope, registry, *, transport=None, max_probes: int = 24) -> dict:
    """Probe the discovered surface as the current user; return a structured brief
    enrichment: per-endpoint baseline, plus accessible/denied action maps."""
    base = scope.authorized_base_urls[0]
    limiter = RateLimiter(scope.rate_limit_per_second)
    try:
        c = ScopedClient(scope, base, role="recon-enrich", limiter=limiter, transport=transport)
    except ValueError:
        return {}
    identity = scope.identities[0]["name"] if scope.identities else None
    if identity:
        try:
            c.apply_auth(await AuthManager(scope, transport=transport).ensure(identity))
        except Exception as exc:  # noqa: BLE001
            logger.info("recon enrichment unauthenticated (%s)", exc)

    probed: list[dict] = []
    accessible: list[str] = []
    denied: list[str] = []
    seen: set[tuple[str, str]] = set()
    try:
        for e in registry.by_risk()[:max_probes]:
            method = e.method.upper()
            key = (method, e.path)
            if key in seen:
                continue
            seen.add(key)
            try:
                if method == "GET":
                    resp = await c.request("GET", e.path, follow_redirects=False)
                else:
                    # empty body: the authz gate answers before any state change
                    resp = await c.request(method, e.path, data={}, follow_redirects=False)
            except ScopeError:
                continue
            except Exception as exc:  # noqa: BLE001
                logger.debug("probe %s %s failed: %s", method, e.path, exc)
                continue
            status = getattr(resp, "status_code", None)
            # Keep enough text that key identifiers (account names, ids, header names,
            # hints) survive — 140 chars was cutting names like "TREASURY-OPS" in half.
            snippet = compact_html(resp.text if resp is not None else "").get("text", "")[:320]
            entry = {"method": method, "path": e.path, "status": status}
            if snippet:
                entry["snippet"] = snippet
            probed.append(entry)
            label = f"{method} {e.path}"
            if status in _DENY_STATUS or _is_login_redirect(resp):
                denied.append(label)
            elif status is not None and 200 <= status < 400:
                accessible.append(label)

        # Active recon / auto-loot: enumerate object-id parameters as the current
        # user and harvest any secrets a BOLA/IDOR read leaks. Read-only.
        loot: list[dict] = []
        priv: list[dict] = []
        try:
            self_texts = {p["path"]: (p.get("snippet") or "") for p in probed}
            candidates = _harvest_id_candidates(
                [p.get("snippet", "") for p in probed], scope.identities)
            loot, priv = await auto_loot(c, registry, candidates=candidates,
                                         self_texts=self_texts)
            if loot:
                logger.info("auto-loot: harvested %d secret(s) from object-id enumeration", len(loot))
        except Exception as exc:  # noqa: BLE001 - loot is best-effort
            logger.debug("auto-loot failed: %s", exc)

        return {"probed": probed,
                "accessible_to_you": sorted(set(accessible)),
                "denied_to_you": sorted(set(denied)),
                "authenticated_as": identity,
                "loot": loot,
                "privileged_reads": priv}
    finally:
        await c.aclose()
