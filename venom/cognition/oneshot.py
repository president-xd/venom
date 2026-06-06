"""
One-shot (LLM-frugal) hunt: deterministic recon -> ONE concise LLM call -> a
self-contained exploit script -> run & verify. On failure, at most a couple of
short feedback calls. Total LLM calls are hard-capped (default 3), which is what
makes it survive free-tier rate limits - versus the per-step agent loop that makes
5-20+ calls per hunt.

Design:
  1. Recon is already done deterministically (crawler -> registry). We turn it into
     a COMPACT brief (top endpoints, form fields, catalog) - small prompt.
  2. The model is asked ONCE for {vuln_class, rationale, exploit_code} where
     exploit_code defines `async def exploit(http): ...` (run in the sandbox).
  3. We run it and check the win-oracle (deterministic, free). If unsolved and
     budget remains, we send back ONLY the short run result and ask for a fix.

`synthesize(brief, last_result) -> dict` is pluggable: an LLM in production
(make_oneshot_synthesizer), a deterministic stub in tests.
"""

from __future__ import annotations

import logging
import re

from ..core.scope import Scope
from ..knowledge import kb_prompt
from ..memory import Notebook
from ..tools import Toolbox
from ..testing.schema import Severity, TestCase, TestStep, VulnClass, Verdict
from .objective import Objective

logger = logging.getLogger("venom.cognition.oneshot")

_VC = {v.value: v for v in VulnClass}

_SYNTH_SCHEMA = ('{"vuln_class":"<one of the known classes>","rationale":"one short clause",'
                 '"exploit_code":"async def exploit(http):\\n    r = await http(\'POST\', \'/path\', '
                 'data={...})\\n    return r[\'status\']"}')


def build_brief(registry, objective: Objective, max_eps: int = 25, enrichment: dict | None = None) -> dict:
    """Compact, token-cheap recon summary for a single synthesis call.
    `enrichment` (from ingest.recon.enrich_recon) adds the accessible/denied maps."""
    eps = []
    for e in registry.by_risk()[:max_eps]:
        item = {"method": e.method, "path": e.path}
        params = [p.name for p in getattr(e, "parameters", [])]
        if params:
            item["params"] = params
        if getattr(e, "form_defaults", None):
            item["form_defaults"] = e.form_defaults
        if getattr(e, "business_rule_tags", None):
            item["tags"] = e.business_rule_tags
        eps.append(item)
    brief = {"objective": objective.description, "win_url": objective.win_url,
             "endpoints": eps, "catalog": registry.catalog, "store_credit": registry.store_credit}
    if enrichment:
        # The senior-tester view: what you CAN and CANNOT currently do.
        brief["accessible_to_you"] = enrichment.get("accessible_to_you", [])
        brief["denied_to_you"] = enrichment.get("denied_to_you", [])
        brief["authenticated_as"] = enrichment.get("authenticated_as")
        brief["page_snippets"] = [p for p in enrichment.get("probed", []) if p.get("snippet")][:12]
        # Auto-loot: secrets already harvested from object-id enumeration (BOLA reads),
        # and the cross-object reads that produced them. Gold for the exploit.
        if enrichment.get("loot"):
            brief["loot"] = enrichment["loot"][:12]
        if enrichment.get("privileged_reads"):
            brief["privileged_reads"] = enrichment["privileged_reads"][:8]
        # Which custom auth header the privileged action expects is often named in the
        # page prose ("needs header 'X-Staff-Pin'"). Surface it structurally so the
        # model uses the RIGHT header for a looted secret instead of guessing X-API-Key.
        blob = " ".join(p.get("snippet", "") for p in enrichment.get("probed", []))
        hdrs = re.findall(r"[Hh]eader\s*['\"]?(X-[A-Za-z][A-Za-z0-9-]+)", blob)
        if "bearer" in blob.lower() or "authorization" in blob.lower():
            hdrs.append("Authorization")
        if hdrs:
            brief["auth_headers_seen"] = sorted(set(hdrs))
    return brief


_FENCE = re.compile(r"```(?:python)?\s*(.*?)```", re.S)
_VULN = re.compile(r"VULN\s*:\s*([A-Za-z0-9_-]+)", re.I)


def auth_paths(scope) -> set[str]:
    """Login/auth endpoints are INFRASTRUCTURE, not part of the attack surface - an
    account-takeover chain must re-authenticate as the victim (change their password,
    then log in as them). Action-grounding should never block these, so we always
    allow the conventional `/login` plus any login path the engagement's identities
    declare. (The `login()` helper already bypasses grounding; this also lets the
    model's natural `http('POST','/login', ...)` succeed instead of being rejected as
    an 'invented' endpoint - the exact footgun that broke trusted-identity takeovers.)"""
    paths = {"/login"}
    for ident in (getattr(scope, "identities", None) or []):
        auth = ident.get("auth") if isinstance(ident, dict) else getattr(ident, "auth", None)
        if isinstance(auth, dict):
            lp = auth.get("login_url") or auth.get("path")
            if lp:
                paths.add((lp.split("?")[0].rstrip("/") or "/"))
    return paths


def _extract_code(text: str) -> str:
    """Pull the exploit function from a fenced block (or raw text). Robust to the
    newlines/quotes that break code-inside-JSON for small local models."""
    blocks = _FENCE.findall(text or "")
    for b in blocks:
        if "def exploit" in b:
            return b.strip()
    if blocks:
        return blocks[0].strip()
    i = (text or "").find("async def exploit")
    if i < 0:
        i = (text or "").find("def exploit")
    return text[i:].strip() if i >= 0 else ""


def make_oneshot_synthesizer(llm_agent):
    """Wrap an LLM agent into `synthesize(brief, last_result) -> dict` (ONE call).

    Asks for a FENCED python block (not code-inside-JSON) - far more reliable for
    small local models, which mangle JSON-escaped multi-line code.
    """
    def _endpoint_lines(brief: dict) -> str:
        """Explicit, high-salience list of the ONLY paths the model may call -
        the model otherwise copies example paths from the priors and invents URLs."""
        lines = []
        for e in brief.get("endpoints", []):
            fields = list(e.get("params", []) or []) + list((e.get("form_defaults") or {}).keys())
            extra = f"  fields={sorted(set(fields))}" if fields else ""
            lines.append(f"  {e.get('method')} {e.get('path')}{extra}")
        return "\n".join(lines)

    # Best-of-N state: each retry is a fresh, MORE DIVERSE sample (higher
    # temperature + an explicit "change approach" nudge), so retries explore new
    # flaw classes instead of re-rolling the same dead end. This is the honest,
    # model-agnostic reliability lever (no dependence on a specific model name).
    state = {"attempt": 0}
    _TEMP_RAMP = (0.1, 0.45, 0.7, 0.9, 1.0)

    async def synthesize(brief: dict, last_result: dict | None) -> dict:
        attempt = state["attempt"]
        state["attempt"] += 1
        temperature = _TEMP_RAMP[min(attempt, len(_TEMP_RAMP) - 1)]
        fix = ""
        if last_result:
            fix = ("\n\nYour PREVIOUS exploit did NOT meet the objective. Short run result: "
                   f"{str(last_result)[:400]}\nFix the code. IMPORTANT: do NOT repeat the same "
                   "approach - try a DIFFERENT vulnerability class, a different endpoint, or a "
                   "different parameter/identity substitution than your last attempt. Think step by "
                   "step about WHY it was denied, then attack a different assumption.")
        auth_as = brief.get("authenticated_as") or "the test user"
        loot_block = ""
        if brief.get("loot"):
            loot_lines = "\n".join(
                f"  {l.get('field')} = {l.get('value')!r}   (leaked by {l.get('found_at')})"
                for l in brief["loot"])
            hdr_hint = brief.get("auth_headers_seen")
            hdr_txt = (f" The privileged action's header is one of these NAMED on the page: "
                       f"{hdr_hint} - use that EXACT header name (do NOT default to X-API-Key)."
                       if hdr_hint else "")
            loot_block = (
                "ALREADY-LOOTED SECRETS - extracted FOR YOU from readable endpoints. Use the "
                "LITERAL value as the credential the privileged action needs (an Authorization: "
                "Bearer header, an X-API-Key / X-*-Token / X-*-Pin header named on the page, or a "
                "'token'/'key' form field). Do NOT re-fetch or re-guess them:\n" + loot_lines
                + hdr_txt + "\n\n")
        user = (
            "Write ONE self-contained exploit for an app you are authorized to test.\n"
            f"OBJECTIVE - your end goal: {brief.get('objective')}\n"
            f"You usually must ESCALATE FIRST: an admin-only action needs ADMIN power, so take over "
            f"or impersonate the PRIVILEGED account (e.g. 'administrator') - steal/forge ITS "
            f"credential, or reset ITS password then login() as it - and ONLY THEN perform the goal "
            f"on the exact target named. Do not take over the victim you are targeting.\n\n"
            + loot_block +
            f"CALLABLE ENDPOINTS - use these EXACT method+path strings and NOTHING ELSE "
            f"(do NOT invent paths). You are ALREADY authenticated as '{auth_as}', so do not "
            f"re-login as yourself - BUT for an account TAKEOVER you MUST become the victim: after "
            f"you change/reset a privileged account's credential, call `await login('administrator', "
            f"'<new-pass>')` (or POST /login) to switch into THAT session, THEN do the privileged "
            f"action:\n{_endpoint_lines(brief)}\n\n"
            f"BUSINESS-LOGIC PRIORS (ranked to this target; their example paths are ILLUSTRATIVE - "
            f"map them onto the CALLABLE ENDPOINTS above):\n{kb_prompt(surface=str(brief))}\n\n"
            f"RECON BRIEF (endpoints/forms/catalog/credit + what you CAN and CANNOT do):\n{brief}\n\n"
            "The brief's 'denied_to_you' lists actions you currently CANNOT perform; "
            "'accessible_to_you' lists what you can. Your job: find the business-logic flaw that "
            "lets you perform a DENIED action (the objective). Reason from 'page_snippets' and form "
            "fields - e.g. a profile/update form may silently accept an extra privileged field. "
            "If a request field names an account/owner/source you do NOT own (from_account, user, "
            "id, ...), try SUBSTITUTING a more-privileged value seen in recon - the server may trust it.\n"
            "OUTPUT FORMAT - exactly two parts and nothing else:\n"
            "1) a line: VULN: <vuln id from the priors>\n"
            "2) a ```python code block defining `async def exploit(http):`\n"
            "Inside call `await http(method, path, data={form}, params={query}, json={body}, "
            "headers={...}, cookies={...})` - use `params` for GET query strings, `json` for JSON "
            "APIs, `headers` for auth like {'Authorization':'Bearer <jwt>'} or {'X-API-Key':'...'}, "
            "and `cookies` to FORGE a client-trusted identity cookie, e.g. "
            "cookies={'auth': b64e('administrator:administrator')}. It "
            "returns a dict with keys 'status','text','headers'; you may loop/compute; perform the "
            "FULL exploit toward the objective and `return` a short result. Your session is handled "
            "for you. "
            "Pre-imported helpers (use ONLY if the flaw needs them; do NOT import): "
            "`await login(user, pass)` re-auths as another user in-session (cookies persist) - use "
            "after taking over a victim's credentials; `extract(text, pattern)` regex-pulls a "
            "token/id from a response to reuse; `find_overflow_qty(price)`, `modinv`, `brute` for "
            "numeric/overflow math; `jwt_none(claims)` forges an UNSIGNED admin JWT (e.g. "
            "jwt_none({'user':'administrator','role':'administrator'}) -> put it in "
            "headers={'Authorization':'Bearer '+tok}); `jwt_hs256(claims, secret)` signs with a "
            "KNOWN key; `b64e('administrator:administrator')` / `b64d(s)` build/parse url-safe "
            "base64 cookies & tokens. "
            "KEY TACTICS: (1) REPEAT/LOOP a step when one pass is not enough - apply a coupon, mint "
            "store credit, convert currency, or earn points in a `for` loop UNTIL the goal threshold "
            "is met, THEN do the final action. (2) If a page only DESCRIBES an auth scheme (JWT, "
            "identity cookie), FORGE the credential from scratch (jwt_none / b64e) - do NOT GET the "
            "page and try to decode it as a token; there is no ready token to fetch. (3) ESCALATE "
            "WITH YOUR OWN VISIBLE CREDENTIAL: if the page shows YOUR key/cookie and a privileged "
            "endpoint reads a `scope`/`role`/`plan` field or a header, send YOUR credential plus the "
            "ELEVATED value (scope='admin', role='administrator') - you do not always need a stolen "
            "secret. (4) HTML forms take `data={...}` (form-encoded); only true JSON APIs take "
            "`json={...}` - match what the endpoint expects. "
            "Use ONLY endpoints that appear in the RECON BRIEF (do not invent paths). "
            "Numeric form values (price, quantity) are INTEGERS in minor units (e.g. 1), never decimals. "
            "If a hidden field like csrf is shown in the brief, reuse its value." + fix +
            "\n\nExample shape (write your OWN logic):\n"
            "VULN: client-side-trust\n```python\nasync def exploit(http):\n"
            "    r = await http('POST', '/cart', data={'productId': '1', 'quantity': '1'})\n"
            "    return r['status']\n```"
        )
        text = await llm_agent.complete_text(user, temperature=temperature)
        vm = _VULN.search(text or "")
        return {"vuln_class": vm.group(1) if vm else "", "rationale": "",
                "exploit_code": _extract_code(text)}

    return synthesize


async def oneshot_hunt(scope: Scope, registry, synthesize, *, objective: Objective,
                       transport=None, max_llm_calls: int = 3, enrichment: dict | None = None) -> list[TestCase]:
    """Run the frugal hunt. At most `max_llm_calls` calls to `synthesize`.

    `enrichment` may be passed precomputed (the coverage campaign computes the
    accessible/denied recon ONCE and reuses it across many per-target hunts instead
    of re-probing the surface for every objective)."""
    from ..audit import RunMetrics, sign_records
    metrics = RunMetrics()
    notebook = Notebook()
    toolbox = Toolbox(scope, notebook, transport=transport, objective=objective)
    # Run exploits AND the success oracle from the engagement's primary low-priv
    # identity, so agent code starts in an authenticated baseline session (real
    # business-logic abuse is escalation FROM a normal user) and any in-exploit
    # session change (e.g. login() as admin) is seen by the win check.
    identities = list(getattr(scope, "identities", []) or [])
    if identities:
        toolbox.default_identity = getattr(identities[0], "name", None) or \
            (identities[0].get("name") if isinstance(identities[0], dict) else None)
    # Action grounding: confine agent-authored code to the discovered surface.
    # Always include the root + objective verification paths so the oracle isn't blocked.
    toolbox.known_paths = {(e.path or "/").rstrip("/") or "/" for e in registry}
    toolbox.known_paths |= {"/", (objective.win_url or "/").rstrip("/") or "/"}
    toolbox.known_paths |= auth_paths(scope)   # re-login for takeover chains
    if objective.win_action and objective.win_action.get("path"):
        toolbox.known_paths.add(objective.win_action["path"].rstrip("/") or "/")
    # Recon depth: probe the surface as the current user -> accessible/denied maps.
    # Reuse a precomputed enrichment when the campaign supplies one (avoids
    # re-probing the whole surface once per target).
    if enrichment is None:
        from ..ingest.recon import enrich_recon
        try:
            enrichment = await enrich_recon(scope, registry, transport=transport)
        except Exception as exc:  # noqa: BLE001
            logger.warning("recon enrichment failed: %s", exc)
            enrichment = {}
    brief = build_brief(registry, objective, enrichment=enrichment)
    last_result = None
    calls = 0
    try:
        # General differential oracle: does the win action ALREADY work (un-escalated)?
        # If so it's not a flaw; if it never works post-exploit, no finding. No lab strings.
        baseline_ok = await objective.baseline(toolbox)
        if baseline_ok:
            logger.info("oneshot: win action already permitted at baseline - not a flaw")
            return []
        while calls < max_llm_calls:
            calls += 1
            metrics.llm_calls = calls
            try:
                plan = await synthesize(brief, last_result)
            except Exception as exc:  # noqa: BLE001
                logger.warning("oneshot synthesize failed (call %d): %s", calls, exc)
                break
            code = (plan or {}).get("exploit_code") or ""
            if not code:
                last_result = {"objective_met": False,
                               "hint": "Return a fenced python block defining `async def exploit(http)`."}
                continue
            try:
                res = await toolbox.run_exploit_code(code)
                met = bool((await toolbox.check_objective()).data.get("met"))
                # The bare win-action re-run only proves SESSION escalation. If the
                # privilege was carried IN the winning request (e.g. a looted token in
                # a BOLA delete), the exploit's own trace shows the win - accept that
                # too (baseline was already denied, so the differential still holds).
                if not met and objective.win_action:
                    if objective.action_succeeded_in_trace((res.data or {}).get("trace")):
                        met = True
            except Exception as exc:  # noqa: BLE001 - one bad attempt must not abort the hunt
                logger.warning("oneshot attempt %d errored: %s", calls, exc)
                last_result = {"objective_met": False, "run_error": str(exc)[:200],
                               "hint": "Your code or the verification errored; simplify it and use only "
                                       "endpoints from the recon brief."}
                continue
            logger.info("oneshot call %d: ran code ok=%s objective_met=%s", calls, res.ok, met)
            if met:
                vc = _VC.get((plan.get("vuln_class") or "").upper(), VulnClass.FAITH_BASED_RULE)
                metrics.requests = len(toolbox.requests)
                metrics.exploit_runs = calls
                return [TestCase(
                    test_id="ONE-001",
                    vulnerability_class=vc,
                    hypothesis=f"One-shot exploit ({plan.get('vuln_class', '?')}): "
                               f"{plan.get('rationale', '')}",
                    risk_rating=Severity.HIGH,
                    affected_endpoint=objective.win_url,
                    business_impact="Objective reached by a single synthesized, self-verified exploit script.",
                    steps=[TestStep(step=1, description=f"synthesized exploit ({calls} LLM call(s))",
                                    method="*", path=objective.win_url)],
                    origin="oneshot",
                    verdict=Verdict.CONFIRMED_EXPLOIT,
                    notes=[f"{calls} LLM call(s)", "OBJECTIVE MET",
                           ("PROOF (differential): the win action was DENIED at baseline and "
                            "SUCCEEDED after the exploit" if objective.win_action
                            else "verified via win signal"),
                           f"code:\n{code[:1500]}"],
                    evidence={"exploit_code": code, "run": res.data,
                              "differential": {"win_action": objective.win_action,
                                               "baseline_denied": bool(objective.win_action),
                                               "post_exploit_allowed": True},
                              "metrics": metrics.to_dict(),
                              "audit": sign_records(toolbox.audit())},   # tamper-evident trail
                )]
            # Sharp feedback: the win-oracle drives the fix, the REAL observed
            # responses are shown back (so the next attempt is directed, not blind),
            # and invented endpoints (grounding violations) are called out loudly.
            unknown = (res.data or {}).get("unknown_endpoints") or []
            real = ", ".join(sorted(toolbox.known_paths or [])[:20])
            trace = (res.data or {}).get("trace") or []
            # Compact, token-cheap view of what each request actually returned.
            observed = [{"method": t.get("method"), "path": t.get("path"),
                         "status": t.get("status"), "saw": (t.get("snippet") or "")[:160],
                         **({"note": t["note"]} if t.get("note") else {})}
                        for t in trace[-8:]]
            hint = ("The objective is NOT yet met - your target action is still FORBIDDEN to you "
                    "(see 'denied_to_you'). Study 'observed_responses' below: that is what the server "
                    "ACTUALLY returned to your code. If a response contained a token/id you need, "
                    "extract() it and reuse it. To act as a privileged user, login(user, pass) AFTER "
                    "you control their credentials, THEN retry the target action in the SAME session. "
                    "If a writable form silently accepts an extra privileged field (role, is_admin, "
                    "tier), set it. Match a business-logic prior to what the surface exposes.")
            if not trace:
                hint = ("Your exploit made NO successful requests (check run_error and that you used "
                        "real endpoints). " + hint)
            if unknown:
                hint = (f"STOP: your code called endpoints that DO NOT EXIST: {unknown}. "
                        f"The ONLY real endpoints are: {real}. Rewrite using exclusively those. " + hint)
            last_result = {
                "objective_met": False,
                "exploit_returned": str((res.data or {}).get("return"))[:200],
                "run_error": ((res.data or {}).get("error") or "")[:300],
                "observed_responses": observed,
                "invented_endpoints": unknown,
                "hint": hint,
            }
        logger.info("oneshot: objective not met after %d LLM call(s)", calls)
        return []
    finally:
        await toolbox.aclose()
