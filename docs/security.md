# Safety & security model

VENOM is offensive tooling. Its safety model is layered and **non-negotiable**.

## 1. Scope guard - the single chokepoint

[`venom/core/scope.py`](../venom/core/scope.py) is the one place every outbound request
is authorized. `assert_request_allowed` enforces, in order:

1. **Kill switch** - `VENOM_KILL_SWITCH=1` halts **all** requests instantly.
2. **Time window** - requests are blocked before `authorization_date` and after `expiry_date`.
3. **Host allow-list** - only `authorized_base_urls` (matched by scheme + host + port +
   path-prefix); anything in `out_of_scope` is hard-blocked (including subdomains).
4. **Destructive control** - `DELETE`/`PUT`/`PATCH` (or a caller-flagged request) require
   `allow_destructive: true`, and are capped by `max_destructive_actions` if set. An
   explicit `False` can never downgrade a destructive method.

Every request also carries `X-Pentest-ID: <engagement_id>` so a blue team can filter
test traffic. **There is intentionally no bypass flag.** The scope-guarded client
(`engine/http_client.py`) is the only path to the network. Proven by `tests/test_scope.py`.

## 2. The exploit sandbox

Agent-authored code runs in [`tools/base.py :: run_exploit_code`](../venom/tools/base.py):

- **AST validation** (`_validate_exploit_ast`): rejects non-stdlib imports, dunder
  attribute access, banned names (`eval`/`exec`/`open`/`getattr`/...), and **format-string
  dunder traversal** (e.g. `"{0.__class__.__init__.__globals__}".format(obj)` - a string
  literal that the attribute-node check alone would miss).
- **Restricted builtins** + a **stdlib-import whitelist** (`json`, `re`, `base64`,
  `hashlib`, `hmac`, `math`, ... - computation/encoding only; no `os`/`sys`/`subprocess`/
  `socket`/`pathlib`).
- **Action grounding:** `http(...)` may only call endpoints discovered during recon (plus
  `/`, the win-action path, and `/login`). Invented paths are rejected and reported.
- **Hard wall-clock timeout** (180s, headroom for legitimate brute-force loops).
- **Signature-tolerant dispatch:** an `exploit(http, login)` signature (a helper declared
  as a parameter) is bound correctly instead of crashing.

**Honest boundary:** this is a guardrail for an authorized operator driving a trusted
model - *not* a hard security sandbox. A determined in-process escape is a known class of
risk for any `exec`-based sandbox. **For a fully untrusted model, run the agent inside a
container** as well. The code and docs state this plainly.

## 3. Secret redaction

`utils.py` provides an always-on `redact_secrets()` + `SecretLogFilter` that strips
`nvapi-`, `sk-or-`, `sk-ant-`, bearer/api-key material from logs and artifacts. PII is
redacted from evidence unless `allow_pii_capture` is set. Proven by `tests/test_redaction_audit.py`.

## 4. Audit trail

[`audit.py`](../venom/audit.py) produces **HMAC-SHA256 signed**, tamper-evident records of
every outbound request (`VENOM_AUDIT_KEY`), plus `RunMetrics` (llm_calls, requests,
tokens, est_cost, elapsed). `verify_audit` detects any tampering (constant-time compare).
When no key is configured the envelope records `key_configured: false`, so an
unsigned-in-practice run is obvious rather than silently trusted.

## 5. Web console authentication

[`web/auth.py`](../venom/web/auth.py) adds multi-user auth to the console:

- Passwords stored as **PBKDF2-HMAC-SHA256** (200k rounds, per-user salt) - never plaintext.
- Sessions are **HMAC-SHA256 signed** tokens (`user.expiry.sig`) in an **HttpOnly,
  SameSite=Lax** cookie; the server trusts a cookie only if the signature and expiry verify.
- Per-user **engagement isolation**: a run is owned by the operator who launched it; the
  dashboard filters by owner and per-run endpoints are owner-gated (a user cannot read
  another user's run). Read-only config endpoints (status/providers/KB) stay public; the
  whole UI is still gated behind login.

Configure with `VENOM_WEB_SECRET` (sign key, falls back to `VENOM_AUDIT_KEY`),
`VENOM_WEB_USER` / `VENOM_WEB_PASSWORD` (initial operator). It is intentionally simple:
suitable for a localhost console or behind a reverse proxy / SSO, **not** as
internet-facing identity infrastructure. Add `Secure` to the cookie and serve over TLS
for any non-localhost deployment.

## Operating rules

- **Authorized engagements only.** No request leaves the process without passing the scope guard.
- `run` is **dry-run by default**; real traffic requires explicit `--live`.
- The agent stops at proof-of-concept; it does not persist access or destroy data.
