# Architecture

## The pipeline

```
load scope ─► ingest / discover ─► infer model ─► generate ──► execute ──────► confirm ──────► report
 (authz +     OpenAPI/GraphQL/HAR/   LLM fleet or  concrete      authenticated,    differential   md+json+
 identities)  Burp/JS + crawler      heuristic     exploits      scope-guarded      oracle         SARIF+audit
```

The orchestrator that runs this end-to-end is `venom/engagement.py :: run_engagement`.
It is designed to **fail closed**: nothing reaches the network without an authorized,
unexpired scope, and the live hunt fails honestly if no LLM provider is configured
(it does not silently degrade to a status-code scanner).

## Two execution paths (know which one you're touching)

VENOM has two distinct ways to produce a confirmed finding. Conflating them is the
most common mistake.

### A. The general autonomous engine - `venom/cognition/`
Model-driven and fully generalizable to **arbitrary real apps**. It must never depend
on lab-specific strings. Two entry points share the machinery:

- **`oneshot_hunt`** ([cognition/oneshot.py](../venom/cognition/oneshot.py)) -
  LLM-frugal (default ≤3 model calls). Recon -> one synthesis -> sandboxed exploit ->
  verify, with sharp feedback on failure. Survives free-tier rate limits.
- **`Agent`** ([cognition/agent.py](../venom/cognition/agent.py)) - an iterative
  observe->act->re-think loop with skill replay, backtracking, and step/time caps.

### B. The PortSwigger lab solvers - `venom/flows/`
Deterministic, hand-written exploiters that exist **only** to solve specific
PortSwigger labs. Here the lab's `is-solved` banner is the authoritative ground truth
(exactly like a unit test's expected value). On a real, bannerless app these flows
simply do not fire - they never produce a false positive. They are **not** the general
engine; do not "clean up" their `is-solved` checks.

The general engine (path A) is **is-solved-free**: success is a state transition, not a
banner. See [success-oracle.md](success-oracle.md).

## The oneshot loop in detail

1. Deterministic recon is already done (crawler -> `EndpointRegistry`).
2. Build an **action-grounding set** (`known_paths`) from the registry, plus `/`, the
   win-action path, and auth endpoints (`/login`) so account-takeover chains can
   re-authenticate.
3. `enrich_recon()` probes the surface as the current user -> **accessible / denied**
   maps, and **auto-loots** secrets leaked by object-id enumeration *and* shown in page
   prose (api-keys, tokens, pins).
4. Build a compact, token-cheap recon **brief**.
5. **Baseline check:** if the win action already works un-escalated, it is not a flaw -> `[]`.
6. **Bounded synthesis loop (≤ N):** ask the model once for `VULN:<id>` + a fenced
   ```python `async def exploit(http): ...` block; run it in the sandbox; check the
   oracle; on failure feed back the *real* observed responses and any invented
   endpoints. Total LLM calls are hard-capped.
7. On success emit a `TestCase` with proof, run metrics, and an HMAC-signed audit trail.

Fenced code (not code-inside-JSON) is used deliberately: small/local models mangle
JSON-escaped multi-line code.

## Components (what lives where)

| Package | Responsibility |
|---------|----------------|
| `core/scope.py` | The single authorization chokepoint (the safety boundary) |
| `core/registry.py`, `core/graph.py` | Discovered endpoint surface + reconstructed business model |
| `ingest/` | OpenAPI/GraphQL/HAR/Burp/JS parsers, live **crawler**, and **recon** enrichment (accessible/denied + auto-loot) |
| `cognition/` | The autonomous brain: `oneshot`, `agent`, `agent_brain`, and the success `objective` oracle |
| `tools/base.py` | Scope-guarded toolbox + the **sandboxed** `run_exploit_code` (AST validation, action grounding, timeout) |
| `tools/exploit_kit.py` | General technique primitives injected into exploit code |
| `knowledge/business_logic.py` | The 20-class business-logic KB + surface-ranked priors |
| `llm/providers.py` | Multi-provider router (DeepSeek / NVIDIA NIM / OpenRouter / Ollama) with fallback + throttle |
| `engine/http_client.py`, `engine/auth.py`, `engine/runner.py` | Scope-guarded client, identities, state-delta test runner |
| `flows/` | Deterministic PortSwigger-lab solvers (path B) |
| `testing/` | Test schema, API + web playbooks, generator |
| `report/builder.py` | Findings -> Markdown / JSON / **SARIF** + audit trail |
| `audit.py` | HMAC-signed, tamper-evident audit records + run metrics |
| `web/` | The browser console (std-lib HTTP server, JSON API, SSE, auth, React UI) |

## Exploit primitives

Agent-authored exploit code gets these pre-imported (no `import` needed), from
`tools/exploit_kit.py` + `tools/base.py`:

- `extract`, `extract_all` - pull a token/id from a response with a regex.
- `find_overflow_qty`, `modinv`, `brute` - integer-overflow / modular-arithmetic / search helpers.
- `b64e`, `b64d` - url-safe base64 (for forging identity cookies / token segments).
- `jwt_none(claims)` - forge an unsigned `alg:none` JWT; `jwt_hs256(claims, secret)` - sign with a known key.
- `login(user, pass)` - re-authenticate in-session (account-takeover chains); bypasses action grounding.
- `http(method, path, data=, params=, json=, headers=, cookies=)` - the scope-guarded request function.
