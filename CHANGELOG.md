# Changelog

All notable changes to **VENOM** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Documentation** - a structured [`docs/`](docs/) set: getting-started, architecture,
  success-oracle, security, web-console, CLI, configuration, vulnlab, development, and an
  honest **capabilities-and-limits** page (what is proven vs. model-limited, with real
  eval numbers).
- **Web console multi-user login** (`venom/web/auth.py`) - PBKDF2-hashed passwords,
  HMAC-signed HttpOnly session cookies, a login screen, `/api/login|logout|me`, and
  **per-user engagement isolation** (runs are owner-stamped; the dashboard filters by
  owner; per-run endpoints are owner-gated). Seeded operator printed once on first start
  (`VENOM_WEB_USER`/`VENOM_WEB_PASSWORD`/`VENOM_WEB_SECRET`). Tested in `test_web_auth.py`.
- **Web console UX** - visible **Theme** switcher (Auto/Light/Dark) + Density + Accent in
  Settings; **dark mode** (CSS-variable overrides, `prefers-color-scheme` + manual);
  **responsive** layout below 760px; a React error boundary + loading states so the
  Findings/Report screens never blank.
- **Exploit primitives** (`tools/exploit_kit.py`) - `jwt_none`/`jwt_hs256` (token forgery)
  and `b64e`/`b64d` (url-safe base64 for identity-cookie forgery); `http(..., cookies=)`
  and signature-tolerant exploit dispatch.
- **Recon depth** - `enrich_recon` now also harvests credentials shown in **page prose**
  (`sk_live_*`, api-keys, quoted token/pin values), not only from object-id enumeration.
- **Forced-browse wordlist** expanded from 78 to **278** curated business-logic /
  access-control paths.

### Removed
- **The deliberately-vulnerable proving ground is no longer shipped in the repo.** It is
  gitignored (kept on disk for local development), since publishing a vulnerable app in a
  product repo is unprofessional. The vulnlab-dependent test/eval suites skip
  automatically when it is absent (`pytest.importorskip`), so a fresh clone stays green
  (154 passed, 8 skipped); the web console hunts the authorized target URL you enter.

### Changed
- **The success oracle is is-solved-free.** A win is a differential `win_action`
  (denied at baseline, succeeds after the exploit) confirmed by a realistic state marker
  the app genuinely emits - never an `is-solved` banner. The general engine and the web
  coverage path carry **no** `is-solved` string; the banner remains only for the
  deterministic `venom/flows/*` PortSwigger solvers.
- **Action grounding** now always allows auth endpoints (`/login` + identity login paths)
  so account-takeover chains can re-authenticate.
- Finding **title** is now a concise headline with the **full, untruncated** explanation in
  a new `description` field (was hard-cut at 120 chars).
- Removed typographic em-dashes/arrows from user-facing text (UI, reports, findings, KB).

### Fixed
- **Sandbox escape** - the AST validator now blocks format-string dunder traversal
  (`"{0.__class__.__init__.__globals__}".format(obj)`), which the attribute-node check
  alone missed.
- `scripts/eval_vulnlab.py` no longer fails with `ModuleNotFoundError` (adds the repo root
  to `sys.path`).
- `venom providers` reports the provider that actually answered (no fallback masking).
- README/`runs.py` "no LLM key needed" corrected: the web console's live hunt requires a
  provider and fails closed otherwise.
- Web Findings/Report screens no longer blank or leak demo data during the live-findings
  fetch (loading state + array guards + self-healing fetch + error boundary).

### Added (prior)
- **Agent core** - VENOM can now *compose its own exploits*
  instead of only running hand-coded playbooks:
  - **Toolbox** (`venom/tools/`) - composable, scope-guarded tools the agent calls:
    `http_get/post_form/post_json`, `find`, `forms`, `calc`, `read_email_inbox`,
    `note_set/get`, `check_objective`.
  - **Working memory** (`venom/memory/notebook.py`) - a per-engagement scratchpad
    (facts, attempts, sub-goals, stall detection) enabling multi-step reasoning.
  - **Skill library** (`venom/memory/skills.py`) - confirmed chains are persisted as
    retrievable skills, so VENOM *learns* and gets faster on repeat classes.
  - **Agent loop** (`venom/cognition/agent.py`) - Plan -> Act (tool) -> record -> check
    objective -> backtrack to another strategy; learns a skill on success. The brain
    is pluggable (LLM in prod, deterministic stub in tests).
  - **Objective** model + `--objective` flag + scope `objective` field (a generic
    win-oracle so the agent knows the goal and when it's reached).
  - Proven in `tests/test_agent.py`: a stub brain solves an in-memory target by
    composing tools, **backtracks** decoy->real strategy, and **learns a skill** -
    with NO hardcoded flow.
- **LLM robustness** - `venom/llm/telemetry.py`: a **response
  cache** (identical agent calls skip the provider), a per-engagement **token
  budget** with a hard stop (`BudgetExceeded`), and **tracing** (per-call
  provider/model/tokens/latency -> `agent_trace.jsonl`). Plus **model tiering**:
  per-step agent decisions go to the fast model (Qwen), not the slow base model.
  Tested in `tests/test_telemetry.py` (cache hit, budget block, trace summary).
- **Renamed the product to VENOM** (package `venom`, CLI `venom`, image `venom-agent`).
- **Account-lifecycle flow** (`venom/flows/account_takeover.py`) - registration +
  email verification (cross-host **email-client reader**) + privilege via email
  domain (the "inconsistent security controls" pattern): register -> confirm via
  inbox -> log in -> change email to the company domain -> reach `/admin`. A
  destructive objective (e.g. delete a user) is **opt-in** via `allow_destructive`
  + `objective_delete_user`. Scope gains `email_client_url`,
  `privileged_email_domain`, `objective_delete_user`.
- **Adaptive reasoning loop** (`venom/cognition/`) - "think before you exploit":
  observe -> cheap **probe** -> read the real response -> **re-think** -> **exploit** ->
  **verify**. The decision "brain" is pluggable (LLM in production, stub in tests),
  so VENOM can attempt flaws with **no pre-coded playbook**. Enabled with
  `venom run --think --live`. Proven by `tests/test_cognition.py` (the loop confirms
  an exploit driven only by reasoning over observations).
- **Business-logic knowledge base** (`venom/knowledge/`) - 12 vulnerability classes
  curated from OWASP WSTG §4.10 and PortSwigger, used as **priors** for the reasoner
  (signals -> cheap probe -> exploit shape), not as rigid rules.
- **Free-tier context budgeting** (`venom/llm/budget.py`) - per-message trimming and
  HTML->skeleton compaction (forms/inputs/links/text, quote-tolerant) so large pages
  and JSON never exceed small-context API limits. Applied to every agent call.

### Fixed
- HTML attribute parsing now handles **unquoted** attributes (e.g. `value=1337`),
  matching real-world markup - the reasoner would otherwise miss form values.

Still ahead:
- Agent-platform resilience: JSON-schema/tool-calling contracts, parallel fan-out,
  per-agent retry/circuit-breaker, token/cost budgets, tracing.
- Auth: OAuth2/OIDC, multi-step login, MFA hooks, CSRF-on-action-forms generalization.
- OOB/SSRF detection via Burp Collaborator wired into the runner.
- Persistence & scale: resumable engagements, per-host parallel execution, workers.
- Prompt-injection defense for ingested/crawled content.
- Dense RAG (FAISS) + learning loop (persist confirmed exploits to the corpus).
- CI (lint+type+tests+Docker), SBOM, pinned base-image digest.

Both validated purchasing-logic tactics (client-side price tampering and
multi-item cart balancing) now solve real labs end-to-end; see 0.1.0 "Verified".

---

## [0.1.0] - 2026-06-01

First working cut: a context-aware business-logic pentest agent that ingests or
**discovers** a target, reconstructs its business model, generates **concrete,
authenticated exploits**, executes them under a fail-safe scope guard, and
**confirms** findings from real state/HTML - for both JSON APIs and classic web apps.

### Added
- **Authorization core** - `core/scope.py`: single fail-safe chokepoint (host +
  port + path-prefix scoping, `out_of_scope`, time window, destructive gating,
  `X-Pentest-ID` header). Dry-run is the default; `--live` is explicit.
- **Ingestion** - OpenAPI/Swagger, GraphQL (SDL + introspection), HAR, Burp XML,
  JS bundles; unified risk-tiered endpoint registry; business-model graph
  (entities, transitions, rules, actors, economic flows).
- **Live discovery crawler** (`ingest/crawler.py`) - point-and-shoot: crawls a
  URL within scope, extracts forms/links/**query params**, forced-browses a
  bundled wordlist (`venom/data/wordlists/common.txt`). `venom run --crawl --live`.
- **Authentication & identities** (`engine/auth.py`) - `login` (JSON token),
  `bearer`, `cookie`, `basic`, and `form_login` (HTML CSRF scrape + session
  cookie); isolated per-identity sessions; auto re-login + retry on 401/403.
- **Multi-agent fleet** (`agents/`) - orchestrator (DeepSeek base) coordinating
  Research (GLM), Hypothesis (Kimi), CodeGen + Summarizer (Qwen), Reporter
  (DeepSeek), all via one NVIDIA NIM key; env-driven model catalog with aliases;
  `venom agents [--ping]`.
- **Exploit generation** - API playbooks (sequence, BOLA/IDOR, race, param/type,
  mass-assignment, economic, faith-based) and **web-app playbooks** (client-side
  price/parameter tampering with full add-to-cart->checkout chain, web IDOR,
  forced-browse access control); provisioning `setup_steps`.
- **Integer-overflow purchasing flow** (`venom/flows/integer_overflow.py`) - when the
  cart total is a signed 32-bit int, it computes (from the discovered catalog +
  modulus) the exact bulk-add sequence to overflow the total and land it within store
  credit with the target in the cart, verifies the live total, then checks out. Runs
  only as a last resort (it's request-heavy).
- **Cart-total balancing playbook** - for quantity-trusting carts with no client
  price: discovery captures the product **catalog** (prices) and **store credit**,
  then buys the expensive target by adding a cheap product at a computed **negative
  quantity** so the order total lands within credit.
- **Confirmation engine** - before/after **state-delta** probes, `*_before/_after/_delta`
  and `net_balance_delta` in success conditions, HTML/text + reflected-field checks,
  and winning-state/lab-solved detection.
- **RAG** (`rag/`) - dependency-free TF-IDF retriever over a built-in business-logic
  writeup corpus; references attached to findings; extensible via `VENOM_DATA_DIR/rag/corpus.json`.
- **Burp MCP (keyless)** - local-SSE MCP client + execution adapter + provisioning
  scripts (`scripts/setup_burp.*`, `scripts/run_burp_mcp.*`); degrades to no-op.
- **Reporting** - `report.md`, `findings.json`, **`findings.sarif`** (CI gating),
  `business_model.json`, and **`audit.jsonl`** (every request: ts, engagement, method, host, status).
- **Docker** - multi-stage non-root image + Compose (with optional local Ollama);
  bundled prompt + wordlist packaged into the image.
- **Tests** - 43 tests, including end-to-end proofs against in-memory vulnerable
  **JSON API** and **HTML web-app** targets (discovery -> login -> confirm).
- **Docs** - `README.md`, `.env.template` / `.env.example`.

### Changed
- LLM router: refreshed model IDs (DeepSeek base), removed the stale
  `anthropic-beta` header, **model-aware fallback** (a provider-specific model is
  no longer sent to a fallback provider that can't serve it), env-driven NVIDIA
  model catalog (`VENOM_NVIDIA_MODELS`) with alias resolution.
- API (JSON) playbooks now skip crawled HTML forms - web forms are handled by the
  web-app playbooks, eliminating JSON-at-HTML `400 "Missing parameter 'csrf'"` noise.
- CODEGEN and SUMMARIZER agents are now actually invoked (were decorative).
- `write_report` is async and lets the Reporter agent draft the executive summary.

### Fixed
- **Race playbook was defeated by the rate limiter** - concurrency bursts now
  bypass per-request spacing and confirm via final state, not 2xx count.
- **Destructive-method scope downgrade** - a per-step flag could mask a destructive
  method; detection is now fail-safe (method OR explicit).
- **Success-condition eval scoping** - variables (e.g. `text`) were invisible inside
  comprehensions like `any(w in text for w in [...])`; the namespace is now exposed
  as globals so comprehensions resolve free vars (this had silently broken confirmations).
- **Crawler dropped query strings** - `/product?productId=1` was fetched as
  `/product`, missing parameterized pages and their forms; refs now keep their query.
- `net_balance_delta` was hardcoded to `0` (economic conditions could never confirm).
- Circular import between `testing` and `inference`.
- Stale/odd generated directories and unused imports removed; pyflakes clean.

### Security
- No request reaches the network without passing the scope guard; dry-run by default.
- **PII redaction** of evidence/logs (emails, PANs, JWTs, keys, auth headers) unless
  `allow_pii_capture` is explicitly set.
- Structured **audit trail** of all outbound requests.
- Burp integration is **keyless** (loopback MCP) - no Burp API key handled.

### Verified
- **Autonomous agent (live, real LLM):** a Qwen brain (NVIDIA NIM - no stub, no hardcoded
  flow) drove the agent loop to solve a controlled price-tamper target in 2 calls
  (~10s): GET `/product` -> POST `/buy` with `price=1` + the CSRF it extracted itself
  -> objective met -> skill learned. The LLM composed the exploit from tools.
- All four NVIDIA NIM model IDs (`deepseek-ai/deepseek-v4-pro`, `z-ai/glm-5.1`,
  `moonshotai/kimi-k2.6`, `qwen/qwen3.5-397b-a17b`) live-pinged `200 OK`.
- **Autonomously solved two real PortSwigger Web Security Academy labs**, each
  running entirely inside the Docker container, independently verified server-side:
  - *"Excessive trust in client-side controls"* - discovery -> form login -> tamper
    client-side price (133700 -> 1) -> checkout -> `is-solved`.
  - *"High-level logic vulnerability"* - discovery captured the catalog + store
    credit -> jacket ×1 + cheapest filler ×(‑282) to balance the total under credit
    -> checkout -> `is-solved`.
  - *"Inconsistent security controls"* - register -> confirm via the email client ->
    change email to `@dontwannacry.com` -> `/admin` -> delete `carlos` -> `is-solved`.

[Unreleased]: https://example.com/venom/compare/v0.1.0...HEAD
[0.1.0]: https://example.com/venom/releases/tag/v0.1.0
