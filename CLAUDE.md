# CLAUDE.md — VENOM Engineering & Operating Guide

> **Read this first, fully, before touching anything.** This file is the single
> source of truth for what VENOM is, how it is built, how to work on it, and the
> hard rules you must never break. If you are an AI agent picking up this repo
> cold, this document should give you the complete mental model.

---

## 1. What VENOM is (in one paragraph)

**VENOM** is a *Context-Aware Business-Logic Vulnerability Exploitation Agent* —
an autonomous penetration-testing system that behaves like a senior web-exploitation
engineer. Given an **authorized** target, it ingests the application's context,
reconstructs the intended business model, forms hypotheses about where the logic
can be abused, **writes and runs real exploit code in a sandbox**, and **proves**
success with evidence. It is built to hunt **business-logic flaws** (price tampering,
broken object-level auth, mass assignment, workflow/sequence skips, account
takeover via trusted-identity params, integer overflow on totals, gift-card
arbitrage, coupon abuse, email-parser/truncation tricks, etc.) on **any** web app —
not just lab targets.

The project lives at `D:\MANTIS`. The Python package is `venom`. (The old name
"MANTIS" is legacy; do not reintroduce it.)

---

## 2. Non-negotiable principles (the spirit of this project)

These come directly from the project owner and override convenience:

1. **Work honestly. No decorative code.** Every feature must be real and proven by
   a test. Do not write stubs that look done but aren't. If something is partial,
   say so explicitly — never imply completeness.
2. **Prove it with tests.** "It works" means there is a passing test that exercises
   the real behavior. Claims without a test are not accepted.
3. **Never rely on lab-specific success strings (`is-solved`) in the general
   engine.** Real enterprise apps have no such banner. Success is decided by a
   **differential oracle** or an **operator-defined marker** — never a baked-in
   string. (See §6.)
4. **Authorized engagements only.** Every outbound request passes the scope guard.
   There is no bypass flag and you must not add one.
5. **Don't blame the model; maximize what's in our hands.** Recon depth, action
   grounding, the success oracle, sandboxing, and evidence are *our* job. A capable
   model should succeed because the harness is sound.
6. **Secrets never reach logs or artifacts.** Redaction is always on. (See §9.)
7. **Business-logic exploitation is the scope.** Do not drift into generic
   scanner/XSS/SQLi territory unless explicitly asked.

---

## 3. Repository map (what lives where)

```
venom/                         # the product (importable package `venom`)
  __init__.py                  # exports Scope/ScopeError; scope-guard invariant note
  __main__.py                  # `python -m venom`
  cli.py                       # CLI: scope|ingest|providers|agents|burp|run|hunt|oneshot
  _env.py                      # dependency-free .env loader (env vars win)
  config.py                    # logging config; installs the secret-redaction filter
  utils.py                     # redact_secrets(), SecretLogFilter
  audit.py                     # RunMetrics (observability) + HMAC-signed audit trail

  core/
    scope.py                   # THE safety boundary — authorization, kill-switch, budgets
    registry.py                # EndpointRegistry / Endpoint — the discovered surface
    graph.py                   # BusinessModelGraph — reconstructed business model

  ingest/                      # turn a target into a structured surface
    crawler.py                 # crawl + form/link discovery -> registry
    recon.py                   # enrich_recon(): probe surface as current user (accessible/denied map)
    pipeline.py openapi.py graphql.py jsbundle.py traffic.py

  cognition/                   # the AUTONOMOUS brain (runs on ANY app)
    objective.py               # Objective + the differential/marker success oracle  ⭐
    oneshot.py                 # oneshot_hunt(): recon -> 1 synthesis -> sandboxed exploit -> verify ⭐
    agent.py                   # iterative Agent loop (skill replay, backtracking, caps)
    agent_brain.py             # strict-args prompt, surface-ranked KB priors, retries
    evaluate.py                # success_rate(): reliability harness (X% over N runs)

  tools/
    base.py                    # Toolbox: scope-guarded tools + run_exploit_code sandbox ⭐
                               #   action grounding (known_paths), AST validation, timeouts

  llm/
    providers.py               # provider routing: NVIDIA NIM, OpenRouter, Ollama; fallback, throttle
    budget.py telemetry.py

  knowledge/
    business_logic.py          # KB of business-logic priors + rank_kb()/kb_prompt(surface=)

  engine/
    http_client.py             # ScopedClient — every request goes through the scope guard
    auth.py                    # AuthManager / Identity (form_login, bearer, cookie, basic)
    runner.py

  agents/
    roles.py                   # AgentSpec fleet (roles -> provider+model); CODEGEN, RESEARCH, ...
    orchestrator.py base.py

  flows/                       # ⚠ PortSwigger-LAB-SPECIFIC deterministic solvers (NOT the general engine)
    account_privilege.py account_takeover.py coupon_stacking.py email_parser.py
    encryption_oracle.py exceptional_input.py infinite_money.py integer_overflow.py
    login_statemachine.py workflow_skip.py   # each solves one lab; is-solved = lab ground truth here

  testing/
    schema.py                  # TestCase/TestStep/Verdict/Severity/VulnClass
    web_playbooks.py playbooks.py generator.py
  inference/ memory/ rag/ report/ integrations/ prompts/ data/

vulnlab/                       # our OWN deliberately-vulnerable test app (37 labs, easy->hard)
  labs.py                      # Lab registry: handlers + metadata (objective/win_action/difficulty) ⭐
  app.py                       # shared login/index + dispatch; MockTransport + real http.server

scripts/
  eval_vulnlab.py              # end-to-end: drive oneshot_hunt against all 37 labs; scorecard

tests/                         # pytest; asyncio_mode=auto. 220+ tests. THE proof of correctness.
```

⭐ = the files you will most often need to understand. Read them before editing nearby code.

---

## 4. The two execution paths (know which one you're touching)

VENOM has **two distinct success paths**, and conflating them is the most common mistake:

### A. The general autonomous engine — `cognition/` (+ `tools/`, `ingest/`, `llm/`)
This is what runs against **arbitrary real apps**. It is model-driven and must be
fully generalizable. **It must never depend on lab-specific strings.** Entry points:
- `oneshot_hunt(...)` — LLM-frugal (default ≤3 calls). Preferred for rate-limited / slow models.
- `Agent` loop — iterative, more calls, for capable/fast models.

### B. The PortSwigger lab solvers — `venom/flows/*` (+ `engagement.py`, `web_playbooks.py`)
Deterministic, hand-written exploiters that exist **only** to solve specific
PortSwigger labs. Here `is-solved` is the lab's authoritative ground truth (exactly
like a unit test's expected value). **These never run against enterprise targets.**
Do not "clean up" their `is-solved` checks — that would break a correct tool.

> If a task says "make it work on real apps / not rely on is-solved," it concerns
> **path A**. If it says "solve PortSwigger lab X," it's **path B**.

---

## 5. The oneshot strategy (the core loop — understand this deeply)

`venom/cognition/oneshot.py :: oneshot_hunt(scope, registry, synthesize, *, objective, transport, max_llm_calls=3)`

1. **Deterministic recon is already done** (crawler -> `EndpointRegistry`).
2. Build **action-grounding set** `toolbox.known_paths` from the registry (plus `/`,
   `win_url`, and the win-action path so the oracle isn't blocked).
3. `enrich_recon()` probes the surface as the current user -> `accessible_to_you` /
   `denied_to_you` maps (the "what you can/can't do" senior-tester view).
4. Compute `build_brief()` — a compact, token-cheap recon summary.
5. **Baseline check:** if the win action already works un-escalated, it's not a flaw -> return `[]`.
6. **Bounded synthesis loop** (≤ `max_llm_calls`):
   - Ask the model ONCE for `VULN: <id>` + a fenced ```python `async def exploit(http): ...` block.
   - Run it in the sandbox (`toolbox.run_exploit_code`).
   - Check the **differential oracle**. If met -> emit a `TestCase` with proof,
     `RunMetrics`, and a **signed audit trail** in `evidence`.
   - If not met -> feed back SHARP, specific guidance; invented endpoints
     (grounding violations) are surfaced loudly.
7. Total LLM calls are **hard-capped** — this is what survives free-tier rate limits.

**Why fenced code, not JSON-embedded code:** small/local models mangle JSON-escaped
multi-line code. Fenced blocks are far more reliable. Keep it that way.

---

## 6. The success oracle (the heart of "enterprise-grade") — `cognition/objective.py`

`Objective` decides what "won" means, in this strict priority:

1. **Differential (preferred, app-agnostic):** a concrete `win_action`
   (`{"method","path","data"}`) that is **denied** for the un-escalated user
   (baseline) and **succeeds** after the exploit. No strings required.
2. **Operator-defined marker (only if explicitly set):** `success_text` or
   `win_signals` substrings at `win_url`.
3. **Neither defined -> `check()` returns `False`** (honest "unknown"). VENOM does
   **not** guess success from any baked-in banner.

**`_DEFAULT_SIGNALS` is empty.** Do not add lab strings (`is-solved`,
`congratulations`, ...) back into it. Proven by
`tests/test_tools.py::test_objective_does_not_rely_on_baked_in_lab_strings`.

---

## 7. VulnLab — our own proving ground (`vulnlab/`)

A single deliberately-vulnerable app with **37 real, exploitable labs** (no fake
banners — each `solved` flag flips only on the genuine exploit). Registry lives in
`vulnlab/labs.py` (one source of truth: handler + metadata).

The 37 labs span three batches (all in `vulnlab/labs.py`): the original 11
(price, idor, coupon, pin, mass, negqty, workflow, trustid, io, money, reg);
enterprise I+II (jwt, bola, reset, refund, bank, tenant, scope, billing, loyalty,
invoice, twofa, records, files, deploy, referral); and enterprise III — realistic
new surfaces (graphql, cookie, selfapprove, stack, fx, iam, receipt, batch,
license, headerip, quota). Flaw classes cover client-trust, IDOR/BOLA, BFLA,
mass-assignment, trusted-identity/-param, integer-overflow, brute-force, JWT
alg:none, token/secret disclosure & forgery, replay, segregation-of-duties,
network-trust headers, and economic abuse (coupon/loyalty/billing/fx/referral).

- Both oracle modes are exercised on purpose: a **differential** win action
  (delete/remove carlos style) for access-control labs, and an operator **marker**
  for economic wins.
- Exposed two ways from the same pure `handle()`: `make_transport()` (in-process
  `httpx.MockTransport` for tests) and `serve()` (real `http.server` for Docker/live).
- **Every lab has a human-authored solving exploit + negative test** in
  `tests/test_vulnlab_labs.py`. That is the baseline the LLM is measured against.
- Run the model against all of them: `python scripts/eval_vulnlab.py` (needs VulnLab
  serving on :8000 and an LLM provider configured).

When you add a lab: add a handler + `Lab(...)` entry in `labs.py`, add a deterministic
solving test AND a negative test in `tests/test_vulnlab_labs.py`, and it auto-appears
in the eval scorecard.

---

## 8. LLM providers & models (`venom/llm/providers.py`, `.env`)

- **Providers:** `DEEPSEEK` (paid primary, OpenAI-compatible — `deepseek-chat`/
  `deepseek-reasoner`), `NVIDIA_NIM`, `OPENROUTER`, `OLLAMA` (local). All agent
  roles default to `deepseek-chat`. Anthropic is removed (no key) — do not reintroduce it.
- **Fallback chain:** DeepSeek → NVIDIA → OpenRouter → Ollama, with throttle (RPM)
  and 429 same-provider retry. Robust JSON parsing handles reasoning-model
  `content`/`reasoning_content`/`tool_calls`.
- **Air-gap mode** (`LLM_AIR_GAP=true`): forces Ollama-only; nothing leaves the box.
- **Local model reality (proven, be honest about it):** on typical hardware (e.g.
  6 GB GPU, 32 GB RAM) small local models (qwen-7b, deepseek-16b) **cannot** reliably
  chain multi-step business-logic exploits even with a perfect harness. `qwen2.5-coder:14b`
  reasons better; `qwen2.5-coder:32b` (CPU-bound, slow) is the local reliability ceiling.
  Frontier models via OpenRouter (e.g. Llama-4 Maverick) are the high-reliability path.
  **Model strength is the variable; the harness is sound.** Do not over-claim local results.
- Ollama context: `OLLAMA_NUM_CTX` (default 8192) so the recon brief isn't silently
  truncated — truncation is a real hallucination cause; never drop below the brief size.
- **Key env vars:** `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, `NVIDIA_API_KEY`,
  `NVIDIA_RPM`, `OLLAMA_MODEL`, `OLLAMA_BASE_URL`, `LLM_AIR_GAP`, `VENOM_MODEL_<ROLE>`.

---

## 9. Safety, governance & observability (enterprise layer)

- **Scope guard (`core/scope.py`)** is the single chokepoint. `assert_request_allowed`
  enforces: host allow-list, out-of-scope blocks, time window, **kill switch**
  (`VENOM_KILL_SWITCH=1` halts ALL requests), destructive permission
  (`allow_destructive`) and **destructive budget** (`max_destructive_actions`).
- **Sandbox (`tools/base.py :: run_exploit_code`)**: AST validation (`_validate_exploit_ast`,
  banned names), restricted builtins, hard timeout. Agent-authored `http()` is
  **action-grounded** — calls to endpoints not in `known_paths` are rejected and reported.
- **Secret redaction (`utils.py`)**: always-on `redact_secrets()` + `SecretLogFilter`
  strips `nvapi-`, `sk-or-`, `sk-ant-`, bearer/api-key material from logs/artifacts.
- **Audit (`audit.py`)**: HMAC-SHA256 signed, tamper-evident records (`VENOM_AUDIT_KEY`);
  `RunMetrics` for observability (llm_calls, requests, tokens, est_cost, elapsed).

---

## 10. How to run things

```bash
# Tests (the real proof). asyncio_mode=auto, testpaths=tests.
python -m pytest -q                       # full suite (expect ~220 passed, 2 skipped)
python -m pytest tests/test_vulnlab_labs.py -q   # the 11-lab ground-truth proofs

# CLI (entry point: `venom` == venom.cli:main)
python -m venom scope <scope.json>        # validate/summarize an engagement scope
python -m venom providers                 # ping configured LLM providers
python -m venom oneshot --url ... --objective "..."   # LLM-frugal hunt
python -m venom hunt --url ...            # iterative autonomous agent

# VulnLab end-to-end eval (start the app first, then run the harness)
python -m vulnlab.app                     # serve on :8000 (or `docker compose up vulnlab`)
python scripts/eval_vulnlab.py            # scorecard across all 37 labs
python scripts/eval_vulnlab.py price mass # subset
```

Opt-in live-LLM tests are gated by `VENOM_LIVE_LLM=1` (skipped by default).

---

## 11. Conventions & house style

- **Python ≥ 3.10**, std-lib-first. Runtime deps are tiny: `httpx`, `python-dotenv`,
  `pyyaml` (FAISS/numpy optional for RAG). Don't add heavy deps casually.
- **Async throughout** the engine/tools/cognition. Tests use `asyncio_mode=auto`.
- Dataclasses for structured types (`Scope`, `Objective`, `Lab`, `TestCase`, `RunMetrics`).
- Keep modules focused and documented with a top docstring explaining *why*.
- Comments explain rationale and flaws ("# FLAW: trusts client price"), not the obvious.
- New behavior **must** ship with a test. Prefer in-process `httpx.MockTransport`
  over network in tests.
- Keep the public API of `vulnlab/app.py` stable: `handle`, `new_state`,
  `make_transport`, `serve`, `PIN`, `ADMIN_TOKEN`, `LABS` (other modules/tests import these).

---

## 12. DO's (in depth)

- **DO** read `cognition/objective.py`, `cognition/oneshot.py`, `tools/base.py`,
  and `vulnlab/labs.py` before changing agent/oracle/lab behavior.
- **DO** decide success via the **differential oracle** first; only fall back to an
  **operator-defined** marker; otherwise return an honest `False`.
- **DO** keep agent-authored exploits **action-grounded** — confined to discovered
  endpoints. If grounding blocks a legitimate path, add it to `known_paths` deliberately
  (as the oracle exemptions already do), don't loosen the guard globally.
- **DO** route every outbound request through the scope guard / `ScopedClient`.
- **DO** keep LLM usage frugal where rate limits bite; respect `max_llm_calls`.
- **DO** give the model **sharp, specific feedback** on failed attempts (what was
  denied, which endpoints were invented, what to escalate). Vague prompts waste calls.
- **DO** add both a **solving test and a negative test** for every new VulnLab lab,
  and prove the exploit yourself before pointing a model at it.
- **DO** be explicit and honest in reports/summaries about what is proven vs. partial
  vs. model-limited. Distinguish "the harness can't" from "the model didn't".
- **DO** keep secrets in `.env`; rely on the always-on redaction for logs.
- **DO** run the full test suite after any change to shared code (scope, oracle,
  tools, providers, vulnlab) — these have wide blast radius.

## 13. DON'Ts (in depth)

- **DON'T** reintroduce baked-in lab strings (`is-solved`, `congratulations`,
  `you solved the lab`) into the general engine (`cognition/`, `Objective` defaults).
  That is the exact enterprise anti-pattern this project rejects.
- **DON'T** confuse the two execution paths (§4). Don't strip `is-solved` from
  `venom/flows/*` — there it is correct lab ground truth, not the general engine.
- **DON'T** add a scope-bypass flag, disable the kill switch, or weaken the sandbox /
  action grounding to "make a test pass." Fix the real cause.
- **DON'T** write decorative/stub code that appears complete. If it's partial, say so.
- **DON'T** claim something works without a passing test that exercises it.
- **DON'T** fabricate results, success rates, or "figures." Report real numbers from
  real runs (e.g. the eval scorecard), including failures.
- **DON'T** over-claim local-model capability. Be honest that small local models fail
  multi-step chaining; don't dress that up.
- **DON'T** put exploit code inside JSON for synthesis — use fenced ```python blocks.
- **DON'T** add the Anthropic provider or the old "MANTIS" name back.
- **DON'T** lower `OLLAMA_NUM_CTX` below the brief size, or remove recon enrichment —
  both directly cause endpoint hallucination.
- **DON'T** run against any target that isn't in an authorized scope. Authorized
  engagements only — no exceptions.
- **DON'T** commit/push unless explicitly asked. When asked, follow the existing
  per-file commit convention in `commit.sh`.

---

## 14. When you finish a task (checklist)

1. Did you add/extend a **test** that proves the real behavior? Does `pytest -q` pass?
2. Did you touch the **general oracle**? Re-verify no baked-in lab strings and the
   differential path still works.
3. Did you touch **scope/sandbox/grounding**? Re-verify the guards still reject
   out-of-scope / invented-endpoint / destructive-over-budget cases.
4. Did you change **providers/.env**? Confirm air-gap, fallback, and redaction still hold.
5. Are your claims **honest** — proven vs. partial vs. model-limited clearly separated?
6. Did you avoid scope creep (business-logic exploitation only, unless asked)?

---

## 15. Glossary

- **Differential oracle** — success = (win action denied at baseline) AND (succeeds
  after exploit). The app-agnostic, string-free way to know we won.
- **Action grounding** — restricting agent-authored exploit code to endpoints that
  were actually discovered, so the model can't hallucinate paths.
- **oneshot** — the LLM-frugal hunt loop (≤ N synthesis calls). Survives rate limits.
- **Marker mode** — operator-defined `success_text`/`win_signals` fallback when no
  win action exists. Only active when explicitly configured.
- **VulnLab** — our local multi-lab vulnerable app for proving the harness + model.
- **Flows** — deterministic PortSwigger lab solvers; *not* the general engine.
- **Scope guard** — the single authorization chokepoint; no bypass exists.
```
