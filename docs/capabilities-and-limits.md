# Capabilities and limits (the honest assessment)

This document separates three things the project deliberately keeps distinct:

- **Proven** - a passing test in this repo exercises the real behavior.
- **Model-limited** - the *harness* is sound; whether a given flaw is actually cracked
  depends on the reasoning model.
- **Out of scope / partial** - stated plainly so nothing is over-claimed.

## What is proven (harness)

These are exercised by the shipped test suite (run `python -m pytest -q`) and do not
depend on any model:

| Capability | Proof |
|------------|-------|
| Scope guard blocks out-of-scope / expired / over-budget destructive requests | `tests/test_scope.py` |
| The success oracle never confirms from a baked-in lab string | `tests/test_tools.py::test_objective_does_not_rely_on_baked_in_lab_strings` |
| Action grounding rejects invented endpoints | `tests/test_tools.py`, `tests/test_exploit_sandbox.py` |
| Sandbox blocks imports + the format-string dunder escape; allows safe stdlib + helpers | `tests/test_exploit_sandbox.py` |
| Exploit primitives are correct (modinv, overflow search, JWT/base64 forging) | `tests/test_exploit_kit.py` |
| Secret redaction + HMAC-signed, tamper-evident audit trail | `tests/test_redaction_audit.py` |
| LLM router: response cache, token budget, tracing | `tests/test_telemetry.py` |
| Web console: real engine wiring, login, per-user isolation, findings/report mappers | `tests/test_web.py`, `tests/test_web_auth.py`, `tests/test_web_app.py` |

So the parts that are "our job" per the project charter - the scope guard, action
grounding, the success oracle's string-free contract, sandboxing, evidence, redaction,
audit, and the multi-user console - are sound and covered.

> A separate, internal development suite drives the engine end-to-end against a
> deliberately-vulnerable lab. That lab is **not shipped** in this repo (it is
> unprofessional to publish a vulnerable app), so those suites are skipped automatically
> on a clone. The capability conclusions below come from that internal testing.

## What is model-limited

Whether the autonomous engine synthesizes a working exploit for a *specific* multi-step
business-logic chain depends on the model's reasoning, **not** the harness. The
confirmation itself is deterministic and string-free; the synthesis is the model's job.

From internal testing with a fast, low-cost model under a tight call budget:

- Access-control / BOLA / BFLA, mass-assignment, trusted-identity takeover,
  segregation-of-duties, network-trust-header, JWT `alg:none` forgery, and
  on-page-credential escalation solve **reliably**.
- The hardest **multi-step economic chains** (gift-card arbitrage, integer-overflow
  totals, currency-rounding, receipt-replay), brute-force loops, and 2-step
  over-fetch->mutate flows often **miss** - they are genuinely hard for a fast/cheap
  model in a few calls. They become solvable the instant a correct exploit is supplied,
  so the gap is the model's synthesis, not the oracle.
- Single-run results are **statistically noisy**: a frugal model samples differently each
  run, so borderline cases flip between runs. Judge capability per class, not by one run.

### The model lever (an honest finding)

The single biggest reliability lever is a genuinely stronger reasoning model behind the
same harness - set `VENOM_MODEL_CODEGEN=<stronger-model>` (a paid OpenRouter frontier
model, a real reasoning endpoint, etc.), no code change required. Be aware that on some
accounts a `*-reasoner` model id silently resolves to the same fast model as `*-chat`;
`venom providers` reports the model that actually answered. We do not publish a score for
a model we cannot actually run.

### Local models

Small local models (e.g. qwen-7b, deepseek-16b on ~6 GB GPU / 32 GB RAM) **cannot**
reliably chain multi-step business-logic exploits even with a perfect harness.
`qwen2.5-coder:14b` reasons better; `qwen2.5-coder:32b` (CPU-bound, slow) is roughly the
local reliability ceiling. Frontier models are the high-reliability path. Do not
over-claim local results.

## What is deliberately out of scope

- **Generic web vulns (XSS, SQLi, SSRF, ...).** VENOM targets **business logic**. The
  20-class knowledge base and the engine are tuned for logic flaws. The LLM is not
  *forbidden* from noticing other issues, but the project does not aim to be a generic
  scanner.
- **The exploit sandbox is a guardrail, not a hard security boundary.** It is AST-
  validated with restricted builtins, a stdlib-import whitelist, format-string-escape
  blocking, and a hard timeout - strong enough for an authorized operator driving a
  trusted model. For a *fully untrusted* model, run the agent inside a container too.
  See [security.md](security.md).
- **The web console auth is simple** (PBKDF2 + HMAC-signed cookies), intended for a
  localhost operator console or behind a reverse proxy / SSO - not as internet-facing
  identity infrastructure.
