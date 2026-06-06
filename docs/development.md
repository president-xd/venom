# Development

## Conventions

- **Python ≥ 3.10**, std-lib first. Runtime deps are tiny (`httpx`, `python-dotenv`,
  `pyyaml`); don't add heavy deps casually.
- **Async throughout** the engine/tools/cognition. Tests use `asyncio_mode=auto`.
- Dataclasses for structured types (`Scope`, `Objective`, `Lab`, `TestCase`, `Finding`,
  `RunMetrics`).
- Comments explain rationale and flaws (`# FLAW: trusts client price`), not the obvious.
- **New behavior must ship with a test.** Prefer in-process `httpx.MockTransport` over
  network in tests. A claim without a passing test is not accepted.

## Running tests

```bash
python -m pytest -q                       # full suite (expect 154 passed, 8 skipped)
python -m pytest tests/test_web_auth.py -q          # console auth + per-user isolation
python -m pytest tests/test_exploit_sandbox.py -q   # the sandbox + action grounding
python -m pytest tests/test_scope.py -q             # the scope guard
```

Opt-in live-LLM tests are gated by `VENOM_LIVE_LLM=1` (skipped by default). A few
suites exercise an internal, deliberately-vulnerable lab used in development; it is not
shipped in this repo, and those suites are skipped automatically when it is absent
(`pytest.importorskip`), so a clone stays green.

## Adding an exploit primitive

General, dependency-free helpers go in `tools/exploit_kit.py` and are registered in
`KIT` (which is injected into the sandbox namespace). They must be pure (no IO, no host
access). Add them to the prompt's helper list in `cognition/oneshot.py` and the catalog
in `tools/base.py`, and cover them in `tests/test_exploit_kit.py`.

## Touching shared code? Re-verify the guards

Some modules have wide blast radius. After changing any of them, run the full suite:

- **scope / sandbox / grounding** - re-verify the guards still reject out-of-scope,
  invented-endpoint, and destructive-over-budget cases.
- **the oracle (`cognition/objective.py`)** - re-verify there are **no** baked-in lab
  strings and the differential path still works.
- **providers / `.env`** - confirm air-gap, fallback, and redaction still hold.
- **web routes** - `routes.handle` returns `(status, body, content_type, extra_headers)`;
  per-user data endpoints are owner-gated.

## Finish checklist

1. Did you add/extend a **test** that proves the real behavior? Does `pytest -q` pass?
2. Did you touch the **oracle**? No baked-in lab strings; differential path intact.
3. Did you touch **scope/sandbox/grounding**? Guards still reject the bad cases.
4. Are claims **honest** - proven vs. partial vs. model-limited clearly separated?
5. Stay in scope: business-logic exploitation, unless explicitly asked otherwise.
