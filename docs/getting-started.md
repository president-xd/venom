# Getting started

## Requirements

- Python **3.10+** (developed/tested on 3.14).
- Runtime dependencies are tiny: `httpx`, `python-dotenv`, `pyyaml`.
  Optional extras: `faiss-cpu`+`numpy` (dense RAG), `mcp` (Burp), `pytest`+`pytest-asyncio` (dev).

## Install

```bash
cd D:\MANTIS
py -m venv .venv
# Windows:  .\.venv\Scripts\Activate.ps1
# POSIX:    source .venv/bin/activate
pip install -e .
copy .env.template .env      # optional - see configuration.md
```

VENOM runs **without an LLM key** for the deterministic playbooks/flows. The
autonomous engine (`oneshot` / `hunt`) and the web console's live hunt **require** a
provider (e.g. `DEEPSEEK_API_KEY`). See [configuration.md](configuration.md).

## Run the tests (the proof of correctness)

```bash
python -m pytest -q
# expected: 154 passed, 8 skipped  (asyncio_mode=auto)
```

The test suite is the source of truth for what actually works. Highlights:

- `tests/test_scope.py` - the scope guard blocks out-of-scope / expired / over-budget
  destructive requests.
- `tests/test_tools.py` - action grounding, and that the success oracle never confirms
  from a baked-in lab string.
- `tests/test_exploit_sandbox.py` - the sandbox blocks escapes (imports, format-string
  dunder traversal) and gives agent code the helpers it needs.
- `tests/test_redaction_audit.py` - secret redaction + the HMAC-signed audit trail.
- `tests/test_web_auth.py` - password hashing, signed sessions, login gating, per-user
  isolation.

> A few suites that exercise an internal, deliberately-vulnerable lab (used in
> development, not shipped in this repo) are **skipped** automatically when that lab is
> absent, so a clone stays green.

## Launch the web console

```bash
python -m venom web --open            # serves http://127.0.0.1:8080 and opens a browser
python -m venom web --host 0.0.0.0 --port 8080
```

On first start it creates a login: **user `admin`, password `venom`** (override with
`VENOM_WEB_USER` / `VENOM_WEB_PASSWORD`; the credentials are printed once on startup).
The console requires an LLM provider for its live hunt. See [web-console.md](web-console.md).

## Run a hunt from the CLI

```bash
# Validate an engagement scope
python -m venom scope --scope examples/scope.json

# LLM-frugal hunt (<=3 model calls) against an AUTHORIZED url
python -m venom oneshot https://app.example.com --objective "delete another user's account"

# Iterative agent loop
python -m venom hunt https://app.example.com --login wiener:peter
```

Both autonomous entry points require an LLM provider and only act inside an authorized
scope. See [capabilities-and-limits.md](capabilities-and-limits.md) for an honest read
on what the engine reliably does versus what depends on the reasoning model.
