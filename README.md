# VENOM

**Context-aware business-logic penetration testing agent** — the runtime for the
CIPHER system prompt. VENOM reconstructs how an application is *supposed* to
work, then systematically attacks every assumption that model rests on:
sequence violations, BOLA/IDOR, race conditions, parameter/type confusion,
mass-assignment privilege escalation, and economic-flow abuse.

> ⚠️ **Authorized engagements only.** VENOM loads an authorization *scope object*
> before any action and refuses to send a single request outside it. There is no
> bypass flag. Testing any target without explicit written authorization is
> illegal and unsupported.

---

## Pipeline

```
load scope ─► ingest / DISCOVER ─► infer model ─► generate ────► execute ──────────► confirm ─────► report
  (authz +    OpenAPI/GraphQL/HAR/   LLM fleet or   concrete        authenticated,      state-delta /  md+json+
  identities) Burp/JS  +  crawler    heuristic      exploits + RAG  provisioned, burst  HTML/reflect   SARIF+audit
```

## Two target modes: JSON APIs **and** classic web apps

VENOM is not JSON-only. It handles both:

- **API mode** — OpenAPI/GraphQL/HAR artifacts, JSON bodies, bearer/JSON-token login, JSONPath confirmation.
- **Web-app mode** — point it at a URL and it **crawls to discover** forms/links/params (no artifacts needed), logs in via **HTML form + CSRF + session cookie**, sends **form-encoded** requests, and **confirms from HTML** (response text, reflected fields, before/after state). A bundled forced-browse wordlist (`venom/data/wordlists/common.txt`, shipped in Docker) surfaces hidden/privileged pages.

```bash
# Point-and-shoot against a live web app (no artifacts):
venom run --scope scope.json --crawl --live
```

Web-app business-logic classes covered: client-side trust / price & parameter
tampering, web IDOR (cross-account), and broken access control (forced browsing).
Proven end-to-end against an in-memory vulnerable HTML shop in
`tests/test_web_app.py` (discovery → form login → confirm).

Every outbound request passes through `Scope.assert_request_allowed()` and a
token-bucket rate limiter, and carries `X-Pentest-ID: <engagement_id>` so the
target's blue team can filter test traffic.

## Reasoning mode (`--think`) — beyond playbooks

Playbooks are fast and deterministic, but they can only do what's coded. For
flaws nobody pre-wrote, VENOM has an **adaptive reasoning loop**
([`venom/cognition/`](venom/cognition/)):

```
observe → cheap PROBE → read the real response → RE-THINK → EXPLOIT → VERIFY
```

The LLM is given the discovered surface plus a **business-logic knowledge base**
([`venom/knowledge/`](venom/knowledge/), 12 classes from OWASP WSTG + PortSwigger)
as *priors*, and decides one action at a time — preferring to learn before it
strikes. The decision "brain" is pluggable (LLM in production, deterministic stub
in tests), so the loop mechanics are verified independently of any model
(`tests/test_cognition.py`).

```bash
venom run --scope scope.json --crawl --think --live
```

All LLM input is **budget-trimmed** ([`venom/llm/budget.py`](venom/llm/budget.py))
and HTML is compacted to its form/link/text skeleton, so VENOM stays within
free-tier context limits.

> Honest scope: the reasoning loop *architecture* is tested and proven; whether it
> cracks a given novel flaw depends on the LLM. Playbooks remain the reliable path
> for known classes, and both run together.

## Multi-agent fleet

The reasoning stages are driven by a fleet of agents, each backed by the model
best matched to its job — all served through a **single NVIDIA NIM key**, with
**DeepSeek as the base model**:

| Agent | Model | Job |
|-------|-------|-----|
| **Orchestrator** (main) | `deepseek-ai/deepseek-v4-pro` | Planning, business-model synthesis, coordination |
| **Research** | `z-ai/glm-5.1` | Domain-doc analysis, similar-vuln recall |
| **Hypothesis** | `moonshotai/kimi-k2.6` | Adversarial attack-chain generation (5 lenses) |
| **CodeGen** | `qwen/qwen3.5-397b-a17b` | Concrete test steps / payloads |
| **Summarizer** | `qwen/qwen3.5-397b-a17b` | Cheap, high-volume result summaries |
| **Reporter** | `deepseek-ai/deepseek-v4-pro` | Final report prose |

**Where to select models:** in `.env`, via `VENOM_MODEL_<ROLE>` (see
`.env.template`). `venom agents` prints the live mapping; `venom agents --ping`
tests each model. If no NVIDIA key is set, VENOM drops to the deterministic
**offline** pipeline automatically.

## Install

```powershell
cd D:\VENOM
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e .
copy .env.template .env   # then edit .env (optional — runs offline without keys)
```

No LLM keys? VENOM runs in **offline mode**: deterministic playbook generation
and a heuristic business model. Add an `ANTHROPIC_API_KEY` (or OpenRouter / NVIDIA
/ local Ollama) to enable LLM rule inference and adversarial hypotheses.

## Usage

```powershell
# 1. Validate an engagement scope
venom scope --scope examples\scope.json

# 2. Ingest artifacts and inspect the endpoint registry (risk-ranked)
venom ingest --in examples\

# 3. Check providers / the multi-agent model fleet
venom providers
venom agents            # show role -> model mapping
venom agents --ping     # live-test each NVIDIA NIM model
venom burp --status     # check the local Burp MCP endpoint

# 4. Full engagement — DRY-RUN by default (sends nothing)
venom run --scope examples\scope.json --in examples\ --out venom_data\reports\eng-001

# 5. Execute for real (only inside the authorized window; guard still applies)
venom run --scope examples\scope.json --in examples\ --live
```

Outputs land in the `--out` directory:
- `report.md` — executive summary, scope, findings, full test appendix
- `findings.json` — machine-readable findings + every test case
- `business_model.json` — the reconstructed entity/transition/rule/actor graph

## Authenticated, multi-actor testing (identities)

Business-logic flaws live in *authenticated, stateful, multi-actor* flows, so the
scope carries **identities**. VENOM logs each in (capturing tokens/cookies),
keeps isolated sessions, and auto re-logins + retries once on 401/403:

```json
"identities": [
  {"name": "attacker", "role": "free_user", "auth": {
     "type": "login", "method": "POST", "path": "/api/v1/login",
     "body": {"username": "a@x.com", "password": "..."},
     "token_path": "$.access_token", "place": "header",
     "header": "Authorization", "scheme": "Bearer"}},
  {"name": "victim", "role": "premium_user", "auth": {"type": "login", "...": "..."}}
]
```

Auth types: `login` (recommended), `bearer`, `cookie`, `basic`.

## How findings are confirmed (not just attempted)

Each test case can carry **provisioning** (`setup_steps`, often run as the victim
to create a real target object), and a **state probe** (a GET run *before and
after* the attack). The runner exposes `*_before`, `*_after`, `*_delta`, and
`net_balance_delta` to each step's `success_condition`, so confirmation is
grounded in actual state change, e.g.:

- **IDOR** — victim provisions an object; attacker reads it → confirmed on `status == 200 and bool(body)`.
- **Race** — a true concurrency *burst* (rate-limiter bypassed) drives a wallet
  balance below zero → confirmed on `results_2xx > 1 and balance_after < 0`, not a 2xx count.
- **Mass assignment** — confirmed only when the server **reflects** an injected
  privileged field (`body.get('role') == 'admin'`).
- **Sequence bypass** — terminal transition (refund) succeeds without its precondition.

Every confirmed finding carries evidence: the before/after state, deltas, and a
request log. A full end-to-end proof against an in-memory vulnerable API lives in
`tests/test_integration_vuln_app.py`.

## RAG prior-art corpus

Hypotheses and findings are augmented with similar real-world writeups via a
built-in TF-IDF corpus (`venom/rag/`) — no heavy deps. Extend it at
`VENOM_DATA_DIR/rag/corpus.json`.

## Scope object

Saved as `venom_data/engagements/<id>/scope.json` (see `examples/scope.json`):

```json
{
  "engagement_id": "ENG-2026-001",
  "target_name": "AcmePay",
  "authorized_base_urls": ["https://api-staging.acmepay.example.com"],
  "out_of_scope": ["stripe.com", "auth0.com"],
  "rate_limit_per_second": 5,
  "allow_destructive": false,
  "authorized_by": "Jane Smith, CISO",
  "authorization_date": "2026-06-01T00:00:00Z",
  "expiry_date": "2026-06-30T23:59:59Z"
}
```

`authorized_base_urls` gate by scheme + host + port + path prefix. Requests
outside that set, to anything in `out_of_scope`, after `expiry_date`, or
destructive methods without `allow_destructive`, are blocked at the HTTP layer.

## Package layout

```
venom/
  config.py            Settings from .env
  llm/providers.py     Multi-provider router (Anthropic/OpenRouter/NVIDIA/Ollama)
  agents/              Multi-agent fleet: roles, Agent, Orchestrator (DeepSeek base)
  integrations/        Keyless Burp Suite MCP client (loopback SSE)
  core/
    scope.py           Authorization guard (the safety boundary)
    registry.py        Unified endpoint registry + risk tiering
    graph.py           Business model graph (entities/transitions/rules/actors)
  ingest/              OpenAPI, GraphQL, HAR, Burp XML, JS bundles + live crawler
  inference/           LLM rule inference + adversarial hypothesis generation
  rag/                 Writeup corpus + TF-IDF retriever (prior-art augmentation)
  testing/             Schema, API playbooks, web-app playbooks, generator
  engine/              Scope-guarded client + auth/identities + state-delta runner
  report/              Findings + evidence + Markdown/JSON/SARIF + audit trail
  data/wordlists/      Bundled forced-browse wordlist (packaged into Docker)
  utils.py             JSONPath, HTML extract, PII redaction, sandboxed eval
  prompts/             Bundled CIPHER master system prompt
  engagement.py        End-to-end orchestrator
  cli.py               Command-line interface
scripts/               Burp + MCP download/run scripts (PowerShell + bash)
```

## Docker

A multi-stage, **non-root** image is provided, plus a Compose file with an
optional local Ollama backend.

```bash
# Build the image
docker build -t venom-agent:0.1.0 .

# The container IS the `venom` CLI — append subcommands:
docker run --rm venom-agent:0.1.0 scope --scope examples/scope.json
docker run --rm -v "$PWD/venom_data:/data" venom-agent:0.1.0 \
    run --scope examples/scope.json --in examples/ --out /data/reports/eng-001
```

### Compose

VENOM is a CLI, so use `run` rather than `up`:

```bash
cp .env.template .env                         # optional — runs offline without it
docker compose build
docker compose run --rm venom scope --scope examples/scope.json
docker compose run --rm venom run --scope examples/scope.json --in examples/
```

Drop your own engagement files into `./engagements/` (bind-mounted read-only at
`/engagements`) and reports land in `./venom_data/`.

### Local / air-gapped LLM (Ollama)

```bash
docker compose --profile local up -d ollama
docker compose exec ollama ollama pull llama3.1:8b
# In .env set LLM_AIR_GAP=true (or air_gap_mode in the scope) to route all
# inference to the local model — nothing leaves the network.
docker compose --profile local run --rm venom providers
```

The Compose file wires `OLLAMA_BASE_URL` to the `ollama` service automatically.
Uncomment the `deploy.resources` block in `docker-compose.yml` for GPU inference.

## Burp Suite MCP (keyless, local)

**No API key.** The PortSwigger "MCP Server" extension runs inside Burp on your
machine and exposes a loopback SSE endpoint; VENOM speaks MCP to it over
`127.0.0.1`. Provisioning scripts make it available before you run:

```powershell
pwsh scripts/setup_burp.ps1      # download Burp + the MCP extension into ./tools/burp
pwsh scripts/run_burp_mcp.ps1    # launch Burp with the extension auto-loaded
```

```bash
scripts/setup_burp.sh            # bash equivalents
scripts/run_burp_mcp.sh
scripts/setup_burp.sh --check    # verify what's installed, download nothing
```

Then in `.env` set `BURP_MCP_ENABLED=true`, install the client SDK with
`pip install "venom-agent[burp]"`, and verify with `venom burp --status`.
When Burp isn't running, VENOM falls back to `httpx` execution and exportable
artifacts — the engagement still runs.

> Burp needs a Java 17+ runtime. The Community jar works for traffic/Repeater;
> some MCP tools (active scan, Intruder throttling) require Burp Pro.

## Tests

```powershell
pip install pytest pytest-asyncio
pytest
```

## Safety model (non-negotiable)

- No request leaves the process without passing the scope guard.
- `run` is **dry-run by default**; real traffic requires explicit `--live`.
- Rate limiting is enforced per the scope's `rate_limit_per_second`.
- Destructive methods require `allow_destructive: true`.
- Observed secrets in artifacts are redacted, never printed in full.
- The agent stops at proof-of-concept; it never persists access or destroys data.
