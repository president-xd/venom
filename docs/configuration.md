# Configuration

Configuration is via `.env` (loaded by a dependency-free loader; real environment
variables win) and the per-engagement **scope object**. Copy `.env.template` to `.env`
and edit.

## LLM providers

VENOM routes LLM calls across providers with a fallback chain
(**DeepSeek -> NVIDIA NIM -> OpenRouter -> Ollama**), proactive RPM throttling, and a
same-provider 429 retry. **DeepSeek** is the paid primary (OpenAI-compatible).

| Variable | Purpose |
|----------|---------|
| `DEEPSEEK_API_KEY` | DeepSeek key (paid primary) |
| `DEEPSEEK_MODEL` | default `deepseek-chat` (V3); `deepseek-reasoner` (R1) for deeper, slower reasoning |
| `DEEPSEEK_BASE_URL`, `DEEPSEEK_RPM` | endpoint + rate cap |
| `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` | OpenRouter (cloud fallback / frontier models) |
| `NVIDIA_API_KEY`, `NVIDIA_NIM_BASE_URL`, `NVIDIA_RPM` | NVIDIA NIM |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_NUM_CTX` | local/air-gapped (default ctx 8192 so the recon brief is not silently truncated) |
| `LLM_MODE` | `default` / `budget` / `air_gap` routing |
| `LLM_AIR_GAP` | `true` forces Ollama-only (nothing leaves the box) |
| `VENOM_REQUIRE_LLM` | fail closed if no provider is configured |
| `VENOM_MODEL_<ROLE>` | per-role model override (`ORCHESTRATOR`, `RESEARCH`, `HYPOTHESIS`, `CODEGEN`, `SUMMARIZER`, `REPORTER`) |
| `VENOM_NVIDIA_MODELS` | register NIM aliases (`alias=full/model-id`, comma-separated) |

> **Honest note on models:** which model `deepseek-chat`/`deepseek-reasoner` actually
> resolves to depends on the DeepSeek account/endpoint. `venom providers` reports the
> model that actually answered. The single biggest reliability lever is a stronger
> reasoning model behind the same harness - set `VENOM_MODEL_CODEGEN`. See
> [capabilities-and-limits.md](capabilities-and-limits.md).

## Web console & auth

| Variable | Purpose |
|----------|---------|
| `VENOM_WEB_SECRET` | HMAC key for session cookies (falls back to `VENOM_AUDIT_KEY`; **set it in prod** so sessions survive a restart) |
| `VENOM_WEB_USER`, `VENOM_WEB_PASSWORD` | the initial operator created on first run (default `admin` / `venom`) |
| `VENOM_WEB_NAME` | display name for the seeded operator |
| `VENOM_WEB_RANDOM_SEED` | `1` to seed a random initial password instead of `VENOM_WEB_PASSWORD` |

## Governance & storage

| Variable | Purpose |
|----------|---------|
| `VENOM_KILL_SWITCH` | `1` halts ALL outbound requests instantly |
| `VENOM_AUDIT_KEY` | HMAC key for the tamper-evident audit trail |
| `VENOM_COST_PER_1K_IN` / `_OUT` | per-1k-token prices for the cost estimate (default 0) |
| `DEFAULT_RATE_LIMIT_RPS`, `DEFAULT_ALLOW_DESTRUCTIVE` | scope defaults |
| `VENOM_DATA_DIR` | where engagements, web data, users.json, RAG corpus live (default `venom_data`) |
| `BURP_MCP_ENABLED`, `BURP_MCP_URL` | Burp Suite MCP integration |
| `LOG_LEVEL` | logging verbosity (secret redaction is always on) |

## The scope object

Saved as `venom_data/engagements/<id>/scope.json` (see `examples/scope.json`):

```json
{
  "engagement_id": "ENG-2026-001",
  "target_name": "AcmePay",
  "authorized_base_urls": ["https://api-staging.acmepay.example.com"],
  "out_of_scope": ["stripe.com", "auth0.com"],
  "rate_limit_per_second": 5,
  "allow_destructive": false,
  "max_destructive_actions": 0,
  "authorized_by": "Jane Smith, CISO",
  "authorization_date": "2026-06-01T00:00:00Z",
  "expiry_date": "2026-06-30T23:59:59Z",
  "identities": [
    {"name": "attacker", "role": "free_user", "auth": {
       "type": "login", "method": "POST", "path": "/api/v1/login",
       "body": {"username": "a@x.com", "password": "..."},
       "token_path": "$.access_token", "place": "header",
       "header": "Authorization", "scheme": "Bearer"}}
  ],
  "objective": {"description": "delete another user's account",
                "win_action": {"method": "POST", "path": "/api/users/delete",
                               "data": {"id": "victim"}}}
}
```

- `authorized_base_urls` gate by **scheme + host + port + path-prefix**.
- Requests outside the set, to anything in `out_of_scope`, after `expiry_date`, or
  destructive methods without `allow_destructive`, are blocked at the HTTP layer.
- **Identities** make authenticated, multi-actor testing possible (business-logic flaws
  live in authenticated, stateful flows). Auth types: `login` (recommended), `bearer`,
  `cookie`, `basic`, `form_login`.
- The **objective** drives the success oracle. Prefer a differential `win_action`; a
  `success_text`/`win_signals` marker is the operator-defined fallback. See
  [success-oracle.md](success-oracle.md).
