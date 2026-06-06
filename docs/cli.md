# CLI reference

The entry point is `venom` (== `python -m venom` == `venom.cli:main`).

```
venom <command> [options]

Commands:
  scope      Validate / summarize an engagement scope
  ingest     Ingest artifacts and inspect the risk-ranked endpoint registry
  providers  Ping the configured LLM providers
  agents     Show the role -> model mapping (--ping to live-test)
  burp       Check the local Burp Suite MCP endpoint (--status)
  run        Full engagement (dry-run by default; --live to send traffic)
  hunt       Iterative autonomous agent loop against a URL
  oneshot    LLM-frugal hunt (<=3 model calls) against a URL
  web        Launch the browser console
```

## scope

```bash
venom scope --scope examples/scope.json
```
Loads and validates the authorization scope and prints a summary (hosts, out-of-scope,
window, rate limit, destructive policy). See [configuration.md](configuration.md) for the
scope object shape.

## ingest

```bash
venom ingest --in examples/
```
Parses OpenAPI/GraphQL/HAR/Burp/JS artifacts in a directory into the unified
`EndpointRegistry` and prints it risk-ranked.

## providers / agents

```bash
venom providers          # ping each configured provider (reports the one that answered)
venom agents             # role -> model mapping
venom agents --ping      # live-test each model
```

## run (full engagement)

```bash
# DRY-RUN by default - sends nothing:
venom run --scope examples/scope.json --in examples/ --out venom_data/reports/eng-001

# Execute for real (only inside the authorized window; the guard still applies):
venom run --scope examples/scope.json --in examples/ --live

# Point-and-shoot against a live web app (crawl to discover, no artifacts):
venom run --scope scope.json --crawl --live
```
Outputs land in `--out`: `report.md`, `findings.json`, `findings.sarif`,
`business_model.json`, `audit.jsonl`.

## hunt / oneshot (autonomous engine)

```bash
# Frugal (<=3 model calls) - preferred for rate-limited / slow models:
venom oneshot https://app.example.com --objective "delete another user's account"

# Iterative agent loop:
venom hunt https://app.example.com --login wiener:peter
```
The URL is positional. Both require an LLM provider. See
[architecture.md](architecture.md) for how the loop works and
[success-oracle.md](success-oracle.md) for how a win is confirmed.

## web

```bash
venom web --open
venom web --host 0.0.0.0 --port 8080
```
See [web-console.md](web-console.md).

## Docker

A multi-stage, non-root image is provided.

```bash
docker build -t venom-agent:0.1.0 .
docker compose up --build              # web console on http://localhost:8080
docker compose run --rm venom scope --scope examples/scope.json   # the CLI
```
