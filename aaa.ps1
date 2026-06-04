# Per-file commits for the autonomous business-logic exploitation work.
# Review before running. Each file is staged and committed separately.

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------- new core modules

git add venom/_env.py
git commit -m "feat(config): add dependency-free .env auto-loader"

git add venom/audit.py
git commit -m "feat(audit): HMAC-signed tamper-evident audit trail + RunMetrics observability"

git add venom/cognition/oneshot.py
git commit -m "feat(agent): LLM-frugal one-shot hunt (recon -> single synthesis -> sandboxed exploit -> verify)"

git add venom/cognition/evaluate.py
git commit -m "feat(agent): success_rate reliability harness (X% over N runs)"

git add venom/ingest/recon.py
git commit -m "feat(recon): surface enrichment with accessible/denied forbidden-action map"

git add venom/flows/email_parser.py
git commit -m "feat(flows): email parser-discrepancy exploit (UTF-7 atom split)"

git add venom/flows/encryption_oracle.py
git commit -m "feat(flows): encryption-oracle stay-logged-in cookie forge"

# ---------------------------------------------------------------- modified modules

git add venom/cognition/objective.py
git commit -m "feat(oracle): general differential win-oracle (forbidden->allowed), no is-solved reliance"

git add venom/cognition/agent.py
git commit -m "feat(agent): wire grounding, recon-depth and differential oracle into the iterative loop"

git add venom/cognition/agent_brain.py
git commit -m "feat(agent): surface-ranked KB priors, strict-args prompt, brain retries"

git add venom/cognition/__init__.py
git commit -m "refactor(cognition): drop dead reasoner/llm_brain exports; export oneshot/evaluate"

git add venom/core/scope.py
git commit -m "feat(scope): destructive-action budget + kill-switch governance"

git add venom/utils.py
git commit -m "feat(security): always-on provider-secret redaction + logging filter"

git add venom/config.py
git commit -m "feat(logging): install secret-redaction filter on the root logger"

git add venom/llm/providers.py
git commit -m "feat(llm): robust JSON parsing, reasoning-model extraction, fallback chain, throttle, air-gap"

git add venom/agents/roles.py
git commit -m "fix(llm): route CODEGEN to deepseek (clean JSON; qwen truncated under load)"

git add venom/knowledge/business_logic.py
git commit -m "feat(kb): new business-logic priors + surface-ranked selection"

git add venom/engagement.py
git commit -m "feat(engagement): register new flows; gate purchase flows on a live win-oracle"

git add venom/flows/__init__.py
git commit -m "feat(flows): register new business-logic exploitation flows"

git add venom/flows/integer_overflow.py
git commit -m "fix(flows): honest verdict — confirm only when the win-oracle fires"

git add venom/testing/web_playbooks.py
git commit -m "fix(playbooks): eliminate 'order placed' false positive; confirm only on genuine win state"

git add venom/cli.py
git commit -m "feat(cli): add 'hunt' and 'oneshot' commands; auto-load .env"

git add docker-compose.yml
git commit -m "chore(docker): pin compose project name to venom; add vulnlab target service"

# ---------------------------------------------------------------- deletions (dead code)

git rm venom/cognition/reasoner.py
git commit -m "refactor: remove dead Reasoner loop (superseded by Agent)"

git rm venom/cognition/llm_brain.py
git commit -m "refactor: remove dead llm_brain (superseded by agent_brain)"

# ---------------------------------------------------------------- vulnerable test app

git add vulnlab/__init__.py
git commit -m "feat(vulnlab): package init for the deliberately-vulnerable test app"

git add vulnlab/app.py
git commit -m "feat(vulnlab): multi-class vulnerable app (price/idor/pin/mass) for agent testing"

# ---------------------------------------------------------------- evaluation harness

git add scripts/eval_vulnlab.py
git commit -m "feat(scripts): end-to-end VulnLab evaluation harness"

# ---------------------------------------------------------------- tests

git add tests/test_oneshot.py
git commit -m "test(oneshot): frugal hunt, bounded feedback loop, call cap"

git add tests/test_recon.py
git commit -m "test(recon): forbidden-action map enrichment"

git add tests/test_enterprise.py
git commit -m "test(enterprise): secret redaction, signed audit, metrics, destructive governance"

git add tests/test_exploit_code.py
git commit -m "test(tools): self-authored exploit code (error->revise->solve), sandbox"

git add tests/test_toolbox_dispatch.py
git commit -m "test(tools): robust tool dispatch (aliases, body normalization, kwargs)"

git add tests/test_autonomy_features.py
git commit -m "test(agent): skill replay, backtracking, cost/time caps, reliability, JSON salvage"

git add tests/test_autonomy_live.py
git commit -m "test(agent): opt-in live-LLM autonomy (mass-assignment, IDOR) gated by VENOM_LIVE_LLM"

git add tests/test_hunt_cli.py
git commit -m "test(cli): hunt scope synthesis"

git add tests/test_email_parser.py
git commit -m "test(flows): email parser-discrepancy end-to-end"

git add tests/test_encryption_oracle.py
git commit -m "test(flows): encryption-oracle end-to-end"

git add tests/test_agents.py
git commit -m "test(agents): update CODEGEN model assignment to deepseek"

git add tests/test_cognition.py
git commit -m "test(cognition): trim to budgeting + KB tests (incl surface ranking) after reasoner removal"

Write-Host ""
Write-Host "All per-file commits created. Review with:"
Write-Host "git log --oneline"