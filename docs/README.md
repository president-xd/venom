# VENOM documentation

VENOM is a **context-aware business-logic penetration-testing agent**. Given an
**authorized** target it reconstructs how the application is supposed to work, forms
hypotheses about where that logic can be abused, **writes and runs real exploit code
in a sandbox**, and **proves** success with evidence - focused on business-logic
flaws (BOLA/IDOR, mass-assignment, workflow/sequence skips, price/parameter
tampering, trusted-identity abuse, economic/arbitrage flaws, token forgery, ...).

> **Authorized engagements only.** Every outbound request passes a scope guard.
> There is no bypass flag. Testing a target without written authorization is illegal
> and unsupported.

This directory is the structured reference. The top-level [`README.md`](../README.md)
is the quick-start entry point; [`CLAUDE.md`](../CLAUDE.md) is the engineering guide.

## Contents

| Doc | What it covers |
|-----|----------------|
| [getting-started.md](getting-started.md) | Install, run the tests, launch the web console, run your first hunt |
| [architecture.md](architecture.md) | The two execution paths, the pipeline, and what every package does |
| [success-oracle.md](success-oracle.md) | How "success" is decided - the differential oracle and realistic markers (no banners) |
| [capabilities-and-limits.md](capabilities-and-limits.md) | **Honest** capability assessment: what is proven, what is model-limited, real eval numbers |
| [security.md](security.md) | Safety model: scope guard, exploit sandbox, audit trail, secret redaction, console auth |
| [web-console.md](web-console.md) | The browser console: login/multi-user, screens, theming, SSE |
| [cli.md](cli.md) | Command-line reference |
| [configuration.md](configuration.md) | Environment variables, LLM providers, `.env` |
| [development.md](development.md) | Testing, conventions, how to extend |

## The one thing to understand first

VENOM decides a win with a **differential oracle**, not a success banner: an action
that is **denied** to the un-escalated user and **succeeds** after the exploit, proven
by a realistic state marker the app genuinely returns. It does **not** rely on any
baked-in "is-solved"/"congratulations" string, so results carry over to real apps
that have no such banner. See [success-oracle.md](success-oracle.md).

## Honesty policy

These docs distinguish **proven** (a passing test exercises it), **partial**, and
**model-limited** (depends on the reasoning model, not the harness). Numbers come
from real runs, including failures. If something is a guardrail rather than a hard
guarantee, the docs say so. See [capabilities-and-limits.md](capabilities-and-limits.md).
