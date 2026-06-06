# Web console

A local browser UI over the **real** engine - the same scope guard, engine, oracle and
findings, in a browser. It is a std-lib `http.server` (no runtime web dependency) serving
a React UI (loaded from a CDN) and a JSON API, with a Server-Sent-Events stream of a live
run's trace.

```bash
python -m venom web --open                  # http://127.0.0.1:8080, opens a browser
python -m venom web --host 0.0.0.0 --port 8080
```

## Login (multi-user)

The console **requires login**. On first start it seeds an operator and prints the
credentials once:

```
Login created -> user: admin   password: venom
```

Override with `VENOM_WEB_USER` / `VENOM_WEB_PASSWORD`, or set
`VENOM_WEB_RANDOM_SEED=1` for a random initial password. Add more operators via the API
(`auth.add_user`). Each operator sees **only their own engagements**; runs are
owner-stamped and per-run endpoints are owner-gated. See [security.md](security.md) for
the auth design. Sign out from the user chip at the bottom of the sidebar.

## What "launch engagement" does

Launching runs a **real**, scope-guarded `run_engagement` against the target URL you
enter (an authorized external host, hunted over live HTTP). Every request still passes
the scope guard.

> An **LLM provider is required**. The live hunt reasons about the target with a model
> (recon -> infer -> hypothesize -> exploit -> verify) and **fails closed** with a clear
> error if none is configured - it will not fabricate a hunt or silently degrade to a
> status-code scanner.

## Screens

| Screen | What it shows |
|--------|---------------|
| **Dashboard** | Your engagements + aggregate stats (confirmed findings by severity) |
| **New engagement** | A 3-step wizard: authorize target (base URL, in-scope path prefixes, out-of-scope hosts, inbox URL), identities & limits, describe the attack |
| **Live run** | The 7-stage pipeline + the real agent-trace console, streamed over SSE |
| **Findings** | Risk-ranked list (severity/CWE/oracle/confirmation filters, SARIF + JSON export) and a detail panel: full description, scope-guarded request log with `X-Pentest-ID`, CWE/OWASP, identities, oracle rows, state delta, sandboxed exploit (when authored), remediation, audit status |
| **Report** | Executive summary + scope/authorization table; Print/PDF, Markdown, JSON, SARIF export |
| **Knowledge base** | The 20 business-logic priors (with PROBE / EXPLOIT IDEA / references); add custom entries |
| **Settings** | LLM providers, safety/governance status, the multi-agent fleet, and **Appearance** (Theme: Auto/Light/Dark, Density, Accent) |

## Theming & responsiveness

- **Theme** is in **Settings -> Appearance**: *Auto* (follows the OS via
  `prefers-color-scheme`), *Light*, or *Dark*. The choice persists in the browser. Dark
  mode re-themes the whole UI via CSS variables; contrast was tuned so filter chips,
  pills, and muted text stay legible in both themes.
- **Responsive:** below 760px the sidebar becomes a horizontal, scrollable nav strip so
  the console is usable on a narrow viewport. Desktop is unchanged.

## Honesty in the UI

The finding detail is deliberately honest. It shows the **real** confirmation method
("differential oracle", "state-delta", "response-content match", "status response"),
states when a signal is status-level only ("corroborate before treating as proven"), and
shows a **synthesized exploit script only when the agent actually wrote one** - for a
deterministic flow finding it says so and points at the request log as the evidence. No
state delta is shown unless a value actually moved.

## API (for scripting)

All endpoints are under `/api`. Auth: `POST /api/login` `{username,password}` (sets the
session cookie), `POST /api/logout`, `GET /api/me`. Data: `GET /api/engagements`
(owner-filtered), `POST /api/runs`, `GET /api/runs/<id>` / `/findings` / `/report.md` /
`/findings.sarif` (owner-gated), `GET /api/runs/<id>/stream` (SSE). Config (public):
`GET /api/status` / `/vuln-classes` / `/agents` / `/providers`, `POST /api/scope/validate`.
