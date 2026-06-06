"""
Engagement orchestrator - the end-to-end VENOM pipeline:

    load scope -> ingest artifacts -> infer business model -> generate tests
    -> execute (scope-guarded) -> report

Designed to run safely offline (dry_run / no LLM) and to fail closed: nothing
reaches the network without an authorized, unexpired scope.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from .core.scope import Scope
from .core.registry import EndpointRegistry
from .core.graph import BusinessModelGraph
from .ingest import ingest
from .inference import infer_business_model
from .llm import LLMRouter
from .testing import TestCase, generate_test_cases
from .engine.runner import TestRunner
from .report import write_report
from .config import SETTINGS

logger = logging.getLogger("venom.engagement")


def _dedup_confirmed(cases: list) -> list:
    """Collapse duplicate CONFIRMED findings (same vuln class + endpoint) proven by
    more than one engine into a single case, keeping the first (richest evidence).
    Non-confirmed cases are preserved as-is (leads/negatives stay in the appendix)."""
    from .testing.schema import Verdict
    seen: set[tuple] = set()
    out = []
    for c in cases:
        if c.verdict == Verdict.CONFIRMED_EXPLOIT:
            key = (c.vulnerability_class, (c.affected_endpoint or "").rstrip("/"))
            if key in seen:
                continue
            seen.add(key)
        out.append(c)
    return out


@dataclass
class EngagementResult:
    scope: Scope
    registry: EndpointRegistry
    graph: BusinessModelGraph
    cases: list[TestCase]
    artifacts: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


async def run_engagement(
    scope_path: str | Path,
    artifact_paths: list[str | Path],
    out_dir: str | Path,
    *,
    dry_run: bool = True,
    use_llm: bool = True,
    domain_docs: str = "",
    discover: bool = False,             # force live discovery crawl on
    crawl_seeds: list[str] | None = None,
    think: bool = False,                # run the adaptive LLM reasoning loop
    objective_text: str = "",           # the agent's goal (e.g. "buy the jacket")
    transport=None,  # httpx transport override (tests / in-memory targets)
) -> EngagementResult:
    # 1. Authorization - first, always.
    scope = Scope.from_file(scope_path)
    scope.validate_window()
    logger.info("Loaded scope:\n%s", scope.summary())

    # 2. LLM router (optional; air-gap honored from scope).
    router: LLMRouter | None = None
    if use_llm:
        router = LLMRouter.from_env(air_gap=scope.air_gap_mode, mode=scope.llm_mode)
        if not router.any_enabled():
            logger.warning("No LLM provider configured - running in OFFLINE mode.")
            router = None

    # 3. Ingest artifacts -> registry.
    ing = ingest(artifact_paths)
    if ing.secrets:
        logger.warning("Possible secrets observed in artifacts (redacted): %s", ing.secrets)

    # 3b. Live discovery (web-app mode): crawl the target to find forms/links,
    # authenticated as the first identity. Only when enabled and not a dry run.
    disc = dict(scope.discovery or {})
    if discover:
        disc["enabled"] = True
    if disc.get("enabled") and not dry_run:
        from .ingest.crawler import crawl
        from .engine.auth import AuthManager

        auth_state = None
        if scope.identities:
            try:
                am = AuthManager(scope, dry_run=False, transport=transport)
                auth_state = await am.ensure(scope.identities[0]["name"])
            except Exception as exc:  # noqa: BLE001
                logger.warning("Discovery auth failed (%s) - crawling unauthenticated.", exc)
        info = await crawl(scope, ing.registry,
                           seeds=crawl_seeds or disc.get("seeds"),
                           auth_state=auth_state, transport=transport,
                           max_pages=disc.get("max_pages", 40),
                           forced_browse=disc.get("forced_browse", True))
        ing.notes.append(f"Discovery crawl: {info['pages']} pages, {info['forms']} forms")

    # 4-5. Reconstruct the business model and generate test cases. When the
    # NVIDIA NIM multi-agent fleet is available, the orchestrator (DeepSeek)
    # drives research + synthesis and the hypothesis subagent (Kimi) augments
    # the deterministic playbooks. Otherwise we use the offline pipeline.
    from .agents import build_orchestrator, AgentRole

    identity_names = [i.get("name") for i in scope.identities if i.get("name")]

    orch = build_orchestrator(router)
    if orch is not None and orch.enabled:
        logger.info("Multi-agent fleet active (base: %s).",
                    orch.agent(AgentRole.ORCHESTRATOR).model)
        graph = await orch.reconstruct_model(ing.registry, domain_docs=domain_docs)
        cases = await generate_test_cases(
            ing.registry, graph, hypothesis_agent=orch.agent(AgentRole.HYPOTHESIS),
            identities=identity_names,
        )
        cases = await orch.concretize(cases)   # CODEGEN fills runnable conditions
    else:
        graph = await infer_business_model(ing.registry, router, domain_docs=domain_docs)
        cases = await generate_test_cases(ing.registry, graph, router, identities=identity_names)
    logger.info("Generated %d test cases", len(cases))

    # 6. Execute under the scope guard (optionally routing OOB checks through Burp).
    burp = None
    if SETTINGS.burp_mcp_enabled:
        from .integrations.burp_exec import BurpExecutor
        burp = BurpExecutor(SETTINGS.burp_mcp_url)
    runner = TestRunner(scope, dry_run=dry_run, transport=transport, burp=burp)
    await runner.run_all(cases)

    # 6b. Autonomous agent loop ("think before exploit"): a tool-using planner
    # with working memory + skill learning. Lets VENOM attempt flaws no playbook
    # covers by composing tools toward an objective, not running a fixed script.
    agent_trace = None
    if think and not dry_run and orch is not None and orch.enabled:
        from .cognition import Agent, make_agent_brain, Objective
        from .memory import SkillLibrary
        from .llm.telemetry import ResponseCache, Budget, Tracer

        # Cache + token budget + tracing on the router.
        agent_trace = Tracer()
        router.with_telemetry(cache=ResponseCache(),
                              budget=Budget(max_tokens=SETTINGS.agent_token_budget),
                              tracer=agent_trace)
        # Model tiering: per-step decisions go to the FAST model (CODEGEN/Qwen),
        # not the slow base model - cheaper and faster for many short reasoning steps.
        objective = Objective.from_scope(scope, fallback=objective_text or scope.target_name)
        brain = make_agent_brain(orch.agent(AgentRole.CODEGEN))
        agent = Agent(scope, brain, transport=transport, skills=SkillLibrary())
        try:
            reasoned = await agent.run(ing.registry, objective)
            if reasoned:
                cases += reasoned
                logger.info("Agent confirmed %d finding(s) toward objective", len(reasoned))
        except Exception as exc:  # noqa: BLE001 - reasoning is best-effort
            logger.warning("Agent error: %s", exc)

        # COVERAGE CAMPAIGN - do NOT stop at one. Decompose the surface into many
        # scoped differential targets (every action the tester is currently FORBIDDEN
        # to perform) and hunt EACH one, collecting every flaw that can be PROVEN.
        # This is what turns "found 1 of N" into systematic coverage; each win is
        # still verified by the differential oracle, so more findings ≠ false positives.
        try:
            from .cognition import run_campaign, derive_objectives, make_oneshot_synthesizer
            from .ingest.recon import enrich_recon
            # Probe WIDE for the campaign - the more of the surface we map, the more
            # forbidden actions we surface to decompose into targets (default 24 is
            # tuned for a single brief; coverage wants the whole reachable surface).
            enrichment = await enrich_recon(scope, ing.registry, transport=transport,
                                            max_probes=max(80, SETTINGS.campaign_max_targets * 6))
            targets = derive_objectives(ing.registry, enrichment,
                                        base_objective=getattr(objective, "description", ""),
                                        max_targets=SETTINGS.campaign_max_targets)
            if targets:
                logger.info("Coverage campaign: hunting %d forbidden-action target(s) across the surface",
                            len(targets))
                camp = await run_campaign(
                    scope, ing.registry,
                    lambda: make_oneshot_synthesizer(orch.agent(AgentRole.CODEGEN)),
                    objectives=targets, transport=transport, enrichment=enrichment,
                    per_target_calls=SETTINGS.campaign_per_target_calls,
                    max_targets=SETTINGS.campaign_max_targets)
                cases += camp.findings
                ing.notes.append(camp.summary())
                logger.info("Coverage campaign confirmed %d finding(s) across %d target(s)",
                            camp.confirmed, camp.attempted)
        except Exception as exc:  # noqa: BLE001 - coverage is best-effort, never aborts the run
            logger.warning("Coverage campaign error: %s", exc)

        if router.budget is not None:
            ing.notes.append(f"Agent LLM usage: {router.tracer.summary()} | {router.budget.summary()}")

    # Actionable guidance: a registration endpoint exists but the operator gave no
    # email client URL - every email-confirmation exploit (account-takeover,
    # email-parser discrepancy, truncation) NEEDS to read the confirmation link, so
    # they cannot complete. Say so loudly instead of silently skipping them.
    _has_register = any(e.path.rstrip("/").endswith("/register") for e in ing.registry)
    if not dry_run and _has_register and not scope.email_client_url:
        logger.warning(
            "Registration endpoint found, but NO email client URL is configured. "
            "Email-confirmation exploits (account-takeover, email-parser discrepancy, "
            "email truncation) require reading the registration confirmation link, so they "
            "CANNOT complete the register -> confirm -> login -> admin chain. Provide the "
            "inbox / exploit-server email URL in the engagement to hunt these registration labs.")

    # 6c. Account-lifecycle flow (registration + email verification + privilege
    # via email domain). Runs when an inbox URL is configured and a register
    # endpoint was discovered. Cross-host and stateful, so it's a flow, not a step.
    if not dry_run and scope.email_client_url:
        from .flows import account_takeover
        try:
            ato = await account_takeover(scope, ing.registry, transport=transport)
            if ato:
                cases += ato
                logger.info("Account-lifecycle flow confirmed %d finding(s)", len(ato))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Account-lifecycle flow error: %s", exc)

    # 6c-sext. Email parser-discrepancy flow (Splitting the email atom): register a
    # privileged-domain account that actually delivers to an attacker inbox.
    if not dry_run and scope.email_client_url:
        from .flows import email_parser
        try:
            emp = await email_parser(scope, ing.registry, transport=transport)
            if emp:
                cases += emp
                logger.info("Email-parser flow confirmed %d finding(s)", len(emp))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Email-parser flow error: %s", exc)

    # 6c-bis. Exceptional-input registration flow (email length-truncation ->
    # privileged domain). Same preconditions as account-lifecycle (inbox + a
    # register endpoint); a distinct vulnerability class so it runs independently.
    if not dry_run and scope.email_client_url:
        from .flows import exceptional_input
        try:
            xin = await exceptional_input(scope, ing.registry, transport=transport)
            if xin:
                cases += xin
                logger.info("Exceptional-input flow confirmed %d finding(s)", len(xin))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Exceptional-input flow error: %s", exc)

    # 6c-ter. Trusted-identity account-management flow (change-password/email/delete
    # that trusts a client-supplied username/id). Needs a low-priv identity + a
    # change-password endpoint; targets the privileged account.
    if not dry_run and scope.identities:
        from .flows import account_privilege
        try:
            acp = await account_privilege(scope, ing.registry, transport=transport)
            if acp:
                cases += acp
                logger.info("Account-privilege flow confirmed %d finding(s)", len(acp))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Account-privilege flow error: %s", exc)

    # 6c-quater. Flawed-login-state-machine flow (skip a post-login step -> admin).
    if not dry_run and scope.identities:
        from .flows import login_statemachine
        try:
            lsm = await login_statemachine(scope, ing.registry, transport=transport)
            if lsm:
                cases += lsm
                logger.info("Login-state-machine flow confirmed %d finding(s)", len(lsm))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Login-state-machine flow error: %s", exc)

    # 6c-quinque. Encryption-oracle flow (forge stay-logged-in via comment oracle).
    if not dry_run and scope.identities:
        from .flows import encryption_oracle
        try:
            enc = await encryption_oracle(scope, ing.registry, transport=transport)
            if enc:
                cases += enc
                logger.info("Encryption-oracle flow confirmed %d finding(s)", len(enc))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Encryption-oracle flow error: %s", exc)

    # 6d. Coupon/discount-abuse flow (stacking via alternating codes).
    if not dry_run:
        from .flows import coupon_stacking
        try:
            cpn = await coupon_stacking(scope, ing.registry, transport=transport)
            if cpn:
                cases += cpn
                logger.info("Coupon-stacking flow confirmed %d finding(s)", len(cpn))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Coupon-stacking flow error: %s", exc)

    # The three purchasing flows below all target the SAME economic goal ("acquire
    # the item without paying full price"). They are ordered cheapest-first, and once
    # one CONFIRMS the win we skip the rest - especially the request-heavy
    # integer-overflow flow. This gate is a local boolean (app-agnostic), NOT a
    # PortSwigger 'is-solved' banner, so the general pipeline behaves identically on
    # a real enterprise target.
    purchased = False

    # 6d-bis. Workflow-sequence-skip purchasing flow (cheap: add item + jump to
    # order-confirmation).
    if not dry_run:
        from .flows import workflow_skip
        try:
            wfs = await workflow_skip(scope, ing.registry, transport=transport)
            if wfs:
                cases += wfs
                purchased = True
                logger.info("Workflow-skip flow confirmed %d finding(s)", len(wfs))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Workflow-skip flow error: %s", exc)

    # 6d-ter. Infinite-money flow (gift-card arbitrage; request-heavy). Try before
    # the overflow if nothing cheaper solved the purchase yet.
    if not dry_run and not purchased:
        from .flows import infinite_money
        try:
            mny = await infinite_money(scope, ing.registry, transport=transport)
            if mny:
                cases += mny
                purchased = True
                logger.info("Infinite-money flow confirmed %d finding(s)", len(mny))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Infinite-money flow error: %s", exc)

    # 6e. Integer-overflow purchasing flow (expensive ~hundreds of requests) -
    # only as a last resort when nothing cheaper already solved the purchase.
    if not dry_run and not purchased:
        from .flows import integer_overflow
        try:
            ovf = await integer_overflow(scope, ing.registry, transport=transport)
            if ovf:
                cases += ovf
                logger.info("Integer-overflow flow confirmed %d finding(s)", len(ovf))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Integer-overflow flow error: %s", exc)

    # Dedup CONFIRMED findings - the agent, the coverage campaign, the playbooks and
    # the flows can each prove the same flaw; report it once. Keyed by the actual
    # win (class + endpoint); the first confirmation (richest evidence) is kept.
    cases = _dedup_confirmed(cases)

    # SUMMARIZER subagent: terse coverage/results summary for the operator.
    if orch is not None and orch.enabled:
        brief = [{"class": c.vulnerability_class.value, "verdict": c.verdict.value}
                 for c in cases]
        summary = await orch.summarize_results(brief)
        if summary:
            ing.notes.append("Summary: " + summary)

    # 7. Report (reporter agent writes the executive summary when available) +
    #    audit trail of every outbound request.
    reporter = orch.agent(AgentRole.REPORTER) if (orch and orch.enabled) else None
    artifacts = await write_report(out_dir, scope, ing.registry, graph, cases,
                                   reporter=reporter, audit=runner.audit_records())
    if agent_trace is not None and agent_trace.calls:
        trace_path = Path(out_dir) / "agent_trace.jsonl"
        agent_trace.dump(trace_path)
        artifacts["agent_trace"] = trace_path
    logger.info("Report written to %s", artifacts["report"])

    return EngagementResult(
        scope=scope, registry=ing.registry, graph=graph, cases=cases,
        artifacts=artifacts, notes=ing.notes,
    )
