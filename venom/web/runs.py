"""
RunManager - launch a REAL ``run_engagement`` and surface its live trace + findings.

The bundled-VulnLab engagement runs in-process against ``httpx.MockTransport`` (no
network and no separate target required). An LLM provider IS required, however:
``_execute`` fails closed with a clear error if none is configured, because the
live hunt reasons about the target with a model (recon -> infer -> hypothesize ->
exploit -> verify). We do NOT silently degrade to a status-code scanner and present
it as a real hunt. (Set ``DEEPSEEK_API_KEY`` or another provider in ``.env``.)

Each run executes in its own thread; a logging handler scoped to that thread
captures ``venom.*`` log records and turns them into console + pipeline events,
drained by the SSE endpoint.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .mappers import classify_log, findings_payload, stage_order
from ..config import SETTINGS

logger = logging.getLogger("venom.web")

_SEV_KEYS = ("crit", "high", "med", "low")


def _data_dir() -> Path:
    base = Path(os.getenv("VENOM_DATA_DIR", "venom_data")) / "web"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _merge_cases(base_cases: list, extra_cases: list) -> list:
    """Append coverage cases, dropping any CONFIRMED finding that duplicates one
    already proven (same vuln class + endpoint), so a flaw is reported once."""
    from venom.testing.schema import Verdict
    seen = set()
    for c in base_cases:
        if c.verdict == Verdict.CONFIRMED_EXPLOIT:
            seen.add((c.vulnerability_class, (c.affected_endpoint or "").rstrip("/")))
    out = list(base_cases)
    for c in extra_cases:
        if c.verdict == Verdict.CONFIRMED_EXPLOIT:
            key = (c.vulnerability_class, (c.affected_endpoint or "").rstrip("/"))
            if key in seen:
                continue
            seen.add(key)
        out.append(c)
    return out


class Run:
    """In-memory state for one engagement run, safe for concurrent reads."""

    def __init__(self, run_id: str, opts: dict):
        self.id = run_id
        self.opts = opts
        self.target_name = opts.get("target_name") or "VulnLab"
        self.owner = opts.get("owner") or "operator"
        self.target_url = opts.get("target_url") or "localhost:8000"
        self.status = "running"          # running | done | error
        self.out_dir = _data_dir() / run_id
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[dict] = []
        self.findings: list[dict] = []
        self.counts = {k: 0 for k in _SEV_KEYS}
        self.error: str | None = None
        self.stage = 0
        self.thread_ident: int | None = None
        self.finished = False
        self.started = datetime.now(timezone.utc)
        self.meta: dict = {}             # real engagement metadata for the report
        self.total_tests = 0             # how many test cases were executed
        self.provider: str = ""          # the LLM provider that drove the hunt
        self._cond = threading.Condition()

    # -- event plumbing -------------------------------------------------------
    def push(self, event: dict) -> None:
        # Real wall-clock offset (seconds since the run started) so the UI shows
        # genuine timing, not a synthesized clock.
        event.setdefault("ts", round((datetime.now(timezone.utc) - self.started).total_seconds(), 1))
        with self._cond:
            self.events.append(event)
            self._cond.notify_all()

    def push_log(self, msg: str) -> None:
        self.stage = stage_order(msg, self.stage)
        self.push({"t": classify_log(msg), "x": msg, "order": self.stage})

    def finish(self) -> None:
        with self._cond:
            self.finished = True
            self._cond.notify_all()

    def snapshot(self) -> dict:
        with self._cond:
            return {
                "id": self.id, "status": self.status, "stage": self.stage,
                "events": list(self.events), "findings_count": len(self.findings),
                "counts": dict(self.counts), "error": self.error,
                "target_name": self.target_name, "target_url": self.target_url,
                "authorized_by": self.opts.get("authorized_by") or "",
            }

    def iter_events(self):
        """Yield events as they arrive; ends when the run finishes and the buffer
        is drained. Used by the SSE endpoint."""
        idx = 0
        while True:
            with self._cond:
                while idx >= len(self.events) and not self.finished:
                    self._cond.wait(timeout=25)
                batch = self.events[idx:]
                idx = len(self.events)
                finished = self.finished
            for e in batch:
                yield e
            if finished and idx >= len(self.events):
                return


class _LogCapture(logging.Handler):
    """Forward only this run's thread's ``venom.*`` records into its event buffer."""

    def __init__(self, run: Run):
        super().__init__(level=logging.INFO)
        self.run = run

    def emit(self, record: logging.LogRecord) -> None:
        if self.run.thread_ident is not None and record.thread != self.run.thread_ident:
            return
        try:
            for line in record.getMessage().splitlines():
                line = line.strip()
                if line:
                    self.run.push_log(line)
        except Exception:  # noqa: BLE001 - logging must never raise
            pass


class RunManager:
    def __init__(self):
        self.runs: dict[str, Run] = {}
        self._lock = threading.Lock()

    # -- lifecycle ------------------------------------------------------------
    def start(self, opts: dict) -> str:
        run_id = "ENG-WEB-" + uuid.uuid4().hex[:8]
        run = Run(run_id, opts)
        with self._lock:
            self.runs[run_id] = run
        t = threading.Thread(target=self._execute, args=(run,), daemon=True, name=f"venom-run-{run_id}")
        t.start()
        return run_id

    def owner_of(self, run_id: str) -> str | None:
        """The username that launched a run (None if unknown). Checked for per-run
        authorization. Resolves from the live run, then the persisted engagements
        index, then the saved trace."""
        run = self.runs.get(run_id)
        if run:
            return run.owner
        path = _data_dir() / "engagements.json"
        if path.exists():
            try:
                for r in json.loads(path.read_text(encoding="utf-8")):
                    if r.get("id") == run_id:
                        return r.get("owner") or ""
            except Exception:  # noqa: BLE001
                pass
        tj = _data_dir() / run_id / "trace.json"
        if tj.exists():
            try:
                return (json.loads(tj.read_text(encoding="utf-8")).get("owner")) or ""
            except Exception:  # noqa: BLE001
                pass
        return None

    def get(self, run_id: str) -> Run | None:
        return self.runs.get(run_id)

    # -- worker ---------------------------------------------------------------
    @staticmethod
    def _identities() -> list[dict]:
        """The bundled VulnLab's real low-privileged test identities, used so the
        live hunt runs AUTHENTICATED (a senior tester escalates FROM a normal user;
        an anonymous crawl just collects 401s). These are genuine working creds for
        the in-process demo target - not placeholder data."""
        def form_login(user: str, pw: str) -> dict:
            return {"type": "form_login", "login_url": "/login", "method": "POST",
                    "username": user, "password": pw,
                    "username_field": "username", "password_field": "password"}
        return [
            {"name": "attacker", "role": "user", "auth": form_login("wiener", "peter")},
            {"name": "victim", "role": "user", "auth": form_login("carlos", "montoya")},
        ]

    @staticmethod
    def _normalize_target(url: str) -> str:
        """The operator's target, normalized to ``scheme://host[:port]`` (no path)."""
        from urllib.parse import urlparse
        url = (url or "").strip() or "http://localhost:8000"
        if "://" not in url:
            url = "http://" + url
        u = urlparse(url)
        return f"{u.scheme}://{u.netloc}".rstrip("/")

    @staticmethod
    def is_bundled_target(url: str) -> bool:
        """True only for the in-process bundled VulnLab demo (localhost:8000)."""
        from urllib.parse import urlparse
        u = urlparse(url if "://" in (url or "") else "http://" + (url or ""))
        host = (u.hostname or "").lower()
        try:
            port = u.port or (443 if u.scheme == "https" else 80)
        except ValueError:
            port = 0
        return host in ("localhost", "127.0.0.1") and port == 8000

    def _scope_dict(self, run: Run) -> dict:
        now = datetime.now(timezone.utc)
        o = run.opts
        objective = o.get("objective") or ""
        # HONOR THE TARGET THE OPERATOR ENTERED - never hardcode the demo host.
        base = self._normalize_target(o.get("target_url") or run.target_url)
        bundled = self.is_bundled_target(base)
        base_urls = [base]
        for p in (o.get("scope_paths") or []):
            seg = "/" + (p or "").strip().lstrip("/").rstrip("*").strip("/")
            if seg and seg != "/" and base + seg not in base_urls:
                base_urls.append(base + seg)
        # Email-registration labs: authorize the inbox host so the flow's mail client
        # is in scope, and extract the "delete <user>" objective the lab asks for.
        email_url = (o.get("email_client_url") or "").strip()
        if email_url:
            from urllib.parse import urlparse as _u
            eu = _u(email_url if "://" in email_url else "http://" + email_url)
            email_host = f"{eu.scheme}://{eu.netloc}"
            if email_host and email_host not in base_urls:
                base_urls.append(email_host)
        delete_user = ""
        m = re.search(r"\bdelete\s+(?:the\s+)?(?:user\s+|account\s+)?([A-Za-z][A-Za-z0-9_.\-]{0,40})",
                      objective, re.I)
        if m:
            # Strip trailing sentence punctuation - "delete carlos." must target
            # 'carlos', not 'carlos.' (which deletes nobody and fails the lab).
            delete_user = m.group(1).rstrip(".,;:!?'\")")
        return {
            "engagement_id": run.id,
            "target_name": run.target_name,
            "authorized_base_urls": base_urls,
            "out_of_scope": [h for h in (o.get("out_of_scope") or []) if h],
            # Operator-supplied credentials WIN (so the agent can log in to a real
            # target). The bundled VulnLab falls back to its known test identities;
            # a real external target with no creds runs unauthenticated.
            "identities": (o.get("identities") or (self._identities() if bundled else [])),
            "rate_limit_per_second": float(o.get("rate", 5) or 5),
            "allow_destructive": bool(o.get("destructive", False)),
            # Registration / email-parser labs: the inbox URL + the user to delete.
            "email_client_url": email_url,
            "objective_delete_user": delete_user,
            "discovery": {"enabled": True, "seeds": ["/"],
                          "max_pages": int(o.get("max_pages", 40) or 40),
                          "forced_browse": True},
            # written authorization supplied by the operator (falls back to defaults)
            "authorization_date": o.get("authorization_date") or now.isoformat(),
            "expiry_date": o.get("expiry_date") or (now + timedelta(days=1)).isoformat(),
            "authorized_by": o.get("authorized_by") or "VENOM web console (authorized operator)",
            "objective": {"description": objective} if objective else {},
        }

    @staticmethod
    def _build_meta(run: Run, provider: str, crawl: bool, think: bool) -> dict:
        """Real engagement metadata for the enterprise report - no hardcoded values."""
        o = run.opts
        sd = {}
        try:
            sd = json.loads((run.out_dir / "scope.json").read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
        idents = [f'{i.get("name")} ({i.get("role") or "user"})' for i in sd.get("identities", [])]
        return {
            "engagement_id": run.id,
            "target_name": run.target_name,
            "base_url": (sd.get("authorized_base_urls") or ["http://localhost:8000"])[0],
            "out_of_scope": sd.get("out_of_scope") or [],
            "authorized_by": o.get("authorized_by") or sd.get("authorized_by") or "",
            "authorization_date": sd.get("authorization_date") or "",
            "expiry_date": sd.get("expiry_date") or "",
            "rate_limit": sd.get("rate_limit_per_second"),
            "destructive": bool(sd.get("allow_destructive")),
            "identities": idents,
            "objective": o.get("objective") or "",
            "provider": provider,
            "engine": f"LLM-driven agent ({provider})",
            "pipeline": "recon/crawl -> business-model inference -> adversarial hypotheses "
                        "-> sandboxed exploit synthesis -> differential verification",
            "started": run.started.isoformat(),
        }

    def _execute(self, run: Run) -> None:
        run.thread_ident = threading.get_ident()
        handler = _LogCapture(run)
        root = logging.getLogger("venom")
        prev_level = root.level
        root.addHandler(handler)
        if prev_level == logging.NOTSET or prev_level > logging.INFO:
            root.setLevel(logging.INFO)

        run.push({"t": "stage", "x": f"[scope] Loading engagement {run.id} · target {run.target_name}", "order": 0})
        try:
            from venom.engagement import run_engagement
            from venom.llm import LLMRouter

            scope_path = run.out_dir / "scope.json"
            scope_path.write_text(json.dumps(self._scope_dict(run), indent=2), encoding="utf-8")

            # The live engagement is an LLM-DRIVEN HUNT, in the senior-tester order:
            #   recon/crawl -> LLM business-model inference -> adversarial hypotheses
            #   -> LLM exploit synthesis (sandboxed) -> DIFFERENTIAL verification.
            # An LLM provider is REQUIRED - we do not silently degrade to a
            # status-code scanner and dress the result up as a real hunt. If none is
            # configured we fail honestly so the operator knows nothing was reasoned.
            try:
                router = LLMRouter.from_env()
                provider = None
                if router.any_enabled():
                    enabled = [p.value for p, c in router.providers.items() if getattr(c, "enabled", False)]
                    # Prefer DeepSeek (the configured primary) when present.
                    provider = next((p for p in enabled if "deepseek" in p), enabled[0] if enabled else None)
            except Exception as exc:  # noqa: BLE001
                provider = None
                logger.warning("provider probe failed: %s", exc)
            if not provider:
                raise RuntimeError(
                    "No LLM provider is configured. The live hunt reasons about the "
                    "target with a model (recon -> infer -> hypothesize -> exploit -> "
                    "verify); set DEEPSEEK_API_KEY (or another provider) in .env and retry. "
                    "VENOM will not fabricate a hunt without a model.")
            crawl = run.opts.get("crawl", True)
            think = run.opts.get("think", True)
            run.provider = provider
            run.meta = self._build_meta(run, provider, crawl, think)
            # Decide the TARGET and how we reach it. The bundled VulnLab demo runs
            # in-process (MockTransport); a REAL external target is hit over the
            # network (transport=None -> real httpx). We never silently swap one for
            # the other - the engagement targets exactly what the operator entered.
            target = self._normalize_target(run.opts.get("target_url") or run.target_url)
            bundled = self.is_bundled_target(target)
            run.push_log(f"[scope] engine: LLM-driven hunt · provider {provider} · target {target} "
                         f"({'bundled VulnLab, in-process' if bundled else 'external target, live HTTP'}) · "
                         f"recon{'+crawl' if crawl else ''} -> infer -> hypothesize -> "
                         f"exploit -> verify{' (--think)' if think else ''}")

            if bundled:
                # The bundled demo target is VulnLab, a dev-only proving ground that is
                # NOT shipped in the repo (see .gitignore). External targets do not need it.
                try:
                    from vulnlab.app import make_transport
                except ModuleNotFoundError:
                    raise RuntimeError(
                        "The bundled VulnLab demo target is not installed (it is dev-only "
                        "and excluded from the repo). Enter a real, authorized target URL "
                        "instead of localhost:8000.")
                transport, _ = make_transport()
            else:
                transport = None   # real network HTTP, scope-guarded, to the entered host
            result = asyncio.run(run_engagement(
                scope_path=str(scope_path), artifact_paths=[], out_dir=run.out_dir,
                dry_run=False, use_llm=True, discover=bool(crawl), think=bool(think),
                objective_text=run.opts.get("objective", ""), transport=transport,
            ))

            # PER-LAB COVERAGE - ONLY for the bundled VulnLab demo. It hunts EACH lab
            # in ISOLATION (fresh state, the lab's own oracle); the combined surface
            # can only confirm the most generic flaw because every lab's win-oracle
            # expects that lab alone. This is demo-target-specific and MUST NOT run
            # against a real external target (it would re-target localhost) - the exact
            # bug that made an external engagement hunt the wrong host.
            if bundled:
                try:
                    from .coverage import vulnlab_coverage
                    from venom.report import write_report

                    def _on_lab(name, solved, done, total, nsolved):
                        run.push_log(f"[coverage] lab {done}/{total}: {name} - "
                                     f"{'CONFIRMED' if solved else 'not solved'}  "
                                     f"({nsolved} proven so far)")

                    run.push_log("[coverage] hunting each bundled lab in isolation (fresh state per lab)...")
                    cov_cases = asyncio.run(vulnlab_coverage(
                        self._scope_dict(run), concurrency=4,
                        per_lab_calls=SETTINGS.campaign_per_target_calls, on_lab=_on_lab))
                    if cov_cases:
                        merged = _merge_cases(result.cases, cov_cases)
                        # Re-render the report from the merged cases. audit=None means the
                        # original HMAC-signed audit.jsonl is preserved, not overwritten.
                        asyncio.run(write_report(run.out_dir, result.scope, result.registry,
                                                 result.graph, merged, reporter=None, audit=None))
                        result.cases = merged
                        run.push_log(f"[coverage] {len(cov_cases)} additional vulnerability(ies) "
                                     f"proven across isolated labs")
                except Exception as exc:  # noqa: BLE001 - coverage augments; never fails the run
                    logger.warning("per-lab coverage failed: %s", exc)

            findings_json = json.loads((run.out_dir / "findings.json").read_text(encoding="utf-8"))
            run.findings = findings_payload(findings_json)
            run.total_tests = len(result.cases)
            run.meta["tests_run"] = run.total_tests
            run.meta["endpoints"] = len(getattr(result.registry, "endpoints", []) or list(result.registry))
            for f in run.findings:
                if f["severity"] in run.counts:
                    run.counts[f["severity"]] += 1
            run.status = "done"
            run.push_log(f"engagement complete · {len(run.findings)} confirmed "
                         f"({run.counts['crit']} critical · {run.counts['high']} high) of {len(result.cases)} tests")
            run.push_log("trace closed · audit trail HMAC-signed · secrets redacted")
            run.push({"t": "done", "x": "done", "order": 6,
                      "findings_count": len(run.findings), "counts": run.counts})
            self._persist_engagement(run)
            self._persist_trace(run)
        except Exception as exc:  # noqa: BLE001
            run.status = "error"
            run.error = str(exc)
            logger.warning("web run %s failed: %s", run.id, exc)
            run.push({"t": "error", "x": f"engagement error: {exc}", "order": run.stage})
            run.push({"t": "done", "x": "done", "order": run.stage, "findings_count": 0,
                      "counts": run.counts, "error": str(exc)})
        finally:
            root.removeHandler(handler)
            root.setLevel(prev_level)
            run.finish()

    # -- persistence ----------------------------------------------------------
    def _persist_engagement(self, run: Run) -> None:
        path = _data_dir() / "engagements.json"
        rows = []
        if path.exists():
            try:
                rows = json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                rows = []
        rows = [r for r in rows if r.get("id") != run.id]
        rows.insert(0, {
            "id": run.id, "name": run.target_name, "url": run.target_url,
            "status": "done", "crit": run.counts["crit"], "high": run.counts["high"],
            "med": run.counts["med"], "low": run.counts["low"],
            "started": run.started.strftime("%Y-%m-%d %H:%M UTC"), "owner": run.owner, "live": True,
            "authorized_by": run.opts.get("authorized_by") or "",
        })
        try:
            path.write_text(json.dumps(rows[:50], indent=2), encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

    def _persist_trace(self, run: Run) -> None:
        """Save the captured trace so a finished engagement can be re-viewed
        statically (real logs, no animation) even after a restart."""
        trace = {
            "id": run.id, "status": run.status, "counts": run.counts,
            "findings": run.findings, "events": run.events, "meta": run.meta,
            "authorized_by": run.opts.get("authorized_by") or "", "owner": run.owner,
            "target_name": run.target_name, "started": run.started.isoformat(),
        }
        try:
            (run.out_dir / "trace.json").write_text(json.dumps(trace), encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _row(run: "Run") -> dict:
        status = {"running": "live", "error": "error"}.get(run.status, "done")
        return {
            "id": run.id, "name": run.target_name, "url": run.target_url,
            "status": status, "crit": run.counts["crit"], "high": run.counts["high"],
            "med": run.counts["med"], "low": run.counts["low"],
            "started": run.started.strftime("%Y-%m-%d %H:%M UTC"), "owner": run.owner,
            "live": True, "authorized_by": run.opts.get("authorized_by") or "",
        }

    def engagements(self) -> list[dict]:
        """In-memory runs FIRST - including those still RUNNING - so a launched
        engagement appears on the dashboard immediately (not only once it finishes
        and is persisted). Persisted rows fill in past runs from earlier sessions."""
        rows: list[dict] = []
        seen: set[str] = set()
        with self._lock:
            live_runs = list(self.runs.values())
        for run in live_runs:
            rows.append(self._row(run))
            seen.add(run.id)
        path = _data_dir() / "engagements.json"
        if path.exists():
            try:
                for r in json.loads(path.read_text(encoding="utf-8")):
                    if r.get("id") not in seen:
                        rows.append(r)
                        seen.add(r.get("id"))
            except Exception:  # noqa: BLE001
                pass
        rows.sort(key=lambda r: r.get("started", ""), reverse=True)
        return rows

    # -- status / findings (memory first, then persisted trace on disk) -------
    @staticmethod
    def _load_trace(run_id: str) -> dict | None:
        tj = _data_dir() / run_id / "trace.json"
        if tj.exists():
            try:
                return json.loads(tj.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                return None
        return None

    def status_of(self, run_id: str) -> dict | None:
        run = self.runs.get(run_id)
        if run:
            return run.snapshot()
        d = self._load_trace(run_id)
        if d is not None:
            return {"id": run_id, "status": d.get("status", "done"), "stage": 6,
                    "events": d.get("events", []), "findings_count": len(d.get("findings", [])),
                    "counts": d.get("counts", {}), "error": None,
                    "authorized_by": d.get("authorized_by", ""),
                    "target_name": d.get("target_name", "")}
        return None

    def findings_of(self, run_id: str) -> dict | None:
        run = self.runs.get(run_id)
        if run:
            return {"status": run.status, "findings": run.findings, "counts": run.counts,
                    "authorized_by": run.opts.get("authorized_by") or "", "meta": run.meta}
        d = self._load_trace(run_id)
        if d is not None:
            return {"status": "done", "findings": d.get("findings", []),
                    "counts": d.get("counts", {}), "authorized_by": d.get("authorized_by", ""),
                    "meta": d.get("meta", {})}
        fj = _data_dir() / run_id / "findings.json"
        if fj.exists():
            try:
                return {"status": "done",
                        "findings": findings_payload(json.loads(fj.read_text(encoding="utf-8"))),
                        "counts": {}, "authorized_by": "", "meta": {}}
            except Exception:  # noqa: BLE001
                return None
        return None


# module-level singleton (one per server process)
MANAGER = RunManager()
