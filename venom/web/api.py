"""
JSON API handlers - every one is backed by a REAL venom module (the knowledge
base, the agent fleet, the provider router, the scope guard). The dashboard
shows only real runs you launch; nothing is mocked.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone

from .mappers import kb_to_ui
from .runs import MANAGER, _data_dir

__version__ = "0.1.0"

# No seed/demo engagements - the dashboard shows only real runs you launch.
DEMO_ENGAGEMENTS: list[dict] = []


def _kill_switch_on() -> bool:
    return os.getenv("VENOM_KILL_SWITCH", "").lower() in ("1", "true", "yes")


def base_urls(url: str, scope_paths) -> list[str]:
    """The bare host (so the whole app stays in scope) PLUS an explicit, recorded
    entry per in-scope path prefix. Additive: prefixes are documented and gate
    sub-paths, but never silently shrink the host scope on the bundled demo target."""
    out = [url.rstrip("/")]
    for p in (scope_paths or []):
        seg = "/" + (p or "").strip().lstrip("/").rstrip("*").strip("/")
        if seg and seg != "/":
            entry = url.rstrip("/") + seg
            if entry not in out:
                out.append(entry)
    return out


_base_urls = base_urls   # internal alias


def api_status() -> dict:
    return {
        "version": __version__,
        "scope_guard": "armed",
        "kill_switch": _kill_switch_on(),
        "redaction": True,            # always-on (utils.redact_secrets)
        "air_gap": os.getenv("LLM_AIR_GAP", "").lower() in ("1", "true", "yes"),
    }


def _knowledge_path():
    return _data_dir() / "knowledge.json"


def _load_custom_kb() -> list[dict]:
    p = _knowledge_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return []
    return []


def api_vuln_classes() -> dict:
    from venom.knowledge.business_logic import BUSINESS_LOGIC_KB
    return {"classes": kb_to_ui(BUSINESS_LOGIC_KB) + _load_custom_kb()}


def api_add_knowledge(body: dict) -> dict:
    """Add a custom business-logic prior to the knowledge base (persisted)."""
    name = (body.get("name") or "").strip()
    if not name:
        return {"ok": False, "error": "A name is required."}
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48] or "entry"
    items = _load_custom_kb()
    if any(e.get("id") == "custom-" + slug for e in items):
        slug = f"{slug}-{len(items) + 1}"
    entry = {
        "id": "custom-" + slug,
        "name": name,
        "desc": (body.get("desc") or "").strip(),
        "cwe": (body.get("cwe") or "custom").strip(),
        "probe": (body.get("probe") or "").strip(),
        "exploit": (body.get("exploit") or "").strip(),
        "refs": [r for r in (body.get("refs") or []) if r],
        "custom": True,
    }
    items.append(entry)
    try:
        _knowledge_path().write_text(json.dumps(items, indent=2), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"could not persist: {exc}"}
    return {"ok": True, "entry": entry}


def api_agents() -> dict:
    from venom.agents.roles import DEFAULT_AGENTS
    fleet = []
    for role, spec in DEFAULT_AGENTS.items():
        fleet.append({"role": role.value, "model": spec.model(),
                      "provider": spec.provider.value, "description": spec.description})
    return {"fleet": fleet}


def api_providers() -> dict:
    from venom.llm import LLMRouter, Provider
    names = {Provider.DEEPSEEK: "DeepSeek", Provider.NVIDIA_NIM: "NVIDIA NIM",
             Provider.OPENROUTER: "OpenRouter", Provider.OLLAMA: "Ollama (local)"}
    out = []
    try:
        router = LLMRouter.from_env()
        for provider, cfg in router.providers.items():
            configured = bool(cfg.api_key) or provider == Provider.OLLAMA
            out.append({"id": provider.value, "name": names.get(provider, provider.value),
                        "enabled": bool(cfg.enabled), "configured": configured,
                        "model": cfg.model})
        any_enabled = router.any_enabled()
    except Exception as exc:  # noqa: BLE001
        return {"providers": [], "any_enabled": False, "error": str(exc)}
    return {"providers": out, "any_enabled": any_enabled,
            "air_gap": os.getenv("LLM_AIR_GAP", "").lower() in ("1", "true", "yes")}


def api_scope_validate(body: dict) -> dict:
    from venom.core.scope import Scope, ScopeError
    url = (body.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "A target base URL is required."}
    now = datetime.now(timezone.utc)
    scope_dict = {
        "engagement_id": body.get("engagement_id") or "ENG-WEB-PREVIEW",
        "target_name": body.get("target_name") or url,
        "authorized_base_urls": _base_urls(url, body.get("scope_paths")),
        "out_of_scope": [h for h in (body.get("out_of_scope") or []) if h],
        "rate_limit_per_second": float(body.get("rate", 5) or 5),
        "allow_destructive": bool(body.get("destructive", False)),
        "authorized_by": body.get("authorized_by") or "VENOM web console",
        "authorization_date": body.get("authorization_date") or now.isoformat(),
        "expiry_date": body.get("expiry_date") or (now + timedelta(days=1)).isoformat(),
    }
    try:
        scope = Scope.from_dict(scope_dict)
        scope.validate_window()
    except ScopeError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "summary": scope.summary()}


# An engagement is visible to a user if they own it, or it is a legacy/demo row
# (no real owner) so the bundled demo + pre-multi-user runs stay visible to everyone.
_SHARED_OWNERS = {"You", "demo", "VENOM", "", None}


def _owner_of(row: dict) -> str:
    return row.get("owner") or ""


def _visible_to(owner: str, user: str | None) -> bool:
    return owner in _SHARED_OWNERS or (user is not None and owner == user)


def run_visible_to(run_id: str, user: str | None) -> bool:
    """Authorization for the per-run endpoints: a user may only read a run they own
    (or a shared/demo run). Unknown runs are 'visible' so the handler can 404 itself."""
    owner = MANAGER.owner_of(run_id)
    if owner is None:
        for e in DEMO_ENGAGEMENTS:
            if e.get("id") == run_id:
                return True
        return True   # unknown -> let the status handler return its own 404
    return _visible_to(owner, user)


def api_engagements(user: str | None = None) -> dict:
    real = MANAGER.engagements()
    real_ids = {r.get("id") for r in real}
    rows = real + [e for e in DEMO_ENGAGEMENTS if e["id"] not in real_ids]
    rows = [r for r in rows if _visible_to(_owner_of(r), user)]
    return {"engagements": rows}


def api_start_run(body: dict, user: str | None = None) -> dict:
    if _kill_switch_on():
        return {"error": "Kill switch engaged (VENOM_KILL_SWITCH); runs are halted."}
    opts = {
        "target_name": body.get("target_name") or "VulnLab",
        "target_url": body.get("target_url") or "localhost:8000",
        "objective": body.get("objective") or "",
        "rate": body.get("rate", 5),
        "destructive": bool(body.get("destructive", False)),
        "max_pages": body.get("max_pages", 40),
        "classes": body.get("classes") or [],
        # The live engagement is an LLM-driven hunt (recon -> infer -> hypothesize ->
        # exploit -> verify). These toggles shape it; a provider is required (the run
        # fails honestly otherwise). `think` runs the autonomous agent loop; `crawl`
        # enables live discovery.
        "use_llm": bool(body.get("use_llm", True)),
        "think": bool(body.get("think", True)),
        "crawl": bool(body.get("crawl", True)),
        # editable scope from the wizard: hard-blocked hosts + in-scope path prefixes
        "out_of_scope": [h for h in (body.get("out_of_scope") or []) if h],
        "scope_paths": [p for p in (body.get("scope_paths") or []) if p],
        # operator-supplied login credentials so the agent can authenticate to the target
        "identities": [i for i in (body.get("identities") or []) if i.get("name")],
        # inbox/exploit-server email URL - unlocks registration/email-parser flows
        "email_client_url": (body.get("email_client_url") or "").strip(),
        # written authorization - supplied by the operator in the wizard
        "authorized_by": (body.get("authorized_by") or "").strip(),
        "authorization_date": body.get("authorization_date") or "",
        "expiry_date": body.get("expiry_date") or "",
        # owner = the logged-in operator, so each user sees only their own engagements
        "owner": user or "operator",
    }
    run_id = MANAGER.start(opts)
    return {"id": run_id}


def api_run_status(run_id: str) -> dict:
    return MANAGER.status_of(run_id) or {"error": "run not found"}


def api_run_findings(run_id: str) -> dict:
    return MANAGER.findings_of(run_id) or {"error": "run not found"}
