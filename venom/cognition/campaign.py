"""
Coverage campaign - hunt the WHOLE surface, not a single objective.

A real target has MANY flaws. A single-objective run finds at most one and stops.
The campaign turns the hunt into systematic coverage:

  1. DECOMPOSE the reconned surface into many scoped, differential objectives -
     every action currently FORBIDDEN to the tester ('denied_to_you') is a
     candidate flaw: "denied now, a vulnerability if it can be made to succeed".
  2. Hunt EACH target with a focused, fresh best-of-N one-shot.
  3. CONTINUE after every confirmation - never stop at the first win - until the
     surface is covered or the global budget is spent.

Every confirmation is independently proven by the differential oracle (forbidden
at baseline -> succeeds after the exploit), so more findings never means more false
positives. The accessible/denied recon is computed ONCE and reused across targets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..testing.schema import TestCase
from .objective import Objective
from .oneshot import oneshot_hunt

logger = logging.getLogger("venom.cognition.campaign")

# Targets touching these get hunted first - economic / destructive / privileged
# actions are where business-logic impact concentrates.
_HIGH_VALUE = ("admin", "delete", "refund", "transfer", "payout", "wire", "approve",
               "promote", "role", "grant", "escalate", "reset", "deploy")
_ECONOMIC = ("wallet", "balance", "credit", "coupon", "money", "bank", "pay", "fund",
             "invoice", "billing", "loyalty", "fx", "license", "quota")
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def _endpoint_data(registry, method: str, path: str) -> dict:
    """Plausible body for a forbidden mutating action, from the discovered form."""
    for e in registry:
        if e.method.upper() == method.upper() and e.path == path:
            data = dict(getattr(e, "form_defaults", {}) or {})
            for p in getattr(e, "parameters", []):
                if getattr(p, "location", "") in ("form", "body") and p.name not in data:
                    data.setdefault(p.name, "1")
            return data
    return {}


def _rank(label: str) -> int:
    """Lower = hunted earlier."""
    p = label.lower()
    score = 0
    if any(h in p for h in _HIGH_VALUE):
        score -= 3
    if any(h in p for h in _ECONOMIC):
        score -= 2
    if label.split(" ", 1)[0].upper() in _MUTATING:
        score -= 1
    return score


def derive_objectives(registry, enrichment: dict | None, *, base_objective: str = "",
                      max_targets: int = 12) -> list[Objective]:
    """Decompose the surface into many differential objectives - one per forbidden
    action discovered, highest business-impact first."""
    objs: list[Objective] = []
    seen: set[tuple[str, str]] = set()
    denied = list((enrichment or {}).get("denied_to_you", []))
    for label in sorted(denied, key=_rank):
        parts = label.split(" ", 1)
        if len(parts) != 2:
            continue
        method, path = parts[0].upper(), parts[1].strip()
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        data = _endpoint_data(registry, method, path) if method in _MUTATING else {}
        desc = f"Escalate from the current low-privileged user to perform the " \
               f"currently-FORBIDDEN action {method} {path}"
        if base_objective:
            desc += f" - engagement goal: {base_objective}"
        objs.append(Objective(description=desc,
                              win_action={"method": method, "path": path, "data": data}))
        if len(objs) >= max_targets:
            break
    return objs


@dataclass
class CampaignResult:
    findings: list[TestCase] = field(default_factory=list)
    attempted: int = 0
    confirmed: int = 0
    targets: list[dict] = field(default_factory=list)

    def summary(self) -> str:
        return f"coverage campaign: {self.confirmed} confirmed of {self.attempted} targets attempted"


async def run_campaign(scope, registry, synth_factory, *, objectives: list[Objective],
                       transport=None, enrichment: dict | None = None,
                       per_target_calls: int = 3, max_targets: int = 12) -> CampaignResult:
    """Hunt EACH objective with a fresh focused one-shot (fresh best-of-N diversity),
    collecting ALL confirmed findings. Continues after each confirmation; a single
    target's error never aborts the campaign."""
    res = CampaignResult()
    for obj in objectives[:max_targets]:
        res.attempted += 1
        try:
            synth = synth_factory()   # fresh per target -> resets best-of-N temperature
            found = await oneshot_hunt(scope, registry, synth, objective=obj,
                                       transport=transport, max_llm_calls=per_target_calls,
                                       enrichment=enrichment)
        except Exception as exc:  # noqa: BLE001 - one target must not abort coverage
            logger.warning("campaign target %s errored: %s", obj.win_action, exc)
            found = []
        confirmed = bool(found)
        if confirmed:
            res.findings.extend(found)
            res.confirmed += 1
            logger.info("campaign: CONFIRMED %s  (%d confirmed / %d attempted)",
                        obj.win_action, res.confirmed, res.attempted)
        res.targets.append({"win_action": obj.win_action, "confirmed": confirmed})
    logger.info("%s", res.summary())
    return res
