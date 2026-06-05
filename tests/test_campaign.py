"""
Coverage campaign — the fix for "finds only one vulnerability". The hunt must
decompose the surface into many forbidden-action targets and prove EVERY one it
can, never stopping at the first confirmation.
"""

from dataclasses import dataclass, field

import pytest

from venom.cognition import campaign
from venom.cognition.campaign import CampaignResult, derive_objectives, run_campaign
from venom.testing.schema import Severity, TestCase, VulnClass, Verdict


# ---- tiny registry stub for derive_objectives -----------------------------------
@dataclass
class _Param:
    name: str
    location: str = "form"


@dataclass
class _EP:
    method: str
    path: str
    form_defaults: dict = field(default_factory=dict)
    parameters: list = field(default_factory=list)


_REGISTRY = [
    _EP("POST", "/admin/delete", {"username": "carlos"}),
    _EP("POST", "/pay/refund", parameters=[_Param("order_id")]),
    _EP("GET", "/account"),
]


def _enrichment(denied):
    return {"denied_to_you": denied, "accessible_to_you": [], "probed": []}


# ---- decomposition --------------------------------------------------------------
def test_derive_objectives_decomposes_every_forbidden_action():
    enr = _enrichment(["POST /admin/delete", "POST /pay/refund", "GET /reports"])
    objs = derive_objectives(_REGISTRY, enr)
    paths = {o.win_action["path"] for o in objs}
    assert paths == {"/admin/delete", "/pay/refund", "/reports"}
    # every objective is a real differential win-action
    assert all(o.win_action and o.win_action.get("method") for o in objs)


def test_derive_objectives_fills_body_from_discovered_form():
    objs = derive_objectives(_REGISTRY, _enrichment(["POST /admin/delete"]))
    delete = next(o for o in objs if o.win_action["path"] == "/admin/delete")
    assert delete.win_action["data"] == {"username": "carlos"}     # from form_defaults


def test_derive_objectives_prioritizes_high_value_first():
    enr = _enrichment(["GET /reports", "POST /admin/delete", "GET /help"])
    objs = derive_objectives(_REGISTRY, enr)
    # the destructive admin action must be hunted before low-value reads
    assert objs[0].win_action["path"] == "/admin/delete"


def test_derive_objectives_caps_targets():
    enr = _enrichment([f"POST /x{i}/act" for i in range(50)])
    assert len(derive_objectives(_REGISTRY, enr, max_targets=7)) == 7


# ---- orchestration (monkeypatch the per-target hunt) ----------------------------
def _finding(path):
    return TestCase(test_id="C-1", vulnerability_class=VulnClass.PRIV_ESCALATION,
                    hypothesis=f"win {path}", risk_rating=Severity.HIGH,
                    affected_endpoint=path, verdict=Verdict.CONFIRMED_EXPLOIT)


async def test_campaign_collects_all_and_does_not_stop_at_one(monkeypatch):
    """Three targets all winnable → THREE findings (the whole point)."""
    async def fake_oneshot(scope, registry, synth, *, objective, **kw):
        return [_finding(objective.win_action["path"])]
    monkeypatch.setattr(campaign, "oneshot_hunt", fake_oneshot)

    objs = derive_objectives(_REGISTRY, _enrichment(
        ["POST /admin/delete", "POST /pay/refund", "GET /reports"]))
    res = await run_campaign(None, _REGISTRY, lambda: object(), objectives=objs)
    assert res.confirmed == 3 and res.attempted == 3
    assert len(res.findings) == 3
    assert {f.affected_endpoint for f in res.findings} == {"/admin/delete", "/pay/refund", "/reports"}


async def test_campaign_continues_past_failures(monkeypatch):
    """Only some targets winnable → the campaign keeps going and reports the wins."""
    async def fake_oneshot(scope, registry, synth, *, objective, **kw):
        return [_finding(objective.win_action["path"])] if "admin" in objective.win_action["path"] else []
    monkeypatch.setattr(campaign, "oneshot_hunt", fake_oneshot)

    objs = derive_objectives(_REGISTRY, _enrichment(["POST /admin/delete", "POST /pay/refund"]))
    res = await run_campaign(None, _REGISTRY, lambda: object(), objectives=objs)
    assert res.attempted == 2 and res.confirmed == 1
    assert res.findings[0].affected_endpoint == "/admin/delete"


async def test_campaign_one_target_error_does_not_abort(monkeypatch):
    async def fake_oneshot(scope, registry, synth, *, objective, **kw):
        if "boom" in objective.win_action["path"]:
            raise RuntimeError("synthesis blew up")
        return [_finding(objective.win_action["path"])]
    monkeypatch.setattr(campaign, "oneshot_hunt", fake_oneshot)

    enr = _enrichment(["POST /boom/x", "POST /admin/delete"])
    objs = derive_objectives(_REGISTRY, enr)
    res = await run_campaign(None, _REGISTRY, lambda: object(), objectives=objs)
    assert res.attempted == 2                       # both attempted despite the error
    assert res.confirmed == 1                        # the healthy one still confirmed
