"""
Reasoning layer: context budgeting, the business-logic knowledge base, and the
adaptive loop. The reasoner test proves the loop can confirm an exploit with NO
playbook — driven only by a (stub) brain reasoning over observations.
"""

import asyncio
from urllib.parse import parse_qs

import httpx

from venom.llm.budget import trim, compact_html
from venom.knowledge import BUSINESS_LOGIC_KB, kb_prompt
from venom.core.scope import Scope
from venom.cognition import Reasoner, Action
from venom.testing.schema import Verdict

BASE = "https://reason.example.net"


# ---------------------------------------------------------------- budgeting
def test_trim_head_and_tail():
    out = trim("A" * 10_000, limit=200)
    assert len(out) < 400 and "trimmed" in out


def test_compact_html_handles_unquoted_attrs():
    html = ('<html><script>var x=1</script><body>'
            '<form action=/buy method=POST>'
            '<input type=hidden name=price value=1337>'
            '<input type=hidden name=csrf value=ABC123></form>'
            '<a href=/cart>cart</a></body></html>')
    v = compact_html(html)
    assert v["forms"], "no form parsed"
    fields = {f["name"]: f["value"] for f in v["forms"][0]["fields"]}
    assert fields.get("price") == "1337"          # unquoted value captured
    assert fields.get("csrf") == "ABC123"
    assert "/cart" in v["links"]
    assert "var x" not in (v["text"] or "")        # script stripped


# ---------------------------------------------------------------- knowledge
def test_kb_has_core_classes():
    ids = {k["id"] for k in BUSINESS_LOGIC_KB}
    assert {"client-side-trust", "race-condition", "idor-bola", "sequence-bypass"} <= ids
    assert "client-side-trust" in kb_prompt()


# ---------------------------------------------------------------- reasoning loop
def make_app():
    def page(b):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text=f"<html><body>{b}</body></html>")

    def handler(req: httpx.Request) -> httpx.Response:
        path, method = req.url.path, req.method
        form = {k: v[0] for k, v in parse_qs(req.content.decode() if req.content else "").items()}
        if path == "/product" and method == "GET":
            return page('<form action=/buy method=POST>'
                        '<input type=hidden name=productId value=1>'
                        '<input type=hidden name=price value=1337></form>')
        if path == "/buy" and method == "POST":
            # The flaw: the server trusts the client-supplied price.
            if int(form.get("price", "1337")) < 100:
                return page("<div class='is-solved'>Order placed. Thank you!</div>")
            return page("<div>Charged in full.</div>")
        return httpx.Response(404, headers={"content-type": "text/html"}, text="nf")

    return httpx.MockTransport(handler)


def _stub_brain():
    """A deterministic 'brain' that reasons from observations — not a playbook.
    It probes the product page, reads the form it gets back, then tampers price."""
    async def decide(observation, history):
        if not history:
            return Action(type="probe", method="GET", path="/product?productId=1",
                          rationale="learn the purchase form")
        forms = (history[-1].get("view") or {}).get("forms") or []
        for f in forms:
            names = {fl["name"] for fl in f["fields"]}
            if "price" in names:
                body = {fl["name"]: ("1" if fl["name"] == "price" else fl["value"])
                        for fl in f["fields"]}
                return Action(type="exploit", method=f["method"] or "POST",
                              path=f["action"] or "/buy", form=body,
                              success_signal="is-solved", vuln_class="PARAM_POLLUTION",
                              title="client-side price tampering", rationale="tamper trusted price")
        return Action(type="conclude")
    return decide


def _scope():
    return Scope.from_dict({
        "engagement_id": "ENG-RSN", "target_name": "ReasonShop",
        "authorized_base_urls": [BASE], "rate_limit_per_second": 500,
        "authorization_date": "2026-01-01T00:00:00Z", "expiry_date": "2030-01-01T00:00:00Z",
    })


def test_reasoner_confirms_without_a_playbook():
    reasoner = Reasoner(_scope(), _stub_brain(), transport=make_app(), max_steps=6)
    obs = {"target": "ReasonShop", "base": BASE, "identities": [],
           "endpoints": [{"method": "GET", "path": "/product?productId=1"}], "history": []}
    findings = asyncio.run(reasoner.investigate(None, observation=obs))
    assert findings, "reasoner did not confirm anything"
    f = findings[0]
    assert f.verdict == Verdict.CONFIRMED_EXPLOIT
    assert f.origin == "reasoner"
