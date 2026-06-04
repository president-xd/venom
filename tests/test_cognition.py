"""
Reasoning-layer building blocks: context budgeting and the business-logic
knowledge base. (The end-to-end loop is covered by test_agent, test_oneshot,
test_autonomy_features, and the opt-in live test.)
"""

from venom.llm.budget import trim, compact_html
from venom.knowledge import BUSINESS_LOGIC_KB, kb_prompt


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


def test_kb_prompt_ranks_by_surface():
    # With a surface hint, only the most relevant priors are surfaced (focused context).
    ranked = kb_prompt(surface="email registration domain verification confirmation", limit=4)
    assert "email" in ranked.lower()
    assert len(ranked.splitlines()) <= 4
