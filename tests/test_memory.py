"""Working-memory notebook + long-term skill library."""

from venom.memory import Notebook, SkillLibrary, Skill


def test_notebook_facts_and_attempts():
    nb = Notebook()
    nb.set("price", 1337)
    assert nb.get("price") == 1337
    nb.record("price_tamper", "http_post_form /buy", "ok", progressed=True)
    nb.record("price_tamper", "http_post_form /buy", "no change", progressed=False)
    assert nb.tried("http_post_form /buy")
    assert "price_tamper" in nb.strategies_tried()
    r = nb.render()
    assert r["facts"]["price"] == 1337 and r["recent_attempts"]


def test_notebook_stall_detection():
    nb = Notebook()
    for _ in range(4):
        nb.record("coupon", "apply", "still full price", progressed=False)
    assert nb.stalled("coupon", window=4)
    nb.record("coupon", "apply", "dropped!", progressed=True)
    assert not nb.stalled("coupon", window=4)


def test_skill_library_save_and_retrieve(tmp_path):
    lib = SkillLibrary(path=tmp_path / "skills.json")
    lib.add(Skill(name="price_tamper:buy jacket", vuln_class="PARAM_POLLUTION",
                  goal="buy the leather jacket cheaply", keywords=["cart", "product", "checkout"],
                  steps=[{"action": "tamper price"}]))
    # Persisted to disk.
    assert (tmp_path / "skills.json").exists()
    # Retrieval by goal/surface similarity.
    hits = SkillLibrary(path=tmp_path / "skills.json").retrieve(
        "buy the jacket", "product cart checkout", k=3)
    assert hits and hits[0].name.startswith("price_tamper")
    # Irrelevant query returns nothing.
    assert SkillLibrary(path=tmp_path / "skills.json").retrieve("reset password", "login email") == []
