"""GraphQL ingestion + RAG retriever."""

from pathlib import Path

from venom.core.registry import EndpointRegistry
from venom.ingest import ingest
from venom.ingest.graphql import parse_graphql_sdl
from venom.rag import get_retriever
from venom.rag.retriever import Retriever

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_graphql_sdl_ingestion():
    reg = EndpointRegistry()
    n = parse_graphql_sdl(EXAMPLES / "schema.graphql", reg)
    assert n >= 6  # 3 queries + 3 mutations
    keys = {e.key for e in reg}
    assert any("redeemPoints" in k for k in keys)
    assert any("refundOrder" in k for k in keys)
    # id-bearing query is flagged as an IDOR candidate.
    order = next(e for e in reg if "query.order" in e.path)
    assert "object_reference" in order.business_rule_tags


def test_graphql_via_pipeline():
    res = ingest([EXAMPLES / "schema.graphql"])
    assert len(res.registry) >= 6
    assert any("GraphQL" in note for note in res.notes)


def test_rag_retrieves_by_class_and_terms():
    r = get_retriever()
    hits = r.retrieve("concurrent wallet withdraw double spend",
                      vuln_class="RACE_CONDITION", k=3)
    assert hits
    assert hits[0]["vuln_class"] == "RACE_CONDITION"
    assert "reference" in hits[0]


def test_rag_class_boost_orders_results():
    docs = [
        {"title": "A", "vuln_class": "BOLA_IDOR", "keywords": "id object owner", "reference": "x"},
        {"title": "B", "vuln_class": "RACE_CONDITION", "keywords": "id object owner", "reference": "y"},
    ]
    r = Retriever(docs)
    hits = r.retrieve("object id owner", vuln_class="BOLA_IDOR", k=2)
    assert hits[0]["title"] == "A"  # class boost wins the tie
