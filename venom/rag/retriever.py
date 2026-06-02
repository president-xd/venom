"""
Pure-Python TF-IDF retriever over the writeup corpus. No numpy/faiss required
(those can be added later for dense retrieval). Retrieval blends term similarity
with an exact vuln-class match boost, which is the strongest signal here.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from functools import lru_cache

from .corpus import BUILTIN_CORPUS

logger = logging.getLogger("venom.rag")

_TOKEN = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class Retriever:
    def __init__(self, docs: list[dict]):
        self.docs = docs
        self._doc_tokens = [
            Counter(_tokens(f"{d.get('title','')} {d.get('keywords','')} {d.get('technique','')}"))
            for d in docs
        ]
        # Inverse document frequency.
        df: Counter = Counter()
        for tf in self._doc_tokens:
            df.update(tf.keys())
        n = max(len(docs), 1)
        self._idf = {t: math.log((n + 1) / (c + 1)) + 1 for t, c in df.items()}

    def _vec(self, tf: Counter) -> dict[str, float]:
        return {t: (cnt) * self._idf.get(t, 1.0) for t, cnt in tf.items()}

    @staticmethod
    def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        common = set(a) & set(b)
        num = sum(a[t] * b[t] for t in common)
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        return num / (na * nb) if na and nb else 0.0

    def retrieve(self, query: str, *, vuln_class: str | None = None, k: int = 3) -> list[dict]:
        q = self._vec(Counter(_tokens(query)))
        scored = []
        for doc, tf in zip(self.docs, self._doc_tokens):
            score = self._cosine(q, self._vec(tf))
            if vuln_class and doc.get("vuln_class") == vuln_class:
                score += 0.5  # strong boost for an exact class match
            if score > 0:
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [d for _, d in scored[:k]]


def _load_corpus() -> list[dict]:
    docs = list(BUILTIN_CORPUS)
    # Optional user corpus: VENOM_DATA_DIR/rag/corpus.json
    try:
        from ..config import SETTINGS

        path = SETTINGS.data_dir / "rag" / "corpus.json"
        if path.exists():
            extra = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(extra, list):
                docs.extend(extra)
                logger.info("Loaded %d custom RAG corpus entries from %s", len(extra), path)
    except Exception as exc:  # noqa: BLE001
        logger.debug("No custom RAG corpus loaded: %s", exc)
    return docs


@lru_cache(maxsize=1)
def get_retriever() -> Retriever:
    return Retriever(_load_corpus())


def annotate_cases(cases) -> None:
    """Attach the top corpus references to each test case (in place)."""
    r = get_retriever()
    for c in cases:
        query = f"{c.affected_endpoint} {c.hypothesis}"
        hits = r.retrieve(query, vuln_class=c.vulnerability_class.value, k=2)
        c.rag_refs = [f"{h['title']} — {h['reference']}" for h in hits]
        if hits and not c.rag_source:
            c.rag_source = hits[0]["reference"]
