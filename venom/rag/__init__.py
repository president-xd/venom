"""
RAG over a pentest-writeup corpus. Used to augment hypotheses with prior art
("Similar vulnerability found in: …"). Works with zero heavy dependencies via a
pure-Python TF-IDF retriever; if `faiss`+`numpy` are installed, a dense index can
be layered on later. Custom corpora load from VENOM_DATA_DIR/rag/corpus.json.
"""

from .retriever import Retriever, get_retriever, annotate_cases

__all__ = ["Retriever", "get_retriever", "annotate_cases"]
