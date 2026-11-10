"""Tiny TF-IDF retrieval over local markdown playbooks. No network."""
from __future__ import annotations

from pathlib import Path

_CACHE = None


def _chunks() -> list[dict]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    root = Path(__file__).resolve().parent.parent.parent / "data" / "knowledge"
    items = []
    if root.exists():
        for path in sorted(root.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            paras = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 40]
            for i, para in enumerate(paras):
                items.append({"source": path.name, "id": f"{path.stem}-{i}", "text": para})
    _CACHE = items
    return items


def retrieve(query: str, k: int = 3) -> list[dict]:
    docs = _chunks()
    if not docs or not query:
        return []
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except Exception:
        return docs[:k]
    corpus = [d["text"] for d in docs]
    try:
        vec = TfidfVectorizer(stop_words="english", max_features=4000)
        matrix = vec.fit_transform(corpus + [query])
        scores = cosine_similarity(matrix[-1], matrix[:-1]).flatten()
    except Exception:
        return docs[:k]
    ranked = sorted(range(len(docs)), key=lambda i: scores[i], reverse=True)[:k]
    out = []
    for i in ranked:
        if scores[i] <= 0:
            continue
        snippet = docs[i]["text"]
        if len(snippet) > 420:
            snippet = snippet[:420].rsplit(" ", 1)[0] + "…"
        out.append({"source": docs[i]["source"], "snippet": snippet, "score": round(float(scores[i]), 3)})
    return out
