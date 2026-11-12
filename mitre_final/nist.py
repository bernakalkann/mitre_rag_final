"""MiniLM retrieval over the NIST CSF 2.0 Core."""
import hashlib
import json
from functools import lru_cache
from pathlib import Path

import numpy as np

from .search import DEFAULT_MODEL, load_model, normalize

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data/references/nist_csf_2_0.json"
SOURCE_NAME = "NIST CSF 2.0"
DEFAULT_REVISION = "e8f8c211226b894fcb81acc59f3b34ba3efd5f42"
FUNCTIONS = {
    "GV": "Yönetişim", "ID": "Belirleme", "PR": "Koruma",
    "DE": "Tespit", "RS": "Müdahale", "RC": "Kurtarma",
}


@lru_cache(maxsize=1)
def _index(raw_catalog, model_id, revision):
    catalog = json.loads(raw_catalog)
    model = load_model(model_id, revision, offline=True)
    texts = [f"{record['category']}: {record['description']}" for record in catalog["outcomes"]]
    if any(len(model.tokenizer.encode(text, verbose=False)) > model.max_seq_length for text in texts):
        raise ValueError("A NIST outcome exceeds the embedding model token limit")
    vectors = normalize(model.encode(texts, batch_size=32, convert_to_numpy=True,
                                     normalize_embeddings=True))
    return catalog, model, vectors


def search_nist(query, top_k=3, *, model_id=DEFAULT_MODEL, revision=DEFAULT_REVISION):
    if not query.strip() or top_k < 1:
        raise ValueError("NIST search requires a nonempty query and a positive top_k")
    raw_catalog = CATALOG_PATH.read_bytes()
    catalog, model, vectors = _index(raw_catalog, model_id, revision)
    if len(model.tokenizer.encode(query, verbose=False)) > model.max_seq_length:
        raise ValueError("Query exceeds model token limit; shorten the incident description")

    vector = normalize(model.encode([query], convert_to_numpy=True, normalize_embeddings=True))[0]
    scores = vectors @ vector
    hits = []
    for rank, index in enumerate(np.argsort(-scores, kind="stable")[:top_k], start=1):
        record = catalog["outcomes"][index]
        hits.append({**record, "rank": rank, "score": float(scores[index]),
                     "function": FUNCTIONS[record["id"][:2]]})

    return {
        **{key: catalog[key] for key in ("publisher", "title", "version", "publication_date",
                                        "section", "source_url", "source_document")},
        "catalog_size": len(catalog["outcomes"]),
        "catalog_sha256": hashlib.sha256(raw_catalog).hexdigest(),
        "method": "semantic_cosine",
        "embedding_model": model_id,
        "embedding_revision": revision,
        "device": str(model.device),
        "embedding_dimension": int(vectors.shape[1]),
        "results": hits,
    }
