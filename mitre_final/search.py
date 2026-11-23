"""Token-aware Sentence Transformer indexing and cosine retrieval."""
import hashlib
import importlib.metadata
import json
from functools import lru_cache
from pathlib import Path
from time import perf_counter

import numpy as np

from .data import read_records, sha256, write_json
from .lexical import B, K1, BM25Index

DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
SEARCH_METHODS = ("semantic", "bm25")
SCORE_NOTICES = {
    "semantic": "Cosine similarity is not a probability or a confirmed attack classification.",
    "bm25": "BM25 measures lexical relevance. It is not a probability or a confirmed attack classification.",
}


def make_chunks(record, tokenizer, max_length, overlap=16):
    title = record["name"] + ": "
    prefix = tokenizer.encode(title, add_special_tokens=False, verbose=False)
    # Reserve special tokens and the title; each chunk keeps its technique name.
    budget = max_length - tokenizer.num_special_tokens_to_add(pair=False) - len(prefix)
    if budget <= overlap:
        raise ValueError("Model token limit is too small for this technique title")
    tokens = tokenizer.encode(record["description"], add_special_tokens=False, verbose=False)
    chunks = []
    start = 0
    while start < len(tokens):
        piece = tokens[start:start + budget]
        # Decoding and re-encoding can change token boundaries at the title.
        # Check the actual model input instead of trusting the arithmetic budget.
        text = title + tokenizer.decode(piece, skip_special_tokens=True)
        while len(tokenizer.encode(text, verbose=False)) > max_length:
            piece = piece[:-1]
            if not piece:
                raise ValueError("Technique title leaves no room for a description")
            text = title + tokenizer.decode(piece, skip_special_tokens=True)
        chunks.append(text)
        if start + len(piece) >= len(tokens):
            break
        start += max(1, len(piece) - overlap)
    return chunks


def normalize(vectors):
    vectors = np.asarray(vectors, dtype=np.float32)
    if vectors.ndim != 2 or not np.isfinite(vectors).all():
        raise ValueError("Expected a finite 2-D embedding matrix")
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    if np.any(norms == 0):
        raise ValueError("Zero-length embedding is invalid")
    return vectors / norms


def rank(query_vector, vectors, chunks, records, top_k=5):
    if top_k < 1:
        raise ValueError("top_k must be positive")
    query = normalize(np.asarray(query_vector).reshape(1, -1))[0]
    vectors = normalize(vectors)
    if len(vectors) != len(chunks) or query.shape[0] != vectors.shape[1]:
        raise ValueError("Index dimensions or chunk count do not match")
    scores = vectors @ query
    lookup = {r["attack_id"]: r for r in records}
    result, seen = [], set()
    # Stable ordering preserves deterministic ties. Max chunk score per technique.
    for i in np.argsort(-scores, kind="stable"):
        chunk = chunks[int(i)]
        technique = chunk["attack_id"]
        if technique in seen:
            continue
        seen.add(technique)
        record = lookup[technique]
        result.append({"rank": len(result) + 1, "attack_id": technique,
                       "name": record["name"], "score": float(scores[i]),
                       "source_url": record["source_url"],
                       "parent_attack_id": record["parent_attack_id"],
                       "tactics": record.get("tactics", []),
                       "evidence_excerpt": chunk["text"]})
        if len(result) == top_k:
            break
    return result


def load_model(model_id, revision=None, offline=False):
    if offline and revision:
        return _offline_model(model_id, revision)
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(model_id, revision=revision, device="cpu", local_files_only=offline)


@lru_cache(maxsize=2)
def _offline_model(model_id, revision):
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(model_id, revision=revision, device="cpu", local_files_only=True)


@lru_cache(maxsize=2)
def _read_index(index_dir, artifact_versions):
    return (np.load(index_dir / "vectors.npy", allow_pickle=False),
            json.loads((index_dir / "chunks.json").read_text()),
            json.loads((index_dir / "records.json").read_text()))


def build_index(records_path, index_dir, model_id=DEFAULT_MODEL, revision=None, offline=False):
    model = load_model(model_id, revision, offline)
    resolved_revision = getattr(model[0].auto_model.config, "_commit_hash", None)
    if not resolved_revision:
        raise ValueError("Cannot resolve model revision; use a Hugging Face model with a commit hash")
    records = read_records(records_path)
    chunks = []
    for record in records:
        for text in make_chunks(record, model.tokenizer, model.max_seq_length):
            chunks.append({"attack_id": record["attack_id"], "text": text})
    start = perf_counter()
    vectors = normalize(model.encode([c["text"] for c in chunks], batch_size=32,
                                    show_progress_bar=True, convert_to_numpy=True,
                                    normalize_embeddings=True))
    index_dir = Path(index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)
    np.save(index_dir / "vectors.npy", vectors, allow_pickle=False)
    write_json(index_dir / "chunks.json", chunks)
    write_json(index_dir / "records.json", records)
    manifest = {"model_id": model_id, "model_revision": resolved_revision,
                "max_seq_length": model.max_seq_length, "device": "cpu",
                "record_count": len(records), "chunk_count": len(chunks),
                "embedding_dimension": int(vectors.shape[1]),
                "index_seconds": perf_counter() - start,
                "source_records_sha256": sha256(records_path),
                "artifacts": {name: sha256(index_dir / name) for name in
                              ("vectors.npy", "chunks.json", "records.json")},
                "packages": {p: importlib.metadata.version(p) for p in
                             ("numpy", "sentence-transformers", "torch", "transformers")}}
    write_json(index_dir / "manifest.json", manifest)
    return manifest


@lru_cache(maxsize=2)
def _read_bm25(index_dir, records_digest):
    path = index_dir / "records.json"
    contents = path.read_bytes()
    if hashlib.sha256(contents).hexdigest() != records_digest:
        raise ValueError("Index integrity check failed: " + path.name)
    return BM25Index(json.loads(contents))


def search(index_dir, query, top_k=5, offline=False, *, method="semantic"):
    if not query.strip() or top_k < 1 or method not in SEARCH_METHODS:
        raise ValueError("Provide a non-empty query, positive top_k and valid search method")
    index_dir = Path(index_dir).resolve()
    manifest = json.loads((index_dir / "manifest.json").read_text(encoding="utf-8"))
    artifacts = manifest["artifacts"]
    checked_artifacts = {"records.json": artifacts["records.json"]} if method == "bm25" else artifacts
    for name, expected in checked_artifacts.items():
        if sha256(index_dir / name) != expected:
            raise ValueError("Index integrity check failed: " + name)

    if method == "bm25":
        lexical = _read_bm25(index_dir, artifacts["records.json"])
        start = perf_counter()
        hits = lexical.rank(query, top_k)
        parameters = {"k1": K1, "b": B}
    else:
        model = load_model(manifest["model_id"], manifest["model_revision"], offline)
        if len(model.tokenizer.encode(query, verbose=False)) > model.max_seq_length:
            raise ValueError("Query exceeds model token limit; shorten the incident description")
        start = perf_counter()
        hits = _semantic_rank(index_dir, artifacts, model, query, top_k)
        parameters = {}
    return {"query": query, "results": hits, "method": method, "parameters": parameters,
            "query_and_ranking_seconds": perf_counter() - start,
            "timing_excludes_model_load": True, "index_manifest": manifest,
            "notice": SCORE_NOTICES[method]}


def _semantic_rank(index_dir, artifacts, model, query, top_k):
    vector = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)[0]
    vectors, chunks, records = _read_index(index_dir, tuple(sorted(artifacts.items())))
    return rank(vector, vectors, chunks, records, top_k)
