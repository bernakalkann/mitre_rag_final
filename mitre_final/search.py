"""Token-aware Sentence Transformer indexing and cosine retrieval."""
import importlib.metadata
import json
from pathlib import Path
from time import perf_counter

import numpy as np

from .data import read_records, sha256, write_json

DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


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
                       "evidence_excerpt": chunk["text"]})
        if len(result) == top_k:
            break
    return result


def load_model(model_id, revision=None, offline=False):
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(model_id, revision=revision, device="cpu", local_files_only=offline)


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


def search(index_dir, query, top_k=5, offline=False):
    if not query.strip():
        raise ValueError("Query cannot be empty")
    index_dir = Path(index_dir)
    manifest = json.loads((index_dir / "manifest.json").read_text())
    for name, expected in manifest["artifacts"].items():
        if sha256(index_dir / name) != expected:
            raise ValueError("Index integrity check failed: " + name)
    model = load_model(manifest["model_id"], manifest["model_revision"], offline)
    if len(model.tokenizer.encode(query, verbose=False)) > model.max_seq_length:
        raise ValueError("Query exceeds model token limit; shorten the incident description")
    start = perf_counter()
    vector = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)[0]
    hits = rank(vector, np.load(index_dir / "vectors.npy", allow_pickle=False),
                json.loads((index_dir / "chunks.json").read_text()),
                json.loads((index_dir / "records.json").read_text()), top_k)
    return {"query": query, "results": hits, "query_and_ranking_seconds": perf_counter() - start,
            "timing_excludes_model_load": True, "index_manifest": manifest,
            "notice": "Cosine similarity is not a probability or a confirmed attack classification."}
