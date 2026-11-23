"""Reproduce the first ATT&CK retrieval comparison with the cached embedding model."""
import importlib.metadata
import json
import os
import platform
from pathlib import Path

from .data import sha256
from .search import SEARCH_METHODS, search


def compare_retrieval(index_dir, queries_path, data_report_path, top_k=5):
    cases = json.loads(Path(queries_path).read_text(encoding="utf-8"))
    if not cases:
        raise ValueError("At least one comparison query is required")
    data = json.loads(Path(data_report_path).read_text(encoding="utf-8"))
    manifest = json.loads((Path(index_dir) / "manifest.json").read_text(encoding="utf-8"))
    if manifest["source_records_sha256"] != data["records_sha256"]:
        raise ValueError("Dataset report does not match the indexed records")

    os.environ.setdefault("HF_HOME", str(Path(index_dir).resolve().parent / "model_cache"))
    parameters = {}
    for method in SEARCH_METHODS:
        warmup = search(index_dir, cases[0]["query"], top_k, offline=True, method=method)
        parameters[method] = warmup["parameters"]

    results = []
    for case in cases:
        query, target = case["query"], case["inspect_candidate"]
        methods = {}
        for method in SEARCH_METHODS:
            result = search(index_dir, query, top_k, offline=True, method=method)
            hits = result["results"]
            methods[method] = {
                "target_rank": next((hit["rank"] for hit in hits if hit["attack_id"] == target), None),
                "query_and_ranking_ms": round(result["query_and_ranking_seconds"] * 1000, 3),
                "candidates": [{key: hit[key] for key in ("attack_id", "name", "rank", "score")}
                               for hit in hits],
            }
        results.append({"query": query, "inspect_candidate": target, "methods": methods})

    return {
        "dataset": {key: data[key] for key in ("attack_version", "source_sha256", "records_sha256")},
        "index_manifest": manifest,
        "queries_sha256": sha256(queries_path),
        "environment": {
            "python": platform.python_version(),
            "system": platform.platform(),
            "device": "cpu",
            "packages": {name: importlib.metadata.version(name) for name in manifest["packages"]},
        },
        "top_k": top_k,
        "parameters": parameters,
        "timing": "One warm-cache run per query and method; index verification and initialization excluded.",
        "results": results,
    }
