"""Shared local analysis workflow for both MITRE-RAG interfaces."""
import json
import os
from pathlib import Path
from threading import Lock
from time import monotonic

from . import nist, rag, search

ROOT = Path(__file__).resolve().parents[1]
INDEX_DIR = ROOT / "data/index"
SEMANTIC = "Anlamsal arama"
RAG = "Kaynaklı açıklama (RAG)"
DEFAULT_K = 3
NIST_K = 3
EXAMPLES = {
    "PowerShell": "Güvenlik ekibi, bir Windows uç noktasında PowerShell üzerinden şüpheli bir betik çalıştırıldığını gözlemledi.",
    "Zamanlanmış görev": "An endpoint alert reported a new Windows scheduled task associated with a suspicious executable at user logon.",
    "Kimlik bilgilerine erişim": "Endpoint telemetry recorded an unexpected process accessing LSASS memory.",
    "Yetersiz bağlam": "Kullanıcı bilgisayarında hesap makinesini açtı.",
}
SEARCH_ERRORS = (OSError, ValueError, KeyError, TypeError, RuntimeError, ImportError)
_ANALYSIS_LOCK = Lock()
os.environ.setdefault("HF_HOME", str(ROOT / "data/model_cache"))


def read_attack_manifest(index_dir=INDEX_DIR):
    try:
        manifest = json.loads((Path(index_dir) / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return manifest if isinstance(manifest, dict) else {}


def analyze(text, mode="semantic", k=DEFAULT_K, *, index_dir=INDEX_DIR):
    if not text.strip():
        raise ValueError("Analiz için bir olay açıklaması yazın.")
    if mode not in {"semantic", "rag"} or not 1 <= k <= 10:
        raise ValueError("Analiz modu veya aday sayısı geçersiz.")

    started = monotonic()
    manifest = read_attack_manifest(index_dir)
    attack_result, nist_result, explanation, errors = None, None, None, {}
    with _ANALYSIS_LOCK:
        try:
            nist_result = nist.search_nist(text, top_k=NIST_K,
                                           model_id=manifest.get("model_id") or search.DEFAULT_MODEL,
                                           revision=manifest.get("model_revision") or nist.DEFAULT_REVISION)
        except SEARCH_ERRORS as exc:
            errors["nist"] = str(exc)

        if mode == "rag":
            try:
                attack_result = rag.run_rag(text, index_dir, k, offline=True)
                explanation = {"status": "ok", "text": attack_result["summary"],
                               "sources": attack_result["matches"],
                               "additional_data_needed": attack_result["additional_data_needed"],
                               "error": None}
            except SEARCH_ERRORS as exc:
                explanation = {"status": "error", "text": None, "sources": [], "error": str(exc)}

        if attack_result is None:
            try:
                attack_result = search.search(index_dir, text, k, offline=True)
            except SEARCH_ERRORS as exc:
                errors["attack"] = str(exc)

    attack_items = (attack_result.get("retrieved_sources", attack_result.get("results", []))
                    if attack_result is not None else [])
    nist_items = nist_result["results"] if nist_result is not None else []
    export = None
    if attack_result is not None or nist_result is not None:
        export = {**(attack_result if attack_result is not None else {"query": text, "results": []}),
                  "nist_csf": nist_result}

    return {"attack": source_state(attack_items, errors.get("attack")),
            "nist": source_state(nist_items, errors.get("nist")),
            "explanation": explanation, "export": export, "duration_ms": round((monotonic() - started) * 1000)}


def source_state(items, error):
    return {"status": "error" if error is not None else ("ok" if items else "empty"),
            "items": items, "error": error}


def warm_up():
    """Populate offline caches without requiring Ollama for basic search."""
    result = analyze(EXAMPLES["PowerShell"], k=1)
    return {kind: result[kind]["status"] != "error" for kind in ("attack", "nist")}


def health(warmed):
    manifest = read_attack_manifest()
    try:
        artifacts = manifest["artifacts"]
        attack_ready = warmed["attack"] and all(
            search.sha256(INDEX_DIR / filename) == artifacts[filename]
            for filename in ("vectors.npy", "chunks.json", "records.json")
        )
    except (KeyError, OSError, TypeError):
        attack_ready = False
    try:
        nist_count = len(json.loads(nist.CATALOG_PATH.read_bytes())["outcomes"])
    except (KeyError, OSError, ValueError, TypeError):
        nist_count = None
    try:
        tags = rag.LocalOllama(timeout=1.5)._request("GET", "/api/tags")
        ollama = {"reachable": True, "model_ready": any(
            model.get("name") == rag.DEFAULT_LLM and model.get("digest") for model in tags["models"]
        )}
    except (rag.RagError, KeyError, TypeError, AttributeError):
        ollama = {"reachable": False, "model_ready": False}
    return {"attack_ready": attack_ready, "nist_ready": warmed["nist"] and nist_count is not None,
            "nist_count": nist_count, "ollama": ollama, "model": rag.DEFAULT_LLM}
