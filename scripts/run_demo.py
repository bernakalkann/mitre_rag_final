"""Record real-model demonstration evidence, not a benchmark score."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitre_final.data import write_json
from mitre_final.search import load_model, search


def main():
    index = Path("data/index")
    manifest = json.loads((index / "manifest.json").read_text())
    model = load_model(manifest["model_id"], manifest["model_revision"], offline=True)
    chunks = json.loads((index / "chunks.json").read_text())
    lengths = [len(model.tokenizer.encode(c["text"], verbose=False)) for c in chunks]
    check = {"chunk_count": len(chunks), "max_chunk_tokens": max(lengths),
             "model_token_limit": model.max_seq_length,
             "over_limit_count": sum(n > model.max_seq_length for n in lengths)}
    if check["over_limit_count"]:
        raise ValueError("Some chunks would be silently truncated")
    write_json("evidence/chunk_token_validation.json", check)
    write_json("evidence/index_manifest.json", manifest)
    summary = []
    queries = json.loads(Path("examples/demo_queries.json").read_text())
    names = ["semantic_demo_en", "semantic_demo_tr", "semantic_demo_task", "semantic_demo_lsass"]
    for name, item in zip(names, queries):
        result = search(index, item["query"], 5, offline=True)
        write_json("evidence/" + name + ".json", result)
        summary.append({"name": name, "query": item["query"],
                        "inspect_candidate": item["inspect_candidate"],
                        "top_5": [h["attack_id"] for h in result["results"]],
                        "seconds": result["query_and_ranking_seconds"]})
    write_json("evidence/demo_summary.json", summary)
    print(json.dumps({"token_validation": check, "demos": summary}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
