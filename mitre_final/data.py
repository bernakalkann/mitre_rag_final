"""STIX ingestion without a runtime dependency on the internship project."""
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_records(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def clean_description(text):
    text = re.sub(r"\(Citation:[^)]*\)", " ", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return " ".join(text.split())


def parse_bundle(bundle):
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Expected a STIX bundle with an objects list")
    objects = bundle["objects"]
    by_id = {o["id"]: o for o in objects if "id" in o}
    parents = {
        o["source_ref"]: o["target_ref"] for o in objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "subtechnique-of"
        and not o.get("revoked") and not o.get("x_mitre_deprecated")
    }
    counts = Counter()
    records = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        counts["attack_patterns"] += 1
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            counts["excluded_inactive"] += 1
            continue
        domains = obj.get("x_mitre_domains", [])
        if domains and "enterprise-attack" not in domains:
            counts["excluded_other_domain"] += 1
            continue
        ref = next((r for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"
                    and re.fullmatch(r"T\d{4}(?:\.\d{3})?", r.get("external_id", ""))), None)
        description = clean_description(obj.get("description", ""))
        if not ref or not obj.get("name") or not description:
            counts["excluded_incomplete"] += 1
            continue
        attack_id = ref["external_id"]
        parent_obj = by_id.get(parents.get(obj["id"]), {})
        parent_id = next((r.get("external_id") for r in parent_obj.get("external_references", [])
                          if r.get("source_name") == "mitre-attack"), None)
        # ATT&CK IDs retain the parent before '.', even if the relation is missing.
        parent_id = parent_id or (attack_id.split(".")[0] if "." in attack_id else None)
        records.append({
            "stix_id": obj["id"], "attack_id": attack_id, "name": obj["name"],
            "description": description, "description_raw": obj["description"],
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", "." in attack_id)),
            "parent_attack_id": parent_id,
            "tactics": sorted({p["phase_name"] for p in obj.get("kill_chain_phases", [])
                               if p.get("kill_chain_name") == "mitre-attack"}),
            "platforms": obj.get("x_mitre_platforms", []),
            "source_url": ref.get("url", "https://attack.mitre.org/techniques/" + attack_id.replace(".", "/") + "/"),
            "modified": obj.get("modified"),
        })
    records.sort(key=lambda r: r["attack_id"])
    if not records:
        raise ValueError("No active Enterprise ATT&CK techniques were found")
    ids = [r["attack_id"] for r in records]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate ATT&CK IDs: use a single-release Enterprise bundle")
    counts.update(active_records=len(records),
                  techniques=sum(not r["is_subtechnique"] for r in records),
                  subtechniques=sum(r["is_subtechnique"] for r in records))
    versions = [o.get("x_mitre_version") for o in objects if o.get("type") == "x-mitre-collection"]
    return records, {"attack_version": versions[0] if versions else None, "counts": dict(counts)}


def prepare(source, output, provenance=None):
    source, output = Path(source), Path(output)
    inherited = json.loads(Path(provenance).read_text()) if provenance else None
    digest = sha256(source)
    if inherited and inherited.get("sha256") != digest:
        raise ValueError("Source SHA-256 does not match its provenance manifest")
    records, report = parse_bundle(json.loads(source.read_text(encoding="utf-8")))
    if inherited and inherited.get("attack_version") and inherited["attack_version"] != report["attack_version"]:
        raise ValueError("ATT&CK version does not match its provenance manifest")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    report.update(source_sha256=digest, records_sha256=sha256(output), provenance=inherited)
    return report
