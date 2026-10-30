"""Run with python -m mitre_final --help from the repository root."""
import argparse
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .data import prepare, sha256, write_json


def main():
    parser = argparse.ArgumentParser(description="MITRE-RAG capstone: weeks 1–6")
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser("download", help="Download the pinned reference release")
    download.add_argument("--output", default="data/raw/enterprise-attack.json")
    data = commands.add_parser("prepare", help="Parse and filter STIX")
    data.add_argument("--source", default="data/raw/enterprise-attack.json")
    data.add_argument("--provenance", default="data/raw/provenance.json")
    data.add_argument("--output", default="data/processed/techniques.jsonl")
    data.add_argument("--report", default="evidence/data_report.json")
    args = parser.parse_args()
    if args.command == "download":
        # Version and content hash identify the actual reference dataset, not 'latest'.
        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json"
        expected = "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3"
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=120) as response:
            content = response.read()
        import hashlib
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("Downloaded data differs from the reference SHA-256; inspect before updating")
        destination.write_bytes(content)
        report = {"source_url": url, "downloaded_at": datetime.now(timezone.utc).isoformat(),
                  "attack_version": "19.1", "sha256": sha256(destination),
                  "file_name": destination.name, "size_bytes": destination.stat().st_size}
        write_json(destination.parent / "provenance.json", report)
    elif args.command == "prepare":
        report = prepare(args.source, args.output, args.provenance)
        write_json(args.report, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
