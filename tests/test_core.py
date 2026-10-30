"""Contract tests use synthetic vectors; they do not claim real model accuracy."""
import json
import tempfile
import unittest
from pathlib import Path


from mitre_final.data import parse_bundle, prepare


def technique(attack_id, **extra):
    return dict(type="attack-pattern", id="attack-pattern--" + attack_id,
                name="Example", description="Some observable behaviour.",
                external_references=[{"source_name": "mitre-attack", "external_id": attack_id}],
                **extra)


class DataTests(unittest.TestCase):
    def test_filters_and_parent(self):
        objects = [technique("T1000"), technique("T1000.001", x_mitre_is_subtechnique=True),
                   technique("T1001", revoked=True), technique("T1002", x_mitre_deprecated=True),
                   technique("T1003", x_mitre_domains=["mobile-attack"])]
        records, report = parse_bundle({"type": "bundle", "objects": objects})
        self.assertEqual([r["attack_id"] for r in records], ["T1000", "T1000.001"])
        self.assertEqual(records[1]["parent_attack_id"], "T1000")
        self.assertEqual(report["counts"]["excluded_inactive"], 2)

    def test_stale_provenance_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.json").write_text(json.dumps({"type": "bundle", "objects": [technique("T1000")]}))
            (root / "manifest.json").write_text('{"sha256": "incorrect"}')
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                prepare(root / "source.json", root / "out.jsonl", root / "manifest.json")
            self.assertFalse((root / "out.jsonl").exists())

    def test_duplicate_ids_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            parse_bundle({"type": "bundle", "objects": [technique("T1000"), technique("T1000")]})

    def test_empty_bundle_rejected(self):
        with self.assertRaises(ValueError):
            parse_bundle({"type": "bundle", "objects": []})



if __name__ == "__main__":
    unittest.main()
