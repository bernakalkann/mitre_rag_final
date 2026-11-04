"""Contract tests use synthetic vectors; they do not claim real model accuracy."""
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from mitre_final.data import parse_bundle, prepare
from mitre_final.search import make_chunks, normalize, rank


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


class SearchTests(unittest.TestCase):
    def test_cosine_ranking_deduplicates_chunks(self):
        records = [{"attack_id": identifier, "name": identifier, "source_url": "https://attack.mitre.org/",
                    "parent_attack_id": None} for identifier in ("T1000", "T1001")]
        chunks = [{"attack_id": identifier, "text": "evidence"} for identifier in ("T1000", "T1000", "T1001")]
        hits = rank([1, 0], np.array([[10, 0], [0.9, 0.1], [0, 2]]), chunks, records, 2)
        self.assertEqual([h["attack_id"] for h in hits], ["T1000", "T1001"])
        self.assertAlmostEqual(hits[0]["score"], 1)

    def test_bad_vectors_rejected(self):
        for vectors in ([[0, 0]], [[float("nan"), 1]], [1, 2]):
            with self.assertRaises(ValueError):
                normalize(vectors)

    def test_invalid_top_k(self):
        with self.assertRaises(ValueError):
            rank([1, 0], [[1, 0]], [], [], 0)

    def test_chunking_preserves_full_description(self):
        class WordTokenizer:
            def encode(self, text, **kwargs):
                return text.split()
            def decode(self, tokens, **kwargs):
                return " ".join(tokens)
            def num_special_tokens_to_add(self, **kwargs):
                return 2
        words = ["w" + str(i) for i in range(80)]
        chunks = make_chunks({"name": "Technique", "description": " ".join(words)}, WordTokenizer(), 32, overlap=4)
        for word in words:
            self.assertIn(word, " ".join(chunks).split())
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(chunk.split()) + 2 <= 32 for chunk in chunks))

    def test_chunking_checks_reencoded_boundaries(self):
        class BoundaryTokenizer:
            def encode(self, text, add_special_tokens=True, **kwargs):
                parts = text.split()
                # Simulate an extra token at the reconstructed title boundary.
                if add_special_tokens and text.startswith("Technique:"):
                    parts = parts + ["boundary"]
                return parts
            def decode(self, tokens, **kwargs):
                return " ".join(tokens)
            def num_special_tokens_to_add(self, **kwargs):
                return 0
        tokenizer = BoundaryTokenizer()
        chunks = make_chunks({"name": "Technique", "description": " ".join("w"+str(i) for i in range(30))},
                             tokenizer, 12, overlap=2)
        self.assertTrue(all(len(tokenizer.encode(text)) <= 12 for text in chunks))
        self.assertIn("w29", chunks[-1])


if __name__ == "__main__":
    unittest.main()
