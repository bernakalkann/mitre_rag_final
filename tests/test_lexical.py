"""Cover BM25 independence and RRF's technique-level ranking."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mitre_final.data import sha256
from mitre_final.lexical import BM25Index, reciprocal_rank_fusion
from mitre_final.search import search


class LexicalTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            {"attack_id": "T1059.001", "name": "PowerShell",
             "description": "PowerShell executes scripts on Windows.", "parent_attack_id": "T1059",
             "source_url": "https://attack.mitre.org/techniques/T1059/001/"},
            {"attack_id": "T1053.005", "name": "Scheduled Task",
             "description": "Windows starts scheduled tasks.", "parent_attack_id": "T1053",
             "source_url": "https://attack.mitre.org/techniques/T1053/005/"},
        ]

    def test_code_and_case_insensitive_lookup_return_real_evidence(self):
        index = BM25Index(self.records)
        for query in ("POWERSHELL", "t1059.001"):
            with self.subTest(query=query):
                hit, = index.rank(query, top_k=5)
                self.assertEqual(hit["attack_id"], "T1059.001")
                self.assertIn(hit["evidence_excerpt"], self.records[0]["description"])
        self.assertEqual(index.rank("eşleşmeyenterim", top_k=5), [])

    def test_bm25_checks_records_without_loading_vectors_or_model(self):
        index_dir = Path(self.enterContext(TemporaryDirectory()))
        records_file = index_dir / "records.json"
        records_file.write_text(json.dumps(self.records), encoding="utf-8")
        manifest = {"artifacts": {"records.json": sha256(records_file), "vectors.npy": "missing"}}
        (index_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with patch("mitre_final.search.load_model") as load_model:
            result = search(index_dir, "PowerShell", method="bm25")
            load_model.assert_not_called()
        self.assertEqual(result["results"][0]["attack_id"], "T1059.001")
        records_file.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Index integrity"):
            search(index_dir, "PowerShell", method="bm25")

    def test_fusion_rewards_agreement_and_deduplicates_codes(self):
        first = {"attack_id": "T1059.001", "score": 0.8, "evidence_excerpt": "semantic"}
        second = {"attack_id": "T1053.005", "score": 63}
        result = reciprocal_rank_fusion({"semantic": [first], "bm25": [second, first, first]}, top_k=2)
        self.assertEqual([hit["attack_id"] for hit in result], ["T1059.001", "T1053.005"])
        self.assertEqual(result[0]["component_ranks"], {"semantic": 1, "bm25": 2})
        self.assertEqual(result[0]["evidence_excerpt"], "semantic")
        self.assertEqual(result[1]["component_ranks"], {"bm25": 1})
        self.assertGreater(result[0]["score"], result[1]["score"])
