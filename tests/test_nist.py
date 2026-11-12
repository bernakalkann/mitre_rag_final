import json
import unittest
from unittest.mock import Mock, patch

from mitre_final.nist import CATALOG_PATH, _index, search_nist


class NistSearchTests(unittest.TestCase):
    def test_catalog_contains_the_full_core(self):
        outcomes = json.loads(CATALOG_PATH.read_bytes())["outcomes"]
        ids = {outcome["id"] for outcome in outcomes}
        self.assertEqual(len(outcomes), 106)
        self.assertEqual(len(ids), len(outcomes))
        self.assertEqual({identifier[:2] for identifier in ids}, {"GV", "ID", "PR", "DE", "RS", "RC"})
        self.assertTrue(all(outcome["category"] and outcome["description"] for outcome in outcomes))

    def test_semantic_ranking_and_catalog_vector_reuse(self):
        model = Mock(device="cpu", max_seq_length=128)
        model.tokenizer.encode.return_value = [1, 2]
        model.encode.side_effect = [[[-1, 0], [0, 1], [1, 0]] + [[-1, 0]] * 103,
                                    [[1, 0]], [[0, 1]]]
        self.addCleanup(_index.cache_clear)
        with patch("mitre_final.nist.load_model", return_value=model) as load_model:
            result = search_nist("Türkçe örnek olay", top_k=2)
            other = search_nist("Second incident", top_k=1)

        self.assertEqual(result["method"], "semantic_cosine")
        self.assertEqual(result["version"], "2.0")
        self.assertRegex(result["catalog_sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual([hit["id"] for hit in result["results"]], ["GV.OC-03", "GV.OC-02"])
        self.assertEqual(other["results"][0]["id"], "GV.OC-02")
        self.assertEqual(len(model.encode.call_args_list[0].args[0]), 106)
        load_model.assert_called_once()
