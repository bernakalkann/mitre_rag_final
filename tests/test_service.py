"""Verify independent source failures and shared export shape."""
import unittest
from unittest.mock import patch

from mitre_final import service
from mitre_final.rag import RagError

QUERY = "Bir uç nokta alarmında beklenmedik PowerShell etkinliği görüldü."
ATTACK = {"query": QUERY, "results": [{"attack_id": "T1059.001"}]}
NIST = {"results": [{"id": "DE.AE-07"}], "source_url": "https://doi.org/10.6028/NIST.CSWP.29"}


class AnalysisServiceTests(unittest.TestCase):
    def setUp(self):
        self.attack = self.enterContext(patch("mitre_final.search.search", return_value=ATTACK))
        self.nist = self.enterContext(patch("mitre_final.nist.search_nist", return_value=NIST))

    def test_both_sources_keep_original_export_structure(self):
        response = service.analyze(QUERY, k=5)
        self.assertEqual(response["export"], {**ATTACK, "nist_csf": NIST})
        self.assertEqual(response["attack"]["status"], "ok")
        self.assertEqual(response["nist"]["status"], "ok")
        self.assertEqual(self.attack.call_args.args[2], 5)
        self.assertEqual(self.nist.call_args.kwargs["top_k"], 5)

    def test_nist_error_keeps_attack_and_existing_export_fields(self):
        self.nist.side_effect = OSError("NIST cataloğu okunamadı")
        response = service.analyze(QUERY)
        self.assertEqual(response["nist"]["status"], "error")
        self.assertEqual(response["attack"]["items"], ATTACK["results"])
        self.assertEqual(response["export"], {**ATTACK, "nist_csf": None})

    def test_ollama_error_falls_back_to_attack_candidates(self):
        with patch("mitre_final.rag.run_rag", side_effect=RagError("Ollama bağlantısı kurulamadı")):
            response = service.analyze(QUERY, mode="rag")
        self.assertEqual(response["explanation"]["status"], "error")
        self.assertEqual(response["attack"]["status"], "ok")
        self.assertEqual(response["nist"]["status"], "ok")
        self.assertEqual(response["export"], {**ATTACK, "nist_csf": NIST})
        self.attack.assert_called_once()

    def test_both_sources_failing_return_no_export(self):
        self.attack.side_effect = OSError("ATT&CK yok")
        self.nist.side_effect = OSError("NIST yok")
        response = service.analyze(QUERY)
        self.assertIsNone(response["export"])
        self.assertEqual(response["attack"]["status"], "error")
        self.assertEqual(response["nist"]["status"], "error")
