"""Exercise the Streamlit form and result states without loading local models."""
import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from streamlit_app import EXAMPLES, RAG

APP = Path(__file__).resolve().parents[1] / "streamlit_app.py"
HIT = {
    "attack_id": "T1059.001",
    "name": "PowerShell",
    "source_url": "https://attack.mitre.org/techniques/T1059/001/",
    "tactics": ["execution"],
    "parent_attack_id": "T1059",
}
QUERY = EXAMPLES["PowerShell"]
NIST = {
    "section": "Appendix A · CSF Core", "catalog_size": 106,
    "source_url": "https://doi.org/10.6028/NIST.CSWP.29",
    "results": [{"rank": 1, "id": "DE.CM-09", "function": "Tespit",
                 "category": "Continuous Monitoring", "description": "Örnek kaynak metni", "score": 0.5}],
}


class StreamlitAppTests(unittest.TestCase):
    def setUp(self):
        self.nist_search = self.enterContext(patch("mitre_final.nist.search_nist", return_value=NIST))
        self.app = AppTest.from_file(str(APP), default_timeout=60).run()
        self.assertFalse(self.app.exception)

    def submit(self, query):
        self.app.text_area[0].set_value(query)
        next(button for button in self.app.button if button.label == "Analiz et").click().run()
        self.assertFalse(self.app.exception)

    def test_load_example_and_render_semantic_result(self):
        self.assertFalse(self.app.get("iframe"))
        self.app.selectbox[0].select("Kimlik bilgilerine erişim").run()
        next(button for button in self.app.button if button.label == "Örneği girdiye aktar").click().run()
        query = EXAMPLES["Kimlik bilgilerine erişim"]
        self.assertEqual(self.app.text_area[0].value, query)

        hit = {**HIT, "score": -0.125, "evidence_excerpt": "Örnek kaynak metni"}
        with patch("mitre_final.search.search", return_value={"query": query, "results": [hit]}) as search:
            self.submit(query)
        self.assertEqual(search.call_args.args[1:], (query, 3))
        self.assertTrue(search.call_args.kwargs["offline"])
        self.assertIn("PowerShell", [item.value for item in self.app.subheader])
        self.assertTrue(any("Örnek kaynak metni" in item.value for item in self.app.markdown))
        nist_button = self.app.button(key="candidate_nist_DE.CM-09")
        self.assertIn("Continuous Monitoring", nist_button.label)
        nist_button.click().run()
        self.assertIn("Continuous Monitoring", [item.value for item in self.app.subheader])
        self.assertEqual(search.call_count, 1)
        table = next(item.value for item in self.app.markdown if "tactic-table" in item.value
                     and "<table" in item.value)
        self.assertIn("Execution</th><td>1</td>", table)
        self.assertEqual(self.nist_search.call_args.args, (query,))
        self.assertEqual(self.nist_search.call_count, 1)
        self.assertTrue(self.nist_search.call_args.kwargs["revision"])
        self.assertIn('"nist_csf"', self.app.json[0].value)
        self.assertTrue(any('class="score-chart"' in item.value for item in self.app.markdown))
        self.assertEqual(len(self.app.get("download_button")), 1)
        self.assertEqual(len(self.app.get("iframe")), 1)
        self.app.run()
        self.assertFalse(self.app.get("iframe"))

    def test_rag_explains_only_supported_hits_and_handles_insufficient_context(self):
        self.app.radio[0].set_value(RAG)
        source = {**HIT, "retrieval_score": 0.725, "excerpt": "Örnek kaynak metni"}
        other = {**source, "attack_id": "T1059", "name": "Command Interpreter",
                 "tactics": ["execution", "execution", "discovery"]}
        match = {**HIT, "explanation": "Örnek açıklama", "evidence_quote": source["excerpt"]}
        result = {"query": QUERY, "summary": "Örnek değerlendirme", "matches": [match],
                  "retrieved_sources": [source, other], "additional_data_needed": []}
        with patch("mitre_final.rag.run_rag", return_value=result):
            self.submit(QUERY)
        self.assertEqual([item.value for item in self.app.markdown].count("**Neden bu teknik?**"), 1)
        self.assertIn("Örnek açıklama", [item.value for item in self.app.markdown])
        table = next(item.value for item in self.app.markdown if "tactic-table" in item.value
                     and "<table" in item.value)
        self.assertIn("Execution</th><td>2</td>", table)
        self.assertIn("Discovery</th><td>1</td>", table)

        result = {**result, "matches": [], "additional_data_needed": ["Süreç adı"]}
        with patch("mitre_final.rag.run_rag", return_value=result):
            self.submit(QUERY)
        self.assertTrue(self.app.warning)
        self.assertIn("• Süreç adı", [item.value for item in self.app.markdown])
        self.assertNotIn("**Neden bu teknik?**", [item.value for item in self.app.markdown])

    def test_blank_and_failed_submissions_show_feedback(self):
        with patch("mitre_final.search.search") as search:
            self.submit("   ")
        search.assert_not_called()
        self.assertIn("Önce bir olay açıklaması girin.", self.app.warning[0].value)
        self.assertFalse(self.app.get("iframe"))

        with patch("mitre_final.search.search", side_effect=FileNotFoundError("indeks eksik")):
            self.submit(QUERY)
        self.assertIn("indeks eksik", self.app.warning[0].value)
        self.assertIn("Continuous Monitoring", [item.value for item in self.app.subheader])
        self.assertEqual(len(self.app.get("iframe")), 1)
        self.app.run()
        self.assertIn("Continuous Monitoring", [item.value for item in self.app.subheader])
        self.assertFalse(self.app.get("iframe"))
