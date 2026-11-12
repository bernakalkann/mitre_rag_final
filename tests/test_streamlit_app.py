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


class StreamlitAppTests(unittest.TestCase):
    def setUp(self):
        self.app = AppTest.from_file(str(APP), default_timeout=60).run()
        self.assertFalse(self.app.exception)

    def submit(self, query):
        self.app.text_area[0].set_value(query)
        self.app.button[1].click().run()
        self.assertFalse(self.app.exception)

    def test_load_example_and_render_semantic_result(self):
        self.assertIn("İlk analizinizi başlatın", [item.value for item in self.app.subheader])
        self.app.selectbox[0].select("Kimlik bilgilerine erişim").run()
        self.app.button[0].click().run()
        query = EXAMPLES["Kimlik bilgilerine erişim"]
        self.assertEqual(self.app.text_area[0].value, query)

        hit = {**HIT, "score": -0.125, "evidence_excerpt": "Örnek kaynak metni"}
        with patch("mitre_final.search.search", return_value={"query": query, "results": [hit]}) as search:
            self.submit(query)
        self.assertEqual(search.call_args.args[1:], (query, 3))
        self.assertTrue(search.call_args.kwargs["offline"])
        self.assertIn("-0.1250", [item.value for item in self.app.metric])
        self.assertIn("T1059.001 · PowerShell", [item.value for item in self.app.subheader])
        self.assertTrue(any(">Execution</span>" in item.value for item in self.app.markdown))
        charts = self.app.get("vega_lite_chart") or self.app.get("arrow_vega_lite_chart")
        self.assertEqual(len(charts), 1)
        self.assertEqual(len(self.app.get("download_button")), 1)

    def test_rag_explains_only_supported_hits_and_handles_insufficient_context(self):
        self.app.radio[0].set_value(RAG).run()
        source = {**HIT, "retrieval_score": 0.725, "excerpt": "Örnek kaynak metni"}
        other = {**source, "attack_id": "T1059", "name": "Command Interpreter"}
        match = {**HIT, "explanation": "Örnek açıklama", "evidence_quote": source["excerpt"]}
        result = {"query": QUERY, "summary": "Örnek değerlendirme", "matches": [match],
                  "retrieved_sources": [source, other], "additional_data_needed": []}
        with patch("mitre_final.rag.run_rag", return_value=result):
            self.submit(QUERY)
        self.assertEqual([item.value for item in self.app.markdown].count("**Neden bu teknik?**"), 1)
        self.assertIn("Örnek açıklama", [item.value for item in self.app.markdown])

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

        with patch("mitre_final.search.search", side_effect=FileNotFoundError("indeks eksik")):
            self.submit(QUERY)
        self.assertIn("indeks eksik", self.app.error[0].value)
        self.assertFalse(self.app.metric)
