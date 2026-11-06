import json
import threading
import unittest
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from mitre_final.rag import LocalOllama, RagError, answer_schema, build_sources, run_rag, validate_answer


SOURCES = [{"source_id": "S1", "attack_id": "T1059.001", "name": "PowerShell",
            "source_url": "https://attack.mitre.org/techniques/T1059/001/",
            "excerpt": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "retrieval_score": 0.7}]


def valid_answer():
    return {"summary": "PowerShell ile betik yürütme davranışı incelenebilir.",
            "matches": [{"source_id": "S1", "explanation": "Olayda betik yürütülmesi belirtiliyor.",
                         "evidence_quote": SOURCES[0]["excerpt"]}],
            "additional_data_needed": []}


class GroundingTests(unittest.TestCase):
    def test_schema_only_offers_quotes_present_in_sources(self):
        schema = answer_schema(SOURCES)
        options = schema["properties"]["matches"]["items"]["properties"]["evidence_quote"]["enum"]
        self.assertEqual(options, [SOURCES[0]["excerpt"]])

    def test_metadata_comes_from_cited_record(self):
        answer = validate_answer(valid_answer(), SOURCES)
        self.assertEqual(answer["matches"][0]["attack_id"], "T1059.001")
        self.assertEqual(answer["matches"][0]["source_url"], SOURCES[0]["source_url"])

    def test_unknown_source_rejected(self):
        answer = valid_answer()
        answer["matches"][0]["source_id"] = "S999"
        with self.assertRaisesRegex(RagError, "kaynak kimliği"):
            validate_answer(answer, SOURCES)

    def test_invented_quote_rejected(self):
        answer = valid_answer()
        answer["matches"][0]["evidence_quote"] = "A fabricated explanation absent from ATT&CK"
        with self.assertRaisesRegex(RagError, "alıntısı"):
            validate_answer(answer, SOURCES)

    def test_quote_cannot_be_attributed_to_another_source(self):
        sources = deepcopy(SOURCES)
        sources.append({**sources[0], "source_id": "S2", "attack_id": "T1003.001",
                        "excerpt": "Adversaries access the LSASS process memory."})
        answer = valid_answer()
        answer["matches"][0]["source_id"] = "S2"
        with self.assertRaisesRegex(RagError, "alıntısı"):
            validate_answer(answer, sources)

    def test_unknown_technique_in_narrative_rejected(self):
        answer = valid_answer()
        answer["summary"] = "Also map to T9999.001."
        with self.assertRaisesRegex(RagError, "ATT&CK kodu"):
            validate_answer(answer, SOURCES)

    def test_model_cannot_supply_a_source_url(self):
        answer = valid_answer()
        answer["matches"][0]["source_url"] = "https://untrusted.example"
        with self.assertRaises(RagError):
            validate_answer(answer, SOURCES)

    def test_link_in_generated_narrative_rejected(self):
        answer = valid_answer()
        answer["summary"] = "Read https://untrusted.example for more."
        with self.assertRaisesRegex(RagError, "bağlantılar"):
            validate_answer(answer, SOURCES)

    def test_repeated_citation_rejected(self):
        answer = valid_answer()
        answer["matches"] *= 2
        sources = SOURCES + [{**SOURCES[0], "source_id": "S2", "attack_id": "T1059"}]
        with self.assertRaisesRegex(RagError, "kaynak kimliği"):
            validate_answer(answer, sources)

    def test_insufficient_context_is_an_explicit_result(self):
        answer = {"summary": "Olayı eşleştirmek için bilgi yetersiz.", "matches": [],
                  "additional_data_needed": ["Çalıştırılan betiğin davranışı"]}
        checked = validate_answer(answer, SOURCES)
        self.assertEqual(checked["matches"], [])

    def test_empty_match_without_request_for_context_rejected(self):
        answer = valid_answer()
        answer["matches"] = []
        with self.assertRaisesRegex(RagError, "ek bilgi"):
            validate_answer(answer, SOURCES)

    def test_malformed_outputs_rejected(self):
        for value in ([], {}, {**valid_answer(), "matches": "S1"},
                      {**valid_answer(), "additional_data_needed": [42]}):
            with self.subTest(value=value), self.assertRaises(RagError):
                validate_answer(value, SOURCES)


class LocalClientTests(unittest.TestCase):
    def test_remote_and_credential_endpoints_rejected(self):
        for endpoint in ("https://api.example.com", "http://127.0.0.1.evil.example:11434",
                         "http://user:secret@localhost:11434", "http://localhost:11434/api/chat"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                LocalOllama(endpoint=endpoint)

    def test_real_loopback_http_stream_and_provenance(self):
        received = []
        answer = json.dumps(valid_answer(), ensure_ascii=False)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                payload = ({"models": [{"name": "qwen3:8b", "digest": "test-only-digest"}]}
                           if self.path == "/api/tags" else {"version": "test-only-version"})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode())
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append(body)
                self.send_response(200)
                self.end_headers()
                events = [{"message": {"content": answer[:20]}, "done": False},
                          {"message": {"content": answer[20:]}, "done": True,
                           "done_reason": "stop", "eval_count": 42}]
                for event in events:
                    self.wfile.write((json.dumps(event) + "\n").encode())

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LocalOllama(endpoint=f"http://127.0.0.1:{server.server_port}", timeout=2)
            result, metadata = client.generate("Example incident", SOURCES)
            self.assertEqual(result, valid_answer())
            self.assertEqual(metadata["model_digest"], "test-only-digest")
            self.assertEqual(metadata["generated_tokens"], 42)
            payload = received[0]
            self.assertIs(payload["think"], False)
            self.assertEqual(payload["options"]["num_ctx"], 8192)
            self.assertEqual(payload["format"]["properties"]["matches"]["items"]["properties"]["source_id"]["enum"], ["S1"])
            self.assertIn("Example incident", payload["messages"][1]["content"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_missing_model_stops_before_generation(self):
        client = LocalOllama()
        with patch.object(client, "_request", return_value={"models": []}) as request:
            with self.assertRaisesRegex(RagError, "kurulu değil"):
                client.generate("incident", SOURCES)
        self.assertEqual(request.call_count, 1)

    def test_truncated_generation_rejected(self):
        # Exercise the stream parser with a real local HTTP response.
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"message":{"content":"{}"},"done":true,"done_reason":"length"}\n')
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LocalOllama(endpoint=f"http://127.0.0.1:{server.server_port}", timeout=2)
            with self.assertRaisesRegex(RagError, "token sınırında"):
                client._request("POST", "/api/chat", {}, stream=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class PipelineTests(unittest.TestCase):
    def test_retrieval_sources_are_used_in_generation(self):
        hit = {"attack_id": "T1059.001", "name": "PowerShell", "score": 0.7,
               "source_url": SOURCES[0]["source_url"], "evidence_excerpt": SOURCES[0]["excerpt"]}
        retrieval = {"results": [hit], "index_manifest": {
            "model_id": "embedding-test", "model_revision": "revision-test", "source_records_sha256": "hash-test"}}
        client = Mock()
        client.generate.return_value = (valid_answer(), {"model": "test-only"})
        with patch("mitre_final.search.search", return_value=retrieval):
            result = run_rag("incident", client=client)
        client.generate.assert_called_once_with("incident", build_sources([hit]))
        self.assertEqual(result["status"], "matched")
        self.assertFalse(result["validation"]["semantic_correctness_guaranteed"])

    def test_bad_input_does_not_call_model(self):
        client = Mock()
        with patch("mitre_final.search.search", side_effect=ValueError("empty query")):
            with self.assertRaises(ValueError):
                run_rag("", client=client)
        client.generate.assert_not_called()

    def test_candidate_count_is_bounded(self):
        for k in (0, 11):
            with self.assertRaises(ValueError):
                run_rag("incident", top_k=k)


if __name__ == "__main__":
    unittest.main()
