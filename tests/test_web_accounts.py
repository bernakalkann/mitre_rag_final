"""Exercise persistent web accounts through the FastAPI routes."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from web.server import app


class WebAccountTests(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(TemporaryDirectory())
        self.enterContext(patch.dict("os.environ", {"MITRE_RAG_DB": str(Path(temporary) / "test.sqlite3")}))
        self.enterContext(patch("web.server.service.warm_up", return_value=False))

    def register(self, client, email):
        response = client.post("/api/auth/register", json={
            "name": "  Berna  ", "email": email, "password": "demo-only-password",
        })
        self.assertEqual(response.status_code, 201, response.text)
        return response

    def test_history_survives_restart_and_is_private(self):
        chat_url = f"/api/chats/{uuid4()}"
        snapshot = {
            "title": "Bir olay", "label": "",
            "settings": {"method": "hybrid", "k": 3},
            "result": {"export": {"query": "Olay metni"}, "attack": {"items": []},
                       "nist": {"items": []}},
            "conversation": [{"question": "Ne oldu?", "answer": {"text": "İnceleme sonucu"}}],
        }
        with TestClient(app) as owner:
            self.assertEqual(owner.get("/api/chats").status_code, 401)
            registration = self.register(owner, "Berna@example.test")
            self.assertIn("HttpOnly", registration.headers["set-cookie"])
            self.assertEqual(owner.patch("/api/profile", json={"name": "Bernanur"}).json()["name"],
                             "Bernanur")
            self.assertEqual(owner.put(chat_url, json=snapshot).json()["revision"], 1)
            self.assertEqual(owner.put(chat_url, json={**snapshot, "revision": 1}).json()["revision"], 2)
            self.assertEqual(owner.put(chat_url, json={**snapshot, "revision": 1}).status_code, 409)
            self.assertEqual(owner.delete(chat_url + "?revision=1").status_code, 409)
            self.assertEqual(owner.post("/api/auth/logout").status_code, 204)
            self.assertEqual(owner.get(chat_url).status_code, 401)

        with TestClient(app) as client:
            self.register(client, "other@example.test")
            self.assertEqual(client.get("/api/chats").json(), [])
            self.assertEqual(client.get(chat_url).status_code, 404)
            self.assertEqual(client.delete(chat_url + "?revision=2").status_code, 404)
            self.assertEqual(client.put(chat_url, json=snapshot, headers={
                "X-Workbench-Account": registration.json()["id"],
            }).status_code, 401)
            login = client.post("/api/auth/login", json={
                "email": "BERNA@example.test", "password": "demo-only-password",
            })
            self.assertEqual(login.status_code, 200)
            self.assertEqual(client.get("/api/profile").json()["name"], "Bernanur")
            self.assertEqual(client.get(chat_url).json()["conversation"], snapshot["conversation"])
            self.assertEqual(len(client.get("/api/chats").json()), 1)
            self.assertEqual(client.delete(chat_url + "?revision=2").status_code, 204)
            self.assertEqual(client.get("/api/chats").json(), [])

    def test_legacy_import_is_repeatable_without_overwriting_newer_data(self):
        chat_url = f"/api/chats/{uuid4()}"
        snapshot = {
            "title": "Eski sohbet", "settings": {"method": "semantic", "k": 3},
            "result": {"export": {"query": "Olay metni"}, "attack": {"items": []},
                       "nist": {"items": []}},
            "conversation": [],
        }
        with TestClient(app) as client:
            self.register(client, "owner@example.test")
            legacy = {**snapshot, "importedAt": 1760000000000}
            self.assertEqual(client.put(chat_url, json=legacy).json()["updatedAt"], legacy["importedAt"])
            self.assertEqual(client.put(chat_url, json={
                **snapshot, "revision": 1, "title": "Güncel sohbet",
            }).status_code, 200)
            self.assertEqual(client.put(chat_url, json=legacy).json()["revision"], 2)
            self.assertEqual(client.get(chat_url).json()["title"], "Güncel sohbet")
            self.assertEqual(client.delete(chat_url + "?revision=2", headers={
                "Origin": "https://other.example.test",
            }).status_code, 403)
