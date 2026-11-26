"""SQLite storage for local web accounts, sessions and saved conversations."""

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
from uuid import uuid4

SESSION_SECONDS = 7 * 24 * 60 * 60
DUMMY_SALT = bytes(16)


class ChatConflict(Exception):
    """The browser is working from an older copy of a conversation."""


def password_digest(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**17, r=8, p=1,
                          maxmem=256 * 1024 * 1024)


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AccountStore:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.touch(mode=0o600, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    password_digest BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    digest TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chats (
                    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    snapshot TEXT NOT NULL,
                    PRIMARY KEY (account_id, id)
                );
                CREATE INDEX IF NOT EXISTS chats_by_account_date
                    ON chats(account_id, updated_at DESC);
            """)

    def register(self, email, name, password):
        account_id = uuid4().hex
        salt = secrets.token_bytes(16)
        digest = password_digest(password, salt)
        with self.connect() as db:
            row = db.execute(
                """INSERT INTO accounts (id, email, name, salt, password_digest)
                   VALUES (?, ?, ?, ?, ?) ON CONFLICT(email) DO NOTHING
                   RETURNING id, email, name""",
                (account_id, email, name, salt, digest),
            ).fetchone()
        return dict(row) if row else None

    def authenticate(self, email, password):
        with self.connect() as db:
            row = db.execute("SELECT * FROM accounts WHERE email = ?", (email,)).fetchone()
        digest = password_digest(password, row["salt"] if row else DUMMY_SALT)
        if row and secrets.compare_digest(digest, row["password_digest"]):
            return {key: row[key] for key in ("id", "email", "name")}
        return None

    def start_session(self, account_id, previous_token=None):
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            if previous_token:
                db.execute("DELETE FROM sessions WHERE digest = ?", (token_digest(previous_token),))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?)",
                       (token_digest(token), account_id, now + SESSION_SECONDS))
        return token

    def session_account(self, token):
        if not token:
            return None
        with self.connect() as db:
            row = db.execute(
                """SELECT accounts.id, email, name FROM accounts JOIN sessions
                   ON accounts.id = sessions.account_id
                   WHERE digest = ? AND expires_at > ?""",
                (token_digest(token), int(time.time())),
            ).fetchone()
        return dict(row) if row else None

    def end_session(self, token):
        if token:
            with self.connect() as db:
                db.execute("DELETE FROM sessions WHERE digest = ?", (token_digest(token),))

    def rename_account(self, account_id, name):
        with self.connect() as db:
            row = db.execute("UPDATE accounts SET name = ? WHERE id = ? RETURNING id, email, name",
                             (name, account_id)).fetchone()
        return dict(row)

    def list_chats(self, account_id):
        with self.connect() as db:
            rows = db.execute(
                """SELECT id, title, updated_at AS updatedAt, revision FROM chats
                   WHERE account_id = ? ORDER BY updated_at DESC, id""", (account_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def load_chat(self, account_id, chat_id):
        with self.connect() as db:
            row = db.execute(
                """SELECT id, title, updated_at AS updatedAt, revision, snapshot FROM chats
                   WHERE account_id = ? AND id = ?""", (account_id, chat_id),
            ).fetchone()
        if not row:
            return None
        chat = dict(row)
        return {**json.loads(chat.pop("snapshot")), **chat}

    def save_chat(self, account_id, chat_id, title, snapshot, revision, imported_at=None):
        now = int(time.time() * 1000)
        values = (title, now if imported_at is None else min(imported_at, now), snapshot)
        with self.connect() as db:
            if revision is None:
                row = db.execute(
                    """INSERT INTO chats (title, updated_at, snapshot, account_id, id, revision)
                       VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT(account_id, id) DO NOTHING
                       RETURNING id, title, updated_at AS updatedAt, revision""",
                    (*values, account_id, chat_id),
                ).fetchone()
            else:
                row = db.execute(
                    """UPDATE chats SET title = ?, updated_at = ?, snapshot = ?, revision = revision + 1
                       WHERE account_id = ? AND id = ? AND revision = ?
                       RETURNING id, title, updated_at AS updatedAt, revision""",
                    (*values, account_id, chat_id, revision),
                ).fetchone()
            if row is None and imported_at is not None:
                row = db.execute(
                    """SELECT id, title, updated_at AS updatedAt, revision FROM chats
                       WHERE account_id = ? AND id = ?""", (account_id, chat_id),
                ).fetchone()
            if row is None:
                raise ChatConflict
        return dict(row)

    def delete_chat(self, account_id, chat_id, revision):
        with self.connect() as db:
            deleted = db.execute("DELETE FROM chats WHERE account_id = ? AND id = ? AND revision = ?",
                                 (account_id, chat_id, revision)).rowcount
            if not deleted and db.execute("SELECT 1 FROM chats WHERE account_id = ? AND id = ?",
                                          (account_id, chat_id)).fetchone():
                raise ChatConflict
        return bool(deleted)
