"""Account and saved-chat endpoints for the web workbench."""

import json
import os
from pathlib import Path
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from web.account_store import AccountStore, ChatConflict, SESSION_SECONDS

DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "private" / "workbench.sqlite3"
COOKIE = "mitre_rag_session"
router = APIRouter(prefix="/api")


def make_store():
    return AccountStore(os.environ.get("MITRE_RAG_DB", DEFAULT_DB))


def store_for(request: Request):
    return request.app.state.account_store


Store = Annotated[AccountStore, Depends(store_for)]


def require_account(request: Request, store: Store):
    account = store.session_account(request.cookies.get(COOKIE))
    expected = request.headers.get("x-workbench-account")
    if account is None or (expected and expected != account["id"]):
        raise HTTPException(401, "Oturum değişti. Sayfayı yenileyip oturumunu kontrol et.")
    return account


Account = Annotated[dict, Depends(require_account)]


def same_origin(request: Request):
    origin = request.headers.get("origin")
    if origin and (urlsplit(origin).scheme, urlsplit(origin).netloc) != (
        request.url.scheme, request.url.netloc
    ):
        raise HTTPException(403, "İstek bu uygulamanın sayfasından gelmeli.")


SameOrigin = [Depends(same_origin)]


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        return value.strip().casefold()


class Profile(BaseModel):
    name: str = Field(min_length=2, max_length=80)

    @field_validator("name", mode="before")
    @classmethod
    def strip_name(cls, value):
        return value.strip() if isinstance(value, str) else value


class Registration(Credentials, Profile):
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value):
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Geçerli bir e-posta adresi girin.")
        return value


class Settings(BaseModel):
    method: Literal["semantic", "bm25", "hybrid"]
    k: int = Field(ge=1, le=10)


class SavedTurn(BaseModel):
    question: str = Field(min_length=1, max_length=500)
    answer: dict


class ChatSnapshot(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    label: str = Field(default="", max_length=120)
    settings: Settings
    result: dict
    conversation: list[SavedTurn]
    revision: int | None = Field(default=None, ge=1)
    importedAt: int | None = Field(default=None, ge=0)

    @field_validator("result")
    @classmethod
    def valid_result(cls, result):
        export = result.get("export")
        if not isinstance(export, dict) or not isinstance(export.get("query"), str):
            raise ValueError("Olay metni gerekli.")
        for source in ("attack", "nist"):
            group = result.get(source)
            if not isinstance(group, dict) or not isinstance(group.get("items"), list):
                raise ValueError("Analiz adayları gerekli.")
        return result


def set_session(request, response, store, account):
    token = store.start_session(account["id"], request.cookies.get(COOKIE))
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, httponly=True,
                        samesite="strict", secure=request.url.scheme == "https")
    return account


@router.post("/auth/register", status_code=201, dependencies=SameOrigin)
def register(body: Registration, request: Request, response: Response, store: Store):
    account = store.register(body.email, body.name, body.password)
    if account is None:
        raise HTTPException(409, "Bu e-posta adresiyle zaten bir hesap var.")
    return set_session(request, response, store, account)


@router.post("/auth/login", dependencies=SameOrigin)
def login(body: Credentials, request: Request, response: Response, store: Store):
    account = store.authenticate(body.email, body.password)
    if account is None:
        raise HTTPException(401, "E-posta veya parola hatalı.")
    return set_session(request, response, store, account)


@router.post("/auth/logout", status_code=204, dependencies=SameOrigin)
def logout(request: Request, response: Response, store: Store, account: Account):
    store.end_session(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, httponly=True, samesite="strict",
                           secure=request.url.scheme == "https")


@router.get("/profile")
def profile(account: Account, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return account


@router.patch("/profile", dependencies=SameOrigin)
def edit_profile(body: Profile, response: Response, store: Store, account: Account):
    response.headers["Cache-Control"] = "no-store"
    return store.rename_account(account["id"], body.name)


@router.get("/chats")
def list_chats(response: Response, store: Store, account: Account):
    response.headers["Cache-Control"] = "no-store"
    return store.list_chats(account["id"])


@router.get("/chats/{chat_id}")
def load_chat(chat_id: UUID, response: Response, store: Store, account: Account):
    response.headers["Cache-Control"] = "no-store"
    chat = store.load_chat(account["id"], str(chat_id))
    if chat is None:
        raise HTTPException(404, "Sohbet bulunamadı.")
    return chat


@router.put("/chats/{chat_id}", dependencies=SameOrigin)
def save_chat(chat_id: UUID, body: ChatSnapshot, store: Store, account: Account):
    if body.importedAt is not None and body.revision is not None:
        raise HTTPException(422, "Aktarılan sohbet yeni bir kayıt olmalı.")
    data = body.model_dump(include={"label", "settings", "result", "conversation"})
    try:
        snapshot = json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except ValueError as exc:
        raise HTTPException(422, "Sohbet kaydı geçersiz.") from exc
    if len(snapshot.encode("utf-8")) > 2 * 1024 * 1024:
        raise HTTPException(413, "Sohbet kayıt sınırını aştı.")
    try:
        return store.save_chat(account["id"], str(chat_id), body.title, snapshot,
                               body.revision, body.importedAt)
    except ChatConflict as exc:
        raise HTTPException(409, "Sohbet başka bir sekmede değişti veya silindi.") from exc


@router.delete("/chats/{chat_id}", status_code=204, dependencies=SameOrigin)
def delete_chat(chat_id: UUID, revision: int, store: Store, account: Account):
    try:
        done = store.delete_chat(account["id"], str(chat_id), revision)
    except ChatConflict as exc:
        raise HTTPException(409, "Sohbet güncellendi. Sayfayı yenileyip tekrar deneyin.") from exc
    if not done:
        raise HTTPException(404, "Sohbet bulunamadı.")
