"""Serve the local, build-free MITRE-RAG interface."""
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from mitre_final import rag, service
from web import accounts

STATIC = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app):
    app.state.account_store = accounts.make_store()
    await run_in_threadpool(app.state.account_store.initialize)
    app.state.warmed = await run_in_threadpool(service.warm_up)
    yield


app = FastAPI(title="MITRE-RAG", lifespan=lifespan)
app.include_router(accounts.router)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class AnalysisRequest(BaseModel):
    text: str
    mode: Literal["semantic", "bm25", "hybrid", "rag"] = "semantic"
    k: int = Field(default=service.DEFAULT_K, strict=True, ge=1, le=10)
    attack_method: Literal["semantic", "bm25", "hybrid"] = "semantic"


class ConversationTurn(BaseModel):
    question: str = Field(min_length=1, max_length=500)
    answer: str = Field(min_length=1, max_length=800)


class QuestionRequest(BaseModel):
    incident: str = Field(min_length=1, max_length=4000)
    question: str = Field(min_length=1, max_length=500)
    history: list[ConversationTurn] = Field(default_factory=list, max_length=3)
    method: Literal["semantic", "bm25", "hybrid"] = "semantic"
    k: int = Field(default=service.DEFAULT_K, strict=True, ge=1, le=10)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health(request: Request):
    return service.health(request.app.state.warmed)


@app.get("/api/examples")
def examples():
    return {"examples": service.EXAMPLES, "default_k": service.DEFAULT_K}


@app.post("/api/analyze")
def analyze(body: AnalysisRequest):
    if not body.text.strip():
        raise HTTPException(status_code=422, detail="Analiz için bir olay açıklaması yazın.")
    return service.analyze(body.text, body.mode, body.k, attack_method=body.attack_method)


@app.post("/api/ask")
def ask(body: QuestionRequest):
    if not body.incident.strip() or not body.question.strip():
        raise HTTPException(status_code=422, detail="Olay metni ve takip sorusu gerekli.")
    try:
        return service.answer_question(body.incident, body.question.strip(),
                                       [turn.model_dump() for turn in body.history], body.method, body.k)
    except rag.RagError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
