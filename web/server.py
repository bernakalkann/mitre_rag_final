"""Serve the local, build-free MITRE-RAG interface."""
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from mitre_final import service

STATIC = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app):
    app.state.warmed = await run_in_threadpool(service.warm_up)
    yield


app = FastAPI(title="MITRE-RAG", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class AnalysisRequest(BaseModel):
    text: str
    mode: Literal["semantic", "rag"] = "semantic"
    k: int = Field(default=service.DEFAULT_K, strict=True, ge=1, le=10)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health(request: Request):
    return service.health(request.app.state.warmed)


@app.get("/api/examples")
def examples():
    return {"examples": service.EXAMPLES, "default_k": service.DEFAULT_K, "nist_k": service.NIST_K}


@app.post("/api/analyze")
def analyze(body: AnalysisRequest):
    if not body.text.strip():
        raise HTTPException(status_code=422, detail="Analiz için bir olay açıklaması yazın.")
    return service.analyze(body.text, body.mode, body.k)
