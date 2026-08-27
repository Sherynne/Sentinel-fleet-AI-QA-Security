"""
QA Service Entry Point — Cloud Run microservice for Agent 3.
"""
import asyncio
import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uvicorn

from jarviscore import Mesh

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from agents.qa_tester import QATesterAgent

app = FastAPI(title="Sentinel Fleet — QA Tester Agent", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

mesh = Mesh()


class QARequest(BaseModel):
    target_url: str
    api_map: Dict[str, Any]


@app.on_event("startup")
async def startup():
    mesh.add(QATesterAgent)
    await mesh.start()
    print("[qa-service] QATesterAgent ready")


@app.on_event("shutdown")
async def shutdown():
    await mesh.stop()


@app.post("/run")
async def run_tests(request: QARequest):
    """Execute QA tests against an API."""
    agent = mesh.get_agent("qa_tester")
    if not agent:
        raise HTTPException(status_code=503, detail="QATesterAgent not available")

    result = await agent._run_tests(request.target_url, request.api_map)
    return {"status": "success", "qa_results": result}


@app.get("/health")
async def health():
    return {"status": "healthy", "agent": "qa_tester", "service": "sentinel-qa"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8002))
    uvicorn.run(app, host="0.0.0.0", port=port)
