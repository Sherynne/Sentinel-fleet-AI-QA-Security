"""
Security Service Entry Point — Cloud Run microservice for Agent 4.
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
from agents.security_analyst import SecurityAnalystAgent

app = FastAPI(title="Sentinel Fleet — Security Analyst Agent", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

mesh = Mesh()


class SecurityRequest(BaseModel):
    target_url: str
    api_map: Dict[str, Any]
    qa_results: Dict[str, Any]


@app.on_event("startup")
async def startup():
    mesh.add(SecurityAnalystAgent)
    await mesh.start()
    print("[security-service] SecurityAnalystAgent ready")


@app.on_event("shutdown")
async def shutdown():
    await mesh.stop()


@app.post("/run")
async def analyze(request: SecurityRequest):
    """Analyze API security from map + QA results."""
    agent = mesh.get_agent("security_analyst")
    if not agent:
        raise HTTPException(status_code=503, detail="SecurityAnalystAgent not available")

    result = await agent._analyze_security(
        request.target_url, request.api_map, request.qa_results
    )
    return {"status": "success", "security_findings": result}


@app.get("/health")
async def health():
    return {"status": "healthy", "agent": "security_analyst", "service": "sentinel-security"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8003))
    uvicorn.run(app, host="0.0.0.0", port=port)
