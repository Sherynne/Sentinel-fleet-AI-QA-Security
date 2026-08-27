"""
Explorer Service Entry Point — Cloud Run microservice for Agent 2.
Wraps the APIExplorerAgent as a standalone HTTP service.
"""
import asyncio
import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn

from jarviscore import Mesh
from jarviscore.profiles import CustomAgent

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from agents.api_explorer import APIExplorerAgent

app = FastAPI(title="Sentinel Fleet — API Explorer Agent", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

mesh = Mesh()


class ExploreRequest(BaseModel):
    target_url: str
    openapi_url: Optional[str] = ""


@app.on_event("startup")
async def startup():
    mesh.add(APIExplorerAgent)
    await mesh.start()
    print("[explorer-service] APIExplorerAgent ready")


@app.on_event("shutdown")
async def shutdown():
    await mesh.stop()


@app.post("/run")
async def explore(request: ExploreRequest):
    """Analyze an API and return its surface map."""
    agent = mesh.get_agent("api_explorer")
    if not agent:
        raise HTTPException(status_code=503, detail="APIExplorerAgent not available")

    result = await agent._explore_api(request.target_url, request.openapi_url or "")
    return {"status": "success", "api_map": result}


@app.get("/health")
async def health():
    return {"status": "healthy", "agent": "api_explorer", "service": "sentinel-explorer"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)
