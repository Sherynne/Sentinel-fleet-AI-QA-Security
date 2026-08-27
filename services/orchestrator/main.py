"""
Sentinel Fleet — Orchestrator Service

Cloud Run architecture:
    User
      |
      v
  Orchestrator
      |
      +----HTTPS----> API Explorer
      |
      +----HTTPS----> QA Tester
      |
      +----HTTPS----> Security Analyst
      |
      v
    Report

Each agent is deployed as its own Google Cloud Run service.

Important:
Cross-agent communication uses HTTPS service URLs instead of
JarvisCore SWIM/P2P networking. This avoids relying on Docker
DNS, UDP 7946, or localhost networking between Cloud Run services.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from jarviscore import Mesh
from jarviscore.profiles import CustomAgent

# ---------------------------------------------------------------------------
# Python path
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from report.generator import generate_html_report


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

EXPLORER_URL = os.environ.get("EXPLORER_URL", "").rstrip("/")
QA_URL = os.environ.get("QA_URL", "").rstrip("/")
SECURITY_URL = os.environ.get("SECURITY_URL", "").rstrip("/")

ORCHESTRATOR_URL = os.environ.get(
    "ORCHESTRATOR_URL",
    "http://localhost:8000"
).rstrip("/")

HTTP_TIMEOUT = httpx.Timeout(
    connect=15.0,
    read=240.0,
    write=30.0,
    pool=30.0,
)


# ---------------------------------------------------------------------------
# In-memory scan store
# ---------------------------------------------------------------------------
#
# This is fine for the technical challenge/demo.
#
# Production improvement:
# Move scan state to Redis / Firestore because Cloud Run instances
# are stateless and can scale horizontally.
# ---------------------------------------------------------------------------

scans: dict = {}


# ---------------------------------------------------------------------------
# JarvisCore Mesh
# ---------------------------------------------------------------------------
#
# We keep JarvisCore in the application because it is part of the
# architecture/framework used by the challenge.
#
# The actual cross-service communication is HTTPS.
# ---------------------------------------------------------------------------

mesh = Mesh()


class OrchestratorAgent(CustomAgent):
    """
    Agent 1 — Orchestrator.

    Coordinates:
        Explorer -> QA -> Security -> Report
    """

    role = "orchestrator"

    capabilities = [
        "scan_orchestration",
        "workflow_management",
        "report_generation",
        "multi_agent_coordination",
    ]

    description = (
        "Coordinates the Sentinel Fleet API QA and security "
        "analysis pipeline."
    )

    async def call_agent(
        self,
        service_url: str,
        payload: dict,
        agent_name: str,
        timeout_seconds: float = 240.0,
    ) -> dict:
        """
        Call another Cloud Run agent over HTTPS.

        Each agent exposes POST /run.
        """

        if not service_url:
            raise RuntimeError(
                f"{agent_name} URL is not configured. "
                f"Set the corresponding environment variable."
            )

        url = f"{service_url}/run"

        print(
            f"[orchestrator] Calling {agent_name}: {url}",
            flush=True,
        )

        timeout = httpx.Timeout(
            connect=15.0,
            read=timeout_seconds,
            write=30.0,
            pool=30.0,
        )

        async with httpx.AsyncClient(timeout=timeout) as client:

            try:
                response = await client.post(
                    url,
                    json=payload,
                )

                print(
                    f"[orchestrator] {agent_name} returned "
                    f"HTTP {response.status_code}",
                    flush=True,
                )

            except httpx.TimeoutException as e:
                raise RuntimeError(
                    f"{agent_name} timed out after "
                    f"{timeout_seconds} seconds: {e}"
                ) from e

            except httpx.RequestError as e:
                raise RuntimeError(
                    f"Could not reach {agent_name} at {url}: {e}"
                ) from e

        if response.status_code >= 400:
            body = response.text[:2000]

            raise RuntimeError(
                f"{agent_name} returned HTTP "
                f"{response.status_code}: {body}"
            )

        try:
            result = response.json()
        except Exception as e:
            raise RuntimeError(
                f"{agent_name} returned invalid JSON: "
                f"{response.text[:2000]}"
            ) from e

        if not isinstance(result, dict):
            raise RuntimeError(
                f"{agent_name} returned an unexpected response."
            )

        return result

    async def run_scan(
        self,
        scan_id: str,
        target_url: str,
        openapi_url: str = "",
    ):
        """
        Execute:

            Agent 2 -> Agent 3 -> Agent 4 -> Report
        """

        scan = scans[scan_id]

        scan["status"] = "running"
        scan["started_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        try:

            # ================================================================
            # STEP 1 — API EXPLORER
            # ================================================================

            print(
                f"[orchestrator] "
                f"Scan {scan_id}: Starting API Explorer...",
                flush=True,
            )

            scan["current_agent"] = "api_explorer"
            scan["progress"] = 10

            explorer_response = await self.call_agent(
                service_url=EXPLORER_URL,
                agent_name="API Explorer",
                payload={
                    "target_url": target_url,
                    "openapi_url": openapi_url,
                },
                timeout_seconds=180,
            )

            if explorer_response.get("status") != "success":

                raise RuntimeError(
                    "API Explorer failed: "
                    f"{explorer_response.get('error', explorer_response)}"
                )

            api_map = explorer_response.get("api_map")

            if not api_map:
                raise RuntimeError(
                    "API Explorer completed but returned no api_map."
                )

            scan["api_map"] = api_map
            scan["progress"] = 35

            print(
                f"[orchestrator] Scan {scan_id}: "
                f"API Explorer complete — "
                f"{api_map.get('total_endpoints', '?')} endpoints",
                flush=True,
            )

            # ================================================================
            # STEP 2 — QA TESTER
            # ================================================================

            print(
                f"[orchestrator] "
                f"Scan {scan_id}: Starting QA Tester...",
                flush=True,
            )

            scan["current_agent"] = "qa_tester"
            scan["progress"] = 40

            qa_response = await self.call_agent(
                service_url=QA_URL,
                agent_name="QA Tester",
                payload={
                    "target_url": target_url,
                    "api_map": api_map,
                },
                timeout_seconds=240,
            )

            if qa_response.get("status") != "success":

                raise RuntimeError(
                    "QA Tester failed: "
                    f"{qa_response.get('error', qa_response)}"
                )

            qa_results = qa_response.get("qa_results")

            if not qa_results:
                raise RuntimeError(
                    "QA Tester completed but returned no qa_results."
                )

            scan["qa_results"] = qa_results
            scan["progress"] = 65

            total_tests = (
                qa_results
                .get("summary", {})
                .get("total_tests", "?")
            )

            print(
                f"[orchestrator] Scan {scan_id}: "
                f"QA Tester complete — {total_tests} tests",
                flush=True,
            )

            # ================================================================
            # STEP 3 — SECURITY ANALYST
            # ================================================================

            print(
                f"[orchestrator] "
                f"Scan {scan_id}: Starting Security Analyst...",
                flush=True,
            )

            scan["current_agent"] = "security_analyst"
            scan["progress"] = 70

            security_response = await self.call_agent(
                service_url=SECURITY_URL,
                agent_name="Security Analyst",
                payload={
                    "target_url": target_url,
                    "api_map": api_map,
                    "qa_results": qa_results,
                },
                timeout_seconds=240,
            )

            if security_response.get("status") != "success":

                raise RuntimeError(
                    "Security Analyst failed: "
                    f"{security_response.get('error', security_response)}"
                )

            security_findings = security_response.get(
                "security_findings"
            )

            if not security_findings:
                raise RuntimeError(
                    "Security Analyst completed but returned "
                    "no security_findings."
                )

            scan["security_findings"] = security_findings
            scan["progress"] = 90

            print(
                f"[orchestrator] Scan {scan_id}: "
                f"Security Analyst complete — "
                f"risk: {security_findings.get('risk_level', '?')}",
                flush=True,
            )

            # ================================================================
            # STEP 4 — REPORT
            # ================================================================

            print(
                f"[orchestrator] "
                f"Scan {scan_id}: Generating report...",
                flush=True,
            )

            scan["current_agent"] = "report_generator"

            html_report = generate_html_report(
                scan_id=scan_id,
                target_url=target_url,
                api_map=api_map,
                qa_results=qa_results,
                security_findings=security_findings,
                scan_started=scan["started_at"],
            )

            scan["html_report"] = html_report

            scan["progress"] = 100
            scan["status"] = "complete"
            scan["completed_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            scan["current_agent"] = None

            print(
                f"[orchestrator] "
                f"Scan {scan_id}: COMPLETE ✓",
                flush=True,
            )

        except Exception as e:

            print(
                f"[orchestrator] "
                f"Scan {scan_id} FAILED: {e}",
                flush=True,
            )

            scan["status"] = "failed"
            scan["error"] = str(e)
            scan["progress"] = 0
            scan["current_agent"] = None
            scan["completed_at"] = datetime.now(
                timezone.utc
            ).isoformat()


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sentinel Fleet — AI QA Security Scanner",
    description=(
        "Multi-agent API QA and security analysis "
        "powered by JarvisCore and Google Cloud Run."
    ),
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target_url: str
    openapi_url: Optional[str] = ""


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    status_url: str
    report_url: str


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup():

    print(
        "[orchestrator] Starting Sentinel Fleet...",
        flush=True,
    )

    # Add only the orchestrator to this service's local mesh.
    #
    # The other agents are separate Cloud Run services and are
    # reached using HTTPS.
    mesh.add(OrchestratorAgent)

    await mesh.start()

    print(
        "[orchestrator] JarvisCore orchestrator started.",
        flush=True,
    )

    print(
        "[orchestrator] Remote agents:",
        flush=True,
    )

    print(
        f"  Explorer: {EXPLORER_URL or 'NOT CONFIGURED'}",
        flush=True,
    )

    print(
        f"  QA:       {QA_URL or 'NOT CONFIGURED'}",
        flush=True,
    )

    print(
        f"  Security: {SECURITY_URL or 'NOT CONFIGURED'}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------

@app.on_event("shutdown")
async def shutdown():

    try:
        await mesh.stop()
    except Exception as e:
        print(
            f"[orchestrator] Mesh shutdown warning: {e}",
            flush=True,
        )

    print(
        "[orchestrator] Sentinel Fleet stopped.",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root():

    return """
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<title>Sentinel Fleet</title>

<style>

body {
    font-family: 'Segoe UI', sans-serif;
    background: #0d1117;
    color: #e6edf3;
    margin: 0;
    padding: 40px;
}

h1 {
    color: #58a6ff;
}

h2 {
    color: #3fb950;
}

pre {
    background: #161b22;
    padding: 20px;
    border-radius: 8px;
    border: 1px solid #30363d;
    overflow-x: auto;
}

.badge {
    display: inline-block;
    background: #1f6feb;
    color: white;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 12px;
    margin: 2px;
}

a {
    color: #58a6ff;
}

</style>

</head>

<body>

<h1>🛡️ Sentinel Fleet</h1>

<p>
AI-powered API QA & Security analysis
using a distributed 4-agent architecture
on Google Cloud Run.
</p>

<span class="badge">Agent 1: Orchestrator</span>
<span class="badge">Agent 2: API Explorer</span>
<span class="badge">Agent 3: QA Tester</span>
<span class="badge">Agent 4: Security Analyst</span>

<h2>Architecture</h2>

<pre>
User
  |
  v
Orchestrator
  |
  +---- HTTPS ----> API Explorer
  |
  +---- HTTPS ----> QA Tester
  |
  +---- HTTPS ----> Security Analyst
  |
  v
HTML Security Report
</pre>

<h2>Start a Scan</h2>

<pre>
POST /scan
Content-Type: application/json

{
  "target_url": "https://jsonplaceholder.typicode.com",
  "openapi_url": ""
}
</pre>

<h2>Check Status</h2>

<pre>
GET /scan/{scan_id}
</pre>

<h2>Get Report</h2>

<pre>
GET /report/{scan_id}
</pre>

<p>
📚 <a href="/docs">Swagger UI</a>
|
<a href="/health">Health Check</a>
</p>

</body>

</html>
"""


# ---------------------------------------------------------------------------
# Start scan
# ---------------------------------------------------------------------------

@app.post(
    "/scan",
    response_model=ScanResponse,
)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):

    scan_id = str(uuid.uuid4())[:8].upper()

    scans[scan_id] = {

        "scan_id": scan_id,

        "target_url": request.target_url,

        "openapi_url": request.openapi_url or "",

        "status": "queued",

        "progress": 0,

        "current_agent": None,

        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "started_at": None,

        "completed_at": None,

        "api_map": None,

        "qa_results": None,

        "security_findings": None,

        "html_report": None,

        "error": None,
    }

    orchestrator = mesh.get_agent("orchestrator")

    if not orchestrator:

        raise HTTPException(
            status_code=503,
            detail="Orchestrator agent is not available.",
        )

    # Cloud Run request returns immediately while the scan continues.
    background_tasks.add_task(
        orchestrator.run_scan,
        scan_id,
        request.target_url,
        request.openapi_url or "",
    )

    return ScanResponse(

        scan_id=scan_id,

        status="queued",

        message=(
            f"Scan started. Sentinel Fleet is analyzing "
            f"{request.target_url}"
        ),

        status_url=(
            f"{ORCHESTRATOR_URL}/scan/{scan_id}"
        ),

        report_url=(
            f"{ORCHESTRATOR_URL}/report/{scan_id}"
        ),
    )


# ---------------------------------------------------------------------------
# Scan status
# ---------------------------------------------------------------------------

@app.get("/scan/{scan_id}")
async def get_scan_status(
    scan_id: str,
):

    if scan_id not in scans:

        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found",
        )

    scan = scans[scan_id]

    api_map = scan.get("api_map")
    qa_results = scan.get("qa_results")
    security_findings = scan.get(
        "security_findings"
    )

    return {

        "scan_id": scan["scan_id"],

        "target_url": scan["target_url"],

        "status": scan["status"],

        "progress": scan["progress"],

        "current_agent": scan["current_agent"],

        "created_at": scan["created_at"],

        "started_at": scan["started_at"],

        "completed_at": scan["completed_at"],

        "error": scan.get("error"),

        "summary": {

            "endpoints_found": (
                api_map.get("total_endpoints")
                if api_map
                else None
            ),

            "tests_run": (
                qa_results
                .get("summary", {})
                .get("total_tests")
                if qa_results
                else None
            ),

            "defects_found": (
                len(
                    qa_results.get(
                        "defects",
                        []
                    )
                )
                if qa_results
                else None
            ),

            "security_findings": (
                security_findings
                .get("stats", {})
                .get("total")
                if security_findings
                else None
            ),

            "risk_level": (
                security_findings.get(
                    "risk_level"
                )
                if security_findings
                else None
            ),

            "risk_score": (
                security_findings.get(
                    "risk_score"
                )
                if security_findings
                else None
            ),
        },

        "report_url": (
            f"{ORCHESTRATOR_URL}/report/{scan_id}"
            if scan["status"] == "complete"
            else None
        ),
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@app.get(
    "/report/{scan_id}",
    response_class=HTMLResponse,
)
async def get_report(
    scan_id: str,
):

    if scan_id not in scans:

        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found",
        )

    scan = scans[scan_id]

    if scan["status"] != "complete":

        return HTMLResponse(

            content=f"""
<!DOCTYPE html>

<html>

<body
style="
background:#0d1117;
color:#e6edf3;
font-family:sans-serif;
padding:40px
">

<h2>
⏳ Scan {scan_id}
is {scan['status']}
({scan['progress']}%)
</h2>

<p>
Current agent:
{scan.get('current_agent') or 'N/A'}
</p>

<p>
Refresh this page to check progress.
</p>

<p>
<a
href="/scan/{scan_id}"
style="color:#58a6ff"
>
Check status API
</a>
</p>

<script>
setTimeout(
    () => location.reload(),
    5000
);
</script>

</body>

</html>
""",

            status_code=202,
        )

    return HTMLResponse(
        content=scan["html_report"]
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():

    orchestrator_agent = mesh.get_agent(
        "orchestrator"
    )

    configured_agents = {

        "api_explorer": bool(EXPLORER_URL),

        "qa_tester": bool(QA_URL),

        "security_analyst": bool(SECURITY_URL),
    }

    remote_count = sum(
        configured_agents.values()
    )

    local_ok = orchestrator_agent is not None

    all_ready = (
        local_ok
        and remote_count == 3
    )

    return {

        "status": (
            "healthy"
            if all_ready
            else "degraded"
        ),

        "framework": "JarvisCore",

        "version": "1.0.0",

        "architecture": (
            "Cloud Run distributed agents "
            "communicating over HTTPS"
        ),

        "agents": {

            "orchestrator": {
                "online": local_ok,
                "url": ORCHESTRATOR_URL,
            },

            "api_explorer": {
                "configured": bool(
                    EXPLORER_URL
                ),
                "url": EXPLORER_URL or None,
            },

            "qa_tester": {
                "configured": bool(
                    QA_URL
                ),
                "url": QA_URL or None,
            },

            "security_analyst": {
                "configured": bool(
                    SECURITY_URL
                ),
                "url": SECURITY_URL or None,
            },
        },

        "active_scans": len(
            [
                s
                for s in scans.values()
                if s["status"] == "running"
            ]
        ),

        "total_scans": len(scans),
    }


# ---------------------------------------------------------------------------
# Agent connectivity test
# ---------------------------------------------------------------------------

@app.get("/health/agents")
async def health_agents():

    results = {}

    agents = {

        "api_explorer": EXPLORER_URL,

        "qa_tester": QA_URL,

        "security_analyst": SECURITY_URL,
    }

    async with httpx.AsyncClient(
        timeout=15.0
    ) as client:

        for name, base_url in agents.items():

            if not base_url:

                results[name] = {
                    "status": "not_configured"
                }

                continue

            try:

                response = await client.get(
                    f"{base_url}/health"
                )

                results[name] = {

                    "status": (
                        "healthy"
                        if response.status_code == 200
                        else "unhealthy"
                    ),

                    "http_status": response.status_code,

                    "url": base_url,

                }

            except Exception as e:

                results[name] = {

                    "status": "unreachable",

                    "url": base_url,

                    "error": str(e),
                }

    return results


# ---------------------------------------------------------------------------
# List scans
# ---------------------------------------------------------------------------

@app.get("/scans")
async def list_scans():

    return {

        "scans": [

            {

                "scan_id": s["scan_id"],

                "target_url": s["target_url"],

                "status": s["status"],

                "progress": s["progress"],

                "current_agent": s[
                    "current_agent"
                ],

                "risk_level": (
                    s.get(
                        "security_findings",
                        {}
                    ).get("risk_level")
                    if s.get(
                        "security_findings"
                    )
                    else None
                ),

                "created_at": s[
                    "created_at"
                ],
            }

            for s in sorted(
                scans.values(),
                key=lambda x: x["created_at"],
                reverse=True,
            )
        ]
    }
