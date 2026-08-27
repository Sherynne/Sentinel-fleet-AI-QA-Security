"""
Agent 2 — API Explorer (JarvisCore AutoAgent)
Receives a target URL + optional OpenAPI spec and maps the API surface.
Deployed as Cloud Run service: sentinel-explorer
"""
import asyncio
import json
import os
import sys
import httpx
from typing import Optional

from jarviscore import Mesh
from jarviscore.profiles import AutoAgent

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from agents.base import get_claude_client, call_claude, parse_json_response


EXPLORER_SYSTEM_PROMPT = """You are an expert API security researcher and QA engineer specializing in API surface analysis.

Your job is to analyze an API (given its base URL and optionally an OpenAPI/Swagger specification) 
and produce a comprehensive map of its attack surface.

For each endpoint, identify:
1. Path, HTTP methods, and parameters (query, body, path, header)
2. Authentication requirements (Bearer, API Key, Basic, etc.)
3. Expected response codes and response schema
4. Potential test cases (both positive and negative)
5. Risk flags (e.g., endpoints that accept file uploads, admin endpoints, search endpoints susceptible to injection)

Return ONLY a valid JSON object with this exact structure:
{
  "target_url": "https://example.com",
  "spec_source": "openapi|crawled|inferred",
  "endpoints": [
    {
      "path": "/users",
      "methods": ["GET", "POST"],
      "parameters": [
        {"name": "limit", "in": "query", "type": "integer", "required": false},
        {"name": "Authorization", "in": "header", "type": "string", "required": true}
      ],
      "auth_required": true,
      "expected_codes": [200, 201, 400, 401, 403, 404],
      "risk_flags": ["paginatable", "returns_pii"],
      "test_cases": [
        {"description": "Valid GET request", "type": "happy_path", "method": "GET", "params": {}},
        {"description": "Missing auth", "type": "auth_failure", "method": "GET", "params": {}, "remove_auth": true}
      ]
    }
  ],
  "auth_mechanisms": ["Bearer JWT"],
  "base_headers": {},
  "total_endpoints": 5,
  "analysis_notes": "Brief notes about the API"
}

Be thorough. Cover all endpoints you discover. Focus on coverage and accuracy."""


class APIExplorerAgent(AutoAgent):
    """Maps the API surface from a URL or OpenAPI spec."""
    role = "api_explorer"
    capabilities = ["api_analysis", "openapi_parsing", "endpoint_discovery", "attack_surface_mapping"]
    description = "Analyzes API structure, discovers endpoints, and maps the attack surface for QA and security testing"
    system_prompt = EXPLORER_SYSTEM_PROMPT

    async def setup(self):
        await super().setup()
        self.llm = get_claude_client()
        self.http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        print(f"[{self.role}] APIExplorerAgent ready")

    async def on_peer_request(self, msg):
        """Handle incoming scan requests from the Orchestrator."""
        print(f"[{self.role}] Received exploration request")
        data = msg.data if hasattr(msg, 'data') else msg

        target_url = data.get("target_url", "")
        openapi_url = data.get("openapi_url", "")

        try:
            result = await self._explore_api(target_url, openapi_url)
            return {"status": "success", "api_map": result}
        except Exception as e:
            print(f"[{self.role}] ERROR: {e}")
            return {"status": "error", "error": str(e), "api_map": None}

    async def _explore_api(self, target_url: str, openapi_url: str = "") -> dict:
        """Main exploration logic: fetch spec or infer, then analyze with Claude."""
        spec_content = ""
        spec_source = "inferred"

        # Try to fetch OpenAPI spec
        if openapi_url:
            try:
                resp = await self.http_client.get(openapi_url)
                if resp.status_code == 200:
                    spec_content = resp.text[:15000]  # Limit to avoid token explosion
                    spec_source = "openapi"
                    print(f"[{self.role}] Fetched OpenAPI spec from {openapi_url}")
            except Exception as e:
                print(f"[{self.role}] Could not fetch OpenAPI spec: {e}")

        # Try common OpenAPI spec locations if not provided
        if not spec_content:
            for path in ["/openapi.json", "/swagger.json", "/api-docs", "/v2/swagger.json", "/docs/openapi.json"]:
                try:
                    resp = await self.http_client.get(f"{target_url.rstrip('/')}{path}")
                    if resp.status_code == 200 and "paths" in resp.text:
                        spec_content = resp.text[:15000]
                        spec_source = "openapi"
                        print(f"[{self.role}] Auto-discovered spec at {path}")
                        break
                except Exception:
                    continue

        # Probe the live target for basic info
        live_probe = ""
        try:
            resp = await self.http_client.get(target_url)
            live_probe = f"""
Live probe of {target_url}:
- Status: {resp.status_code}
- Response Headers: {dict(list(resp.headers.items())[:10])}
- Content-Type: {resp.headers.get('content-type', 'unknown')}
- Body snippet: {resp.text[:500]}
"""
        except Exception as e:
            live_probe = f"Could not probe live target: {e}"

        # Build the analysis prompt
        user_message = f"""Analyze this API and produce a complete surface map.

TARGET URL: {target_url}

{f"OPENAPI/SWAGGER SPEC:{chr(10)}{spec_content}" if spec_content else "No OpenAPI spec available — infer endpoints from the live probe and URL patterns."}

{live_probe}

Produce the full JSON surface map as specified. Include at least 3-5 test cases per major endpoint type."""

        print(f"[{self.role}] Sending to Claude for analysis...")
        raw_response = await call_claude(self.llm, EXPLORER_SYSTEM_PROMPT, user_message, max_tokens=6000)
        api_map = parse_json_response(raw_response)
        api_map["spec_source"] = spec_source
        print(f"[{self.role}] Discovered {api_map.get('total_endpoints', '?')} endpoints")
        return api_map

    async def teardown(self):
        await self.http_client.aclose()
        await super().teardown()
