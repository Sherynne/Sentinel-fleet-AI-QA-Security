"""
Agent 3 — QA Tester (JarvisCore AutoAgent)
Executes functional HTTP tests against each endpoint discovered by the API Explorer.
Deployed as Cloud Run service: sentinel-qa
"""
import asyncio
import json
import os
import sys
import time
import httpx
from typing import Optional

from jarviscore import Mesh
from jarviscore.profiles import AutoAgent

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from agents.base import get_claude_client, call_claude, parse_json_response


QA_SYSTEM_PROMPT = """You are a senior QA engineer and API testing expert with 10+ years of experience.

You will receive an API surface map and real HTTP test results (status codes, headers, bodies).
Your job is to analyze the test results and produce a structured QA report.

For each test result, determine:
1. Whether the response matches the expected behavior
2. Classification: PASS, FAIL, WARNING, or ERROR
3. Defect severity if failed: CRITICAL, HIGH, MEDIUM, LOW
4. Specific defect description

Focus on:
- Wrong HTTP status codes (e.g., 500 instead of 400 for bad input)
- Missing or wrong validation (accepts invalid data types, missing required fields)
- Response schema violations (missing fields, wrong types)
- Performance issues (response time > 5s)
- Inconsistent behavior (same request, different responses)
- Auth bypass (getting data without credentials)

Return ONLY a valid JSON object:
{
  "summary": {
    "total_tests": 25,
    "passed": 18,
    "failed": 4,
    "warnings": 3,
    "pass_rate": 72.0
  },
  "test_results": [
    {
      "endpoint": "/users",
      "method": "GET",
      "test_type": "happy_path",
      "description": "Valid authenticated GET /users",
      "status": "PASS",
      "expected_code": 200,
      "actual_code": 200,
      "response_time_ms": 234,
      "defect": null,
      "evidence": "Returned 10 user records as expected"
    },
    {
      "endpoint": "/users",
      "method": "GET", 
      "test_type": "auth_failure",
      "description": "Request without auth token",
      "status": "FAIL",
      "expected_code": 401,
      "actual_code": 200,
      "response_time_ms": 89,
      "defect": {
        "severity": "CRITICAL",
        "title": "Authentication bypass on GET /users",
        "description": "Unauthenticated request returns 200 with user data. Authentication is not enforced."
      },
      "evidence": "Response body contained 10 user records without any auth token"
    }
  ],
  "defects": [
    {
      "id": "QA-001",
      "severity": "CRITICAL",
      "endpoint": "/users",
      "method": "GET",
      "title": "Authentication bypass",
      "description": "...",
      "steps_to_reproduce": "...",
      "expected": "401 Unauthorized",
      "actual": "200 OK with data"
    }
  ]
}"""


class QATesterAgent(AutoAgent):
    """Executes functional HTTP tests against API endpoints."""
    role = "qa_tester"
    capabilities = ["api_testing", "functional_testing", "boundary_testing", "auth_testing"]
    description = "Runs comprehensive functional tests against API endpoints, including auth, boundary, and negative test cases"
    system_prompt = QA_SYSTEM_PROMPT

    # Test payloads for common injection/boundary tests
    BOUNDARY_VALUES = {
        "string_empty": "",
        "string_very_long": "A" * 1000,
        "string_special": "'; DROP TABLE users; --",
        "string_xss": "<script>alert('xss')</script>",
        "string_template": "${7*7}",
        "integer_zero": 0,
        "integer_negative": -1,
        "integer_max": 2147483647,
        "boolean_string": "true",
        "null_value": None,
    }

    async def setup(self):
        await super().setup()
        self.llm = get_claude_client()
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            verify=False  # For testing self-signed certs
        )
        print(f"[{self.role}] QATesterAgent ready")

    async def on_peer_request(self, msg):
        """Handle incoming test requests from the Orchestrator."""
        print(f"[{self.role}] Received testing request")
        data = msg.data if hasattr(msg, 'data') else msg

        api_map = data.get("api_map", {})
        target_url = data.get("target_url", api_map.get("target_url", ""))

        try:
            results = await self._run_tests(target_url, api_map)
            return {"status": "success", "qa_results": results}
        except Exception as e:
            print(f"[{self.role}] ERROR: {e}")
            return {"status": "error", "error": str(e), "qa_results": None}

    async def _run_tests(self, target_url: str, api_map: dict) -> dict:
        """Execute HTTP tests for all endpoints in the API map."""
        endpoints = api_map.get("endpoints", [])
        raw_results = []

        print(f"[{self.role}] Running tests against {len(endpoints)} endpoints...")

        for endpoint in endpoints[:10]:  # Cap at 10 endpoints to avoid timeout
            path = endpoint.get("path", "/")
            methods = endpoint.get("methods", ["GET"])
            auth_required = endpoint.get("auth_required", False)
            full_url = f"{target_url.rstrip('/')}{path}"

            for method in methods[:3]:  # Cap at 3 methods per endpoint
                # Test 1: Happy path (no auth for simplicity)
                result = await self._make_request(
                    method=method,
                    url=full_url,
                    test_type="happy_path",
                    description=f"Valid {method} {path}"
                )
                raw_results.append(result)

                # Test 2: Missing auth (if auth required)
                if auth_required:
                    result = await self._make_request(
                        method=method,
                        url=full_url,
                        test_type="auth_failure",
                        description=f"{method} {path} without auth token",
                        headers={}  # Explicitly no auth
                    )
                    raw_results.append(result)

                # Test 3: Invalid content-type for POST/PUT
                if method in ["POST", "PUT", "PATCH"]:
                    result = await self._make_request(
                        method=method,
                        url=full_url,
                        test_type="invalid_content_type",
                        description=f"{method} {path} with wrong Content-Type",
                        headers={"Content-Type": "text/plain"},
                        body="this is plain text, not json"
                    )
                    raw_results.append(result)

                    # Test 4: Empty body on POST
                    result = await self._make_request(
                        method=method,
                        url=full_url,
                        test_type="empty_body",
                        description=f"{method} {path} with empty body",
                        headers={"Content-Type": "application/json"},
                        body=""
                    )
                    raw_results.append(result)

                    # Test 5: Injection probe in body
                    result = await self._make_request(
                        method=method,
                        url=full_url,
                        test_type="injection_probe",
                        description=f"{method} {path} with injection payload",
                        headers={"Content-Type": "application/json"},
                        body=json.dumps({"input": "'; DROP TABLE users; --", "name": "<script>alert(1)</script>"})
                    )
                    raw_results.append(result)

                # Test 6: Method not allowed (try DELETE on non-delete endpoint)
                if method == "GET":
                    result = await self._make_request(
                        method="DELETE",
                        url=full_url,
                        test_type="method_not_allowed",
                        description=f"DELETE {path} (expected: 405)"
                    )
                    raw_results.append(result)

        # Send raw results to Claude for intelligent analysis
        print(f"[{self.role}] Executed {len(raw_results)} tests, analyzing with Claude...")
        qa_report = await self._analyze_results(api_map, raw_results)
        return qa_report

    async def _make_request(self, method: str, url: str, test_type: str, description: str,
                             headers: dict = None, body: str = None) -> dict:
        """Execute a single HTTP request and capture the result."""
        default_headers = {
            "User-Agent": "SentinelFleet-QA/1.0 (Security Testing)",
            "Accept": "application/json, */*"
        }
        if headers is not None:
            default_headers.update(headers)

        start_time = time.time()
        try:
            kwargs = {"headers": default_headers}
            if body is not None:
                kwargs["content"] = body.encode() if isinstance(body, str) else body

            resp = await self.http_client.request(method=method, url=url, **kwargs)
            elapsed_ms = int((time.time() - start_time) * 1000)

            # Capture response details
            response_headers = dict(resp.headers)
            body_snippet = resp.text[:500] if resp.text else ""

            return {
                "test_type": test_type,
                "description": description,
                "url": url,
                "method": method,
                "status_code": resp.status_code,
                "response_time_ms": elapsed_ms,
                "response_headers": response_headers,
                "body_snippet": body_snippet,
                "content_type": resp.headers.get("content-type", ""),
                "error": None
            }
        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            return {
                "test_type": test_type,
                "description": description,
                "url": url,
                "method": method,
                "status_code": None,
                "response_time_ms": elapsed_ms,
                "response_headers": {},
                "body_snippet": "",
                "content_type": "",
                "error": str(e)
            }

    async def _analyze_results(self, api_map: dict, raw_results: list) -> dict:
        """Use Claude to interpret test results and generate QA report."""
        user_message = f"""Analyze these API test results and produce a comprehensive QA report.

API MAP SUMMARY:
{json.dumps({"target_url": api_map.get("target_url"), "total_endpoints": api_map.get("total_endpoints"), "auth_mechanisms": api_map.get("auth_mechanisms")}, indent=2)}

RAW TEST RESULTS ({len(raw_results)} tests):
{json.dumps(raw_results, indent=2)[:12000]}

Generate the full QA report JSON as specified. Be specific about defects and evidence."""

        raw_response = await call_claude(self.llm, QA_SYSTEM_PROMPT, user_message, max_tokens=8000)
        qa_report = parse_json_response(raw_response)
        print(f"[{self.role}] QA complete: {qa_report.get('summary', {}).get('total_tests', '?')} tests, "
              f"{len(qa_report.get('defects', []))} defects found")
        return qa_report

    async def teardown(self):
        await self.http_client.aclose()
        await super().teardown()
