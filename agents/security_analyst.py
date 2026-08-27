"""
Agent 4 — Security Analyst (JarvisCore AutoAgent)
Analyzes QA test results and API map for security vulnerabilities.
Deployed as Cloud Run service: sentinel-security
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


SECURITY_SYSTEM_PROMPT = """You are a senior application security engineer and penetration tester (ethical, authorized testing only).

You will receive:
1. An API surface map (endpoints, auth mechanisms, parameters)
2. QA test results (HTTP responses, status codes, headers, body snippets)

Your job is to analyze this data for security vulnerabilities using OWASP API Security Top 10 2023 as your reference.

Analyze for:

1. **BROKEN OBJECT LEVEL AUTHORIZATION (BOLA/IDOR)**: Can a user access other users' resources?
2. **BROKEN AUTHENTICATION**: Weak tokens, missing auth, token not validated, credentials in URL
3. **BROKEN OBJECT PROPERTY LEVEL AUTH (MASS ASSIGNMENT)**: Extra fields accepted in PUT/POST
4. **UNRESTRICTED RESOURCE CONSUMPTION**: No rate limiting, missing pagination limits
5. **BROKEN FUNCTION LEVEL AUTHORIZATION**: Can regular users access admin functions?
6. **UNRESTRICTED ACCESS TO SENSITIVE BUSINESS FLOWS**: No bot protection, no CAPTCHA
7. **SERVER-SIDE REQUEST FORGERY**: URL parameters that could be manipulated
8. **SECURITY MISCONFIGURATION**: 
   - Missing security headers (X-Frame-Options, CSP, HSTS, X-Content-Type-Options, Permissions-Policy)
   - CORS misconfiguration (wildcard Allow-Origin + credentials)
   - Verbose error messages with stack traces
   - HTTP instead of HTTPS
   - Default credentials
9. **IMPROPER INVENTORY MANAGEMENT**: Deprecated endpoints, undocumented endpoints
10. **UNSAFE CONSUMPTION OF APIS**: Injection vulnerabilities (SQLi, XSS, template injection)

For each finding, assign:
- **Severity**: CRITICAL | HIGH | MEDIUM | LOW | INFO
- **CVSS Score** (approximate): 0.0 - 10.0
- **OWASP Category**: One of the above
- **Evidence**: Specific response data that confirms the finding
- **Recommendation**: Concrete fix

Return ONLY a valid JSON object:
{
  "risk_score": 7.2,
  "risk_level": "HIGH",
  "executive_summary": "2-3 sentence summary of the overall security posture",
  "findings": [
    {
      "id": "SEC-001",
      "title": "Missing HTTP Strict Transport Security Header",
      "severity": "MEDIUM",
      "cvss_score": 5.3,
      "owasp_category": "API8:2023 Security Misconfiguration",
      "affected_endpoints": ["/users", "/orders"],
      "evidence": "Response headers do not include Strict-Transport-Security",
      "recommendation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      "references": ["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"]
    }
  ],
  "security_headers_audit": {
    "x_frame_options": {"present": true, "value": "DENY", "status": "PASS"},
    "content_security_policy": {"present": false, "value": null, "status": "FAIL"},
    "strict_transport_security": {"present": true, "value": "max-age=31536000", "status": "PASS"},
    "x_content_type_options": {"present": false, "value": null, "status": "FAIL"},
    "x_xss_protection": {"present": false, "value": null, "status": "INFO"},
    "permissions_policy": {"present": false, "value": null, "status": "FAIL"},
    "cors_allow_origin": {"present": true, "value": "*", "status": "WARNING"}
  },
  "auth_analysis": {
    "mechanism": "Bearer JWT",
    "enforced": true,
    "token_validated": true,
    "issues": []
  },
  "stats": {
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 2,
    "total": 11
  }
}"""


class SecurityAnalystAgent(AutoAgent):
    """Analyzes API behavior for security vulnerabilities using OWASP Top 10."""
    role = "security_analyst"
    capabilities = ["security_analysis", "owasp", "vulnerability_assessment", "header_audit", "auth_analysis"]
    description = "Analyzes API behavior and responses for OWASP API Security Top 10 vulnerabilities"
    system_prompt = SECURITY_SYSTEM_PROMPT

    # Security headers to check
    SECURITY_HEADERS = [
        "x-frame-options",
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-xss-protection",
        "permissions-policy",
        "cache-control",
        "referrer-policy",
    ]

    async def setup(self):
        await super().setup()
        self.llm = get_claude_client()
        self.http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False)
        print(f"[{self.role}] SecurityAnalystAgent ready")

    async def on_peer_request(self, msg):
        """Handle incoming analysis requests from the Orchestrator."""
        print(f"[{self.role}] Received security analysis request")
        data = msg.data if hasattr(msg, 'data') else msg

        api_map = data.get("api_map", {})
        qa_results = data.get("qa_results", {})
        target_url = data.get("target_url", api_map.get("target_url", ""))

        try:
            findings = await self._analyze_security(target_url, api_map, qa_results)
            return {"status": "success", "security_findings": findings}
        except Exception as e:
            print(f"[{self.role}] ERROR: {e}")
            return {"status": "error", "error": str(e), "security_findings": None}

    async def _analyze_security(self, target_url: str, api_map: dict, qa_results: dict) -> dict:
        """Run security checks and analyze with Claude."""

        # Active security probes
        active_checks = await self._run_active_checks(target_url, api_map)

        # Build prompt with all evidence
        user_message = f"""Perform a comprehensive security analysis of this API.

TARGET: {target_url}

API SURFACE MAP:
{json.dumps(api_map, indent=2)[:5000]}

QA TEST RESULTS (functional tests already run):
{json.dumps(qa_results, indent=2)[:5000]}

ACTIVE SECURITY PROBES (I ran these additional security-focused checks):
{json.dumps(active_checks, indent=2)[:5000]}

Analyze ALL the evidence above and produce the complete security findings JSON.
Be specific — cite actual response data as evidence. 
Focus on real, demonstrable issues rather than hypotheticals."""

        print(f"[{self.role}] Sending evidence to Claude for security analysis...")
        raw_response = await call_claude(self.llm, SECURITY_SYSTEM_PROMPT, user_message, max_tokens=8000)
        security_report = parse_json_response(raw_response)
        print(f"[{self.role}] Security analysis complete: {security_report.get('stats', {}).get('total', '?')} findings, "
              f"risk level: {security_report.get('risk_level', '?')}")
        return security_report

    async def _run_active_checks(self, target_url: str, api_map: dict) -> list:
        """Run targeted security probes beyond the QA tests."""
        checks = []
        base_url = target_url.rstrip("/")
        endpoints = api_map.get("endpoints", [])

        # 1. Security headers check on base URL
        try:
            resp = await self.http_client.get(base_url)
            headers_check = {
                "check": "security_headers",
                "url": base_url,
                "status_code": resp.status_code,
                "headers_present": {},
                "headers_missing": []
            }
            for header in self.SECURITY_HEADERS:
                value = resp.headers.get(header)
                if value:
                    headers_check["headers_present"][header] = value
                else:
                    headers_check["headers_missing"].append(header)
            checks.append(headers_check)
        except Exception as e:
            checks.append({"check": "security_headers", "error": str(e)})

        # 2. CORS misconfiguration probe
        try:
            resp = await self.http_client.get(
                base_url,
                headers={"Origin": "https://evil-attacker.com"}
            )
            cors_value = resp.headers.get("access-control-allow-origin", "")
            cors_credentials = resp.headers.get("access-control-allow-credentials", "")
            checks.append({
                "check": "cors_probe",
                "url": base_url,
                "origin_sent": "https://evil-attacker.com",
                "access_control_allow_origin": cors_value,
                "access_control_allow_credentials": cors_credentials,
                "vulnerable": cors_value == "*" or cors_value == "https://evil-attacker.com"
            })
        except Exception as e:
            checks.append({"check": "cors_probe", "error": str(e)})

        # 3. HTTP vs HTTPS check
        if base_url.startswith("https://"):
            http_url = base_url.replace("https://", "http://", 1)
            try:
                resp = await self.http_client.get(http_url, follow_redirects=False)
                checks.append({
                    "check": "http_redirect",
                    "http_url": http_url,
                    "status_code": resp.status_code,
                    "location": resp.headers.get("location", ""),
                    "redirects_to_https": resp.status_code in [301, 302, 307, 308]
                })
            except Exception as e:
                checks.append({"check": "http_redirect", "error": str(e)})

        # 4. Verbose error probe (trigger 404/500)
        for path in ["/this-does-not-exist-xyz-123", "/../../../etc/passwd", "/api/v1/nonexistent"]:
            try:
                resp = await self.http_client.get(f"{base_url}{path}")
                body = resp.text[:500]
                checks.append({
                    "check": "error_verbosity",
                    "url": f"{base_url}{path}",
                    "status_code": resp.status_code,
                    "body_snippet": body,
                    "leaks_stack_trace": any(kw in body.lower() for kw in ["traceback", "stack trace", "exception at", "line "]),
                    "leaks_version": any(kw in body.lower() for kw in ["nginx/", "apache/", "express/", "django", "flask/", "laravel/"]),
                    "leaks_path": any(kw in body for kw in ["/var/", "/home/", "C:\\", "/usr/"])
                })
                break  # Only need one error probe
            except Exception:
                continue

        # 5. Rate limiting probe (5 rapid requests)
        try:
            probe_url = f"{base_url}/"
            if endpoints:
                probe_url = f"{base_url}{endpoints[0].get('path', '/')}"
            
            responses = []
            for _ in range(5):
                r = await self.http_client.get(probe_url)
                responses.append(r.status_code)
            
            rate_limited = 429 in responses
            checks.append({
                "check": "rate_limiting",
                "url": probe_url,
                "rapid_requests": 5,
                "status_codes": responses,
                "rate_limited": rate_limited,
                "rate_limit_header": responses[0] if responses else None
            })
        except Exception as e:
            checks.append({"check": "rate_limiting", "error": str(e)})

        # 6. Authentication bypass probe (if endpoints have auth)
        auth_endpoints = [e for e in endpoints if e.get("auth_required")]
        for endpoint in auth_endpoints[:2]:
            url = f"{base_url}{endpoint.get('path', '/')}"
            for method in endpoint.get("methods", ["GET"])[:1]:
                try:
                    # Request with no auth
                    resp = await self.http_client.request(method, url, headers={})
                    checks.append({
                        "check": "auth_bypass_probe",
                        "url": url,
                        "method": method,
                        "no_auth_status": resp.status_code,
                        "potential_bypass": resp.status_code == 200,
                        "body_snippet": resp.text[:200]
                    })
                except Exception as e:
                    checks.append({"check": "auth_bypass_probe", "error": str(e)})

        return checks

    async def teardown(self):
        await self.http_client.aclose()
        await super().teardown()
