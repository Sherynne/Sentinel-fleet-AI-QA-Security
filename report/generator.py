"""
Report Generator — produces a premium self-contained HTML security report.
"""
import json
from datetime import datetime, timezone


def severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": "#ff4444",
        "HIGH": "#ff8800",
        "MEDIUM": "#ffcc00",
        "LOW": "#44aaff",
        "INFO": "#888888",
    }
    return colors.get(severity.upper(), "#888888")


def severity_badge(severity: str) -> str:
    color = severity_color(severity)
    return f'<span style="background:{color};color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">{severity}</span>'


def risk_gauge_angle(score: float) -> float:
    """Convert risk score 0-10 to degrees for SVG gauge (0° = safe, 180° = critical)."""
    return min(180, max(0, (score / 10.0) * 180))


def generate_html_report(scan_id: str, target_url: str, api_map: dict,
                          qa_results: dict, security_findings: dict,
                          scan_started: str) -> str:
    """Generate a rich dark-mode HTML security report."""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    risk_score = security_findings.get("risk_score", 0.0)
    risk_level = security_findings.get("risk_level", "UNKNOWN")
    executive_summary = security_findings.get("executive_summary", "No summary available.")
    findings = security_findings.get("findings", [])
    stats = security_findings.get("stats", {})
    qa_summary = qa_results.get("summary", {})
    defects = qa_results.get("defects", [])
    security_headers = security_findings.get("security_headers_audit", {})
    endpoints = api_map.get("endpoints", [])

    # Risk gauge color
    if risk_score >= 7:
        gauge_color = "#ff4444"
    elif risk_score >= 4:
        gauge_color = "#ff8800"
    else:
        gauge_color = "#44cc44"

    # Generate findings rows
    findings_rows = ""
    for f in findings:
        sev = f.get("severity", "INFO")
        findings_rows += f"""
        <tr>
            <td><code style="color:#58a6ff">{f.get('id','')}</code></td>
            <td>{severity_badge(sev)}</td>
            <td>{f.get('title', '')}</td>
            <td style="font-size:12px;color:#8b949e">{f.get('owasp_category', '')}</td>
            <td style="font-size:12px"><code>{f.get('cvss_score', 'N/A')}</code></td>
            <td style="font-size:12px;max-width:300px;word-break:break-word">{f.get('evidence', '')[:120]}...</td>
        </tr>"""

    # Generate QA defect rows
    defect_rows = ""
    for d in defects:
        sev = d.get("severity", "LOW")
        defect_rows += f"""
        <tr>
            <td><code style="color:#3fb950">{d.get('id','')}</code></td>
            <td>{severity_badge(sev)}</td>
            <td>{d.get('endpoint', '')} [{d.get('method','')}]</td>
            <td>{d.get('title', '')}</td>
            <td style="font-size:11px">{d.get('expected', '')}</td>
            <td style="font-size:11px">{d.get('actual', '')}</td>
        </tr>"""

    # Generate endpoint rows
    endpoint_rows = ""
    for ep in endpoints[:15]:
        methods = ", ".join(ep.get("methods", []))
        auth = "🔐 Auth" if ep.get("auth_required") else "🔓 Open"
        flags = ", ".join(ep.get("risk_flags", []))
        endpoint_rows += f"""
        <tr>
            <td><code style="color:#79c0ff">{ep.get('path','')}</code></td>
            <td><code style="color:#56d364">{methods}</code></td>
            <td>{auth}</td>
            <td style="font-size:11px;color:#8b949e">{flags}</td>
        </tr>"""

    # Security headers table
    header_rows = ""
    for header, data in security_headers.items():
        if not isinstance(data, dict):
            continue
        status = data.get("status", "UNKNOWN")
        status_icon = {"PASS": "✅", "FAIL": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}.get(status, "?")
        value = data.get("value") or "<em style='color:#8b949e'>Not present</em>"
        header_rows += f"""
        <tr>
            <td style="font-size:12px"><code>{header.replace('_','-')}</code></td>
            <td>{status_icon} {status}</td>
            <td style="font-size:11px;color:#8b949e">{value}</td>
        </tr>"""

    # Stats for chart
    chart_data = json.dumps({
        "critical": stats.get("critical", 0),
        "high": stats.get("high", 0),
        "medium": stats.get("medium", 0),
        "low": stats.get("low", 0),
        "info": stats.get("info", 0),
    })

    pass_rate = qa_summary.get("pass_rate", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Fleet — Security Report [{scan_id}]</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');

  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --text-muted: #8b949e;
    --blue: #58a6ff; --green: #3fb950; --orange: #d29922;
    --red: #f85149; --purple: #bc8cff;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; font-size: 14px; line-height: 1.6; }}

  .header {{
    background: linear-gradient(135deg, #0d1117 0%, #1a1f2e 50%, #0d1117 100%);
    border-bottom: 1px solid var(--border);
    padding: 40px 48px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse at 20% 50%, rgba(88,166,255,0.08) 0%, transparent 60%);
    pointer-events: none;
  }}
  .header-title {{ font-size: 28px; font-weight: 700; color: var(--text); letter-spacing: -0.5px; }}
  .header-subtitle {{ color: var(--text-muted); margin-top: 4px; font-size: 15px; }}
  .header-meta {{ margin-top: 16px; display: flex; gap: 24px; flex-wrap: wrap; }}
  .meta-item {{ font-size: 12px; color: var(--text-muted); }}
  .meta-item strong {{ color: var(--text); }}

  .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 48px; }}

  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 32px; }}
  .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; margin-bottom: 32px; }}

  .card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
    transition: border-color 0.2s;
  }}
  .card:hover {{ border-color: #444d56; }}
  .card-title {{ font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 8px; }}
  .card-value {{ font-size: 36px; font-weight: 700; }}
  .card-sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}

  .risk-card {{
    background: linear-gradient(135deg, var(--bg2), var(--bg3));
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 28px;
    text-align: center;
  }}
  .risk-score {{ font-size: 56px; font-weight: 800; color: {gauge_color}; }}
  .risk-label {{ font-size: 14px; font-weight: 600; color: {gauge_color}; margin-top: 4px; }}

  section {{ margin-bottom: 40px; }}
  .section-title {{
    font-size: 18px; font-weight: 600; color: var(--text);
    border-bottom: 1px solid var(--border);
    padding-bottom: 12px; margin-bottom: 20px;
    display: flex; align-items: center; gap: 8px;
  }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  thead tr {{ background: var(--bg3); }}
  th {{ padding: 10px 12px; text-align: left; font-weight: 600; color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1c2128; vertical-align: top; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}

  .summary-box {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 4px solid var(--blue);
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 24px;
    font-size: 14px;
    line-height: 1.7;
    color: var(--text-muted);
  }}
  .summary-box strong {{ color: var(--text); }}

  code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; }}

  .progress-bar {{
    height: 8px; background: var(--bg3); border-radius: 4px; overflow: hidden;
  }}
  .progress-fill {{
    height: 100%; background: linear-gradient(90deg, var(--green), #56d364);
    border-radius: 4px;
    transition: width 0.5s ease;
  }}

  .tag {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600; margin: 1px;
  }}

  canvas {{ max-height: 280px; }}
  .chart-container {{ position: relative; height: 280px; }}

  .footer {{
    border-top: 1px solid var(--border);
    padding: 24px 48px;
    color: var(--text-muted);
    font-size: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .powered-by {{ color: var(--text-muted); }}
  .powered-by strong {{ color: var(--blue); }}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
    <span style="font-size:28px">🛡️</span>
    <div class="header-title">Sentinel Fleet — Security Audit Report</div>
  </div>
  <div class="header-subtitle">AI-powered QA &amp; Security analysis • 4-agent fleet • JarvisCore on Google Cloud Run</div>
  <div class="header-meta">
    <div class="meta-item">🎯 <strong>Target</strong> {target_url}</div>
    <div class="meta-item">🆔 <strong>Scan ID</strong> {scan_id}</div>
    <div class="meta-item">📅 <strong>Generated</strong> {now}</div>
    <div class="meta-item">⚡ <strong>Framework</strong> JarvisCore + Claude</div>
  </div>
</div>

<div class="container">

  <!-- EXECUTIVE SUMMARY -->
  <section>
    <div class="section-title">📋 Executive Summary</div>
    <div class="summary-box">{executive_summary}</div>

    <!-- KPI Cards -->
    <div class="grid-4">
      <div class="card" style="border-top:3px solid var(--blue)">
        <div class="card-title">Endpoints Analyzed</div>
        <div class="card-value" style="color:var(--blue)">{api_map.get('total_endpoints', len(endpoints))}</div>
        <div class="card-sub">API surface mapped</div>
      </div>
      <div class="card" style="border-top:3px solid var(--green)">
        <div class="card-title">QA Tests Run</div>
        <div class="card-value" style="color:var(--green)">{qa_summary.get('total_tests', 0)}</div>
        <div class="card-sub">{qa_summary.get('passed', 0)} passed · {qa_summary.get('failed', 0)} failed</div>
      </div>
      <div class="card" style="border-top:3px solid var(--orange)">
        <div class="card-title">Security Findings</div>
        <div class="card-value" style="color:var(--orange)">{stats.get('total', len(findings))}</div>
        <div class="card-sub">{stats.get('critical',0)} critical · {stats.get('high',0)} high</div>
      </div>
      <div class="risk-card" style="border-top:3px solid {gauge_color}">
        <div class="card-title">Overall Risk Score</div>
        <div class="risk-score">{risk_score:.1f}</div>
        <div class="risk-label">{risk_level}</div>
        <div class="card-sub">out of 10.0</div>
      </div>
    </div>
  </section>

  <!-- CHARTS ROW -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">Security Findings by Severity</div>
      <div class="chart-container">
        <canvas id="severityChart"></canvas>
      </div>
    </div>
    <div class="card">
      <div class="card-title">QA Test Pass Rate</div>
      <div class="chart-container">
        <canvas id="qaChart"></canvas>
      </div>
    </div>
  </div>

  <!-- API SURFACE MAP -->
  <section>
    <div class="section-title">🗺️ API Surface Map
      <span style="font-size:13px;font-weight:400;color:var(--text-muted)">— discovered by Agent 2: API Explorer</span>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>Path</th><th>Methods</th><th>Auth</th><th>Risk Flags</th></tr></thead>
        <tbody>{endpoint_rows or '<tr><td colspan="4" style="color:var(--text-muted);text-align:center">No endpoints discovered</td></tr>'}</tbody>
      </table>
    </div>
  </section>

  <!-- QA DEFECTS -->
  <section>
    <div class="section-title">🧪 QA Defects
      <span style="font-size:13px;font-weight:400;color:var(--text-muted)">— discovered by Agent 3: QA Tester</span>
    </div>
    <div class="card" style="margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
        <span>Pass Rate: <strong style="color:var(--green)">{pass_rate:.0f}%</strong></span>
        <div class="progress-bar" style="flex:1">
          <div class="progress-fill" style="width:{min(100,pass_rate):.0f}%"></div>
        </div>
      </div>
      <div style="display:flex;gap:16px;font-size:12px;color:var(--text-muted)">
        <span>✅ {qa_summary.get('passed',0)} Passed</span>
        <span>❌ {qa_summary.get('failed',0)} Failed</span>
        <span>⚠️ {qa_summary.get('warnings',0)} Warnings</span>
        <span>📊 {qa_summary.get('total_tests',0)} Total</span>
      </div>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Endpoint</th><th>Title</th><th>Expected</th><th>Actual</th></tr></thead>
        <tbody>{defect_rows or '<tr><td colspan="6" style="color:var(--text-muted);text-align:center">✅ No QA defects found</td></tr>'}</tbody>
      </table>
    </div>
  </section>

  <!-- SECURITY FINDINGS -->
  <section>
    <div class="section-title">🔐 Security Findings (OWASP API Top 10)
      <span style="font-size:13px;font-weight:400;color:var(--text-muted)">— discovered by Agent 4: Security Analyst</span>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>OWASP Category</th><th>CVSS</th><th>Evidence</th></tr></thead>
        <tbody>{findings_rows or '<tr><td colspan="6" style="color:var(--text-muted);text-align:center">✅ No security findings</td></tr>'}</tbody>
      </table>
    </div>
  </section>

  <!-- SECURITY HEADERS AUDIT -->
  <section>
    <div class="section-title">🔧 Security Headers Audit</div>
    <div class="card">
      <table>
        <thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead>
        <tbody>{header_rows or '<tr><td colspan="3" style="color:var(--text-muted);text-align:center">No header data available</td></tr>'}</tbody>
      </table>
    </div>
  </section>

</div><!-- /container -->

<!-- FOOTER -->
<div class="footer">
  <div>Sentinel Fleet Security Report — Scan ID: {scan_id}</div>
  <div class="powered-by">Powered by <strong>JarvisCore</strong> + Claude + Google Cloud Run</div>
</div>

<script>
const severityData = {chart_data};
const ctx1 = document.getElementById('severityChart').getContext('2d');
new Chart(ctx1, {{
  type: 'doughnut',
  data: {{
    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    datasets: [{{
      data: [severityData.critical, severityData.high, severityData.medium, severityData.low, severityData.info],
      backgroundColor: ['#ff4444','#ff8800','#ffcc00','#44aaff','#666666'],
      borderColor: '#21262d',
      borderWidth: 2
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{
      legend: {{ position: 'right', labels: {{ color: '#e6edf3', font: {{ size: 12 }} }} }}
    }}
  }}
}});

const ctx2 = document.getElementById('qaChart').getContext('2d');
new Chart(ctx2, {{
  type: 'bar',
  data: {{
    labels: ['Passed', 'Failed', 'Warnings'],
    datasets: [{{
      data: [{qa_summary.get('passed',0)}, {qa_summary.get('failed',0)}, {qa_summary.get('warnings',0)}],
      backgroundColor: ['rgba(63,185,80,0.8)', 'rgba(248,81,73,0.8)', 'rgba(210,153,34,0.8)'],
      borderRadius: 6, borderSkipped: false
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
      x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ display: false }} }}
    }}
  }}
}});
</script>
</body>
</html>"""
