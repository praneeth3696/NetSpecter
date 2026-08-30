"""
NetSpecter Reporting & Audit Exporter
=====================================
Generates machine-readable JSON/JSONL artifacts and executive HTML security audit reports.
"""

from __future__ import annotations
import json
import time
from typing import Sequence
from core.models import DetectionResult, SessionStats, mask_secret


def export_json(detections: Sequence[DetectionResult], filepath: str, mask: bool = False) -> None:
    """Exports detections to a structured JSON file."""
    data = [d.to_dict(mask=mask) for d in detections]
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_jsonl(detections: Sequence[DetectionResult], filepath: str, mask: bool = False) -> None:
    """Exports detections as newline-delimited JSON for SIEM ingestion."""
    with open(filepath, "w", encoding="utf-8") as f:
        for d in detections:
            f.write(json.dumps(d.to_dict(mask=mask)) + "\n")


def generate_html_report(
    detections: Sequence[DetectionResult],
    stats: SessionStats,
    filepath: str,
    mask: bool = False
) -> None:
    """Generates an executive-grade HTML security audit report."""
    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    total_findings = len(detections)
    critical_count = sum(1 for d in detections if d.severity == "CRITICAL")
    high_count = sum(1 for d in detections if d.severity == "HIGH")
    medium_count = sum(1 for d in detections if d.severity == "MEDIUM")

    findings_rows = []
    for idx, d in enumerate(detections, 1):
        pwd = mask_secret(d.password) if mask else d.password
        user = d.username if d.username else "<span class='dim'>N/A</span>"
        sev_class = d.severity.lower()
        conf_class = d.confidence.lower()
        
        snippet = (d.raw_snippet or "").replace("<", "&lt;").replace(">", "&gt;")

        findings_rows.append(f"""
        <tr>
            <td>#{idx}</td>
            <td><span class="badge protocol-{d.protocol.lower()}">{d.protocol}</span></td>
            <td><span class="badge badge-{sev_class}">{d.severity}</span></td>
            <td><code>{d.src_ip}:{d.src_port or '–'}</code></td>
            <td><code>{d.dst_ip}:{d.dst_port or '–'}</code></td>
            <td><strong>{user}</strong></td>
            <td><code class="secret">{pwd}</code></td>
            <td><span class="badge badge-{conf_class}">{d.confidence.upper()}</span></td>
            <td><details><summary>View Payload Snippet</summary><pre>{snippet}</pre></details></td>
        </tr>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSpecter Security Audit Report</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-card: #111927;
            --bg-card-hover: #162033;
            --border: #1f2d42;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --cyan: #00f2fe;
            --blue: #4facfe;
            --red: #ff3366;
            --amber: #ffb300;
            --green: #00e676;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background-color: var(--bg-primary); color: var(--text-primary); padding: 40px 20px; line-height: 1.6; }}
        .container {{ max-width: 1280px; margin: 0 auto; }}
        
        header {{
            background: linear-gradient(135deg, #111927 0%, #1e293b 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 32px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .brand h1 {{
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(90deg, #00f2fe, #4facfe);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }}
        .brand p {{ color: var(--text-secondary); margin-top: 4px; font-size: 0.95rem; }}
        .meta-box {{ text-align: right; font-size: 0.9rem; color: var(--text-secondary); }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }}
        .card:hover {{ transform: translateY(-2px); border-color: var(--blue); }}
        .card-label {{ font-size: 0.85rem; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; }}
        .card-val {{ font-size: 2.2rem; font-weight: 700; margin-top: 8px; }}
        .card-val.red {{ color: var(--red); }}
        .card-val.amber {{ color: var(--amber); }}
        .card-val.cyan {{ color: var(--cyan); }}
        .card-val.green {{ color: var(--green); }}

        .table-section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 32px;
            overflow-x: auto;
        }}
        .section-title {{ font-size: 1.3rem; margin-bottom: 20px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; }}
        
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
        th {{ background: #0c121e; padding: 14px 16px; color: var(--text-secondary); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; }}
        td {{ padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
        tr:hover td {{ background: var(--bg-card-hover); }}
        
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(255, 51, 102, 0.2); color: var(--red); border: 1px solid var(--red); }}
        .badge-high {{ background: rgba(255, 179, 0, 0.2); color: var(--amber); border: 1px solid var(--amber); }}
        .badge-medium {{ background: rgba(79, 172, 254, 0.2); color: var(--blue); border: 1px solid var(--blue); }}
        .protocol-http {{ background: rgba(0, 242, 254, 0.15); color: var(--cyan); }}
        .protocol-ftp {{ background: rgba(255, 179, 0, 0.15); color: var(--amber); }}
        .protocol-smtp, .protocol-imap, .protocol-pop3 {{ background: rgba(168, 85, 247, 0.15); color: #c084fc; }}
        .protocol-redis {{ background: rgba(255, 51, 102, 0.15); color: var(--red); }}
        .protocol-token, .protocol-jwt {{ background: rgba(52, 211, 153, 0.15); color: #34d399; }}
        
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; }}
        code.secret {{ color: #fda4af; font-weight: 600; word-break: break-all; }}
        
        details summary {{ cursor: pointer; color: var(--cyan); outline: none; font-size: 0.8rem; }}
        pre {{ margin-top: 8px; background: #06090e; padding: 10px; border-radius: 6px; font-size: 0.78rem; overflow-x: auto; color: #a5b4fc; }}
        .dim {{ opacity: 0.5; }}
        
        .remediation {{
            background: linear-gradient(180deg, #111927 0%, #0d1420 100%);
            border: 1px solid #1e3a5f;
            border-radius: 16px;
            padding: 28px;
        }}
        .rem-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 16px; }}
        .rem-card {{ background: rgba(0,0,0,0.25); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }}
        .rem-card h4 {{ color: var(--cyan); margin-bottom: 8px; font-size: 1.05rem; }}
        .rem-card p {{ font-size: 0.88rem; color: var(--text-secondary); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>NetSpecter Security Audit</h1>
                <p>Real-Time Plaintext Transmission & Credential Leak Analysis</p>
            </div>
            <div class="meta-box">
                <div>Report Generated: <strong>{now_str}</strong></div>
                <div>Engine: <strong>NetSpecter v2.0 Modular IDS</strong></div>
                <div>Status: <strong style="color: var(--green);">Analysis Complete</strong></div>
            </div>
        </header>

        <div class="metrics-grid">
            <div class="card">
                <div class="card-label">Total Packets Inspected</div>
                <div class="card-val cyan">{stats.packets_inspected:,}</div>
            </div>
            <div class="card">
                <div class="card-label">Insecure Transmissions</div>
                <div class="card-val red">{total_findings:,}</div>
            </div>
            <div class="card">
                <div class="card-label">Critical Severity</div>
                <div class="card-val red">{critical_count}</div>
            </div>
            <div class="card">
                <div class="card-label">High Severity</div>
                <div class="card-val amber">{high_count}</div>
            </div>
        </div>

        <div class="table-section">
            <div class="section-title">
                <span>⚠️ Intercepted Plaintext Credentials & Sensitive Tokens</span>
            </div>
            {'<table><thead><tr><th>ID</th><th>Protocol</th><th>Severity</th><th>Source</th><th>Destination</th><th>User</th><th>Secret / Token</th><th>Confidence</th><th>Payload Snippet</th></tr></thead><tbody>' + "".join(findings_rows) + '</tbody></table>' if findings_rows else '<p class="dim" style="padding: 20px;">No plaintext credentials or tokens detected in the analyzed traffic.</p>'}
        </div>

        <div class="remediation">
            <div class="section-title">
                <span>🛡️ Recommended Remediation Actions</span>
            </div>
            <div class="rem-grid">
                <div class="rem-card">
                    <h4>1. Enforce TLS Everywhere</h4>
                    <p>Upgrade all legacy cleartext endpoints (HTTP, FTP, SMTP, POP3, IMAP, Redis) to TLS-encrypted equivalents (HTTPS, FTPS, SMTPS, IMAPS, TLS Redis).</p>
                </div>
                <div class="rem-card">
                    <h4>2. Configure HSTS (Strict-Transport-Security)</h4>
                    <p>Enforce HSTS with <code>max-age=31536000; includeSubDomains; preload</code> headers on web servers to prevent downgrade and SSL-stripping attacks.</p>
                </div>
                <div class="rem-card">
                    <h4>3. Secure Cookie Flags</h4>
                    <p>Mark all authentication and session cookies with <code>Secure; HttpOnly; SameSite=Strict</code> to ensure they are never transmitted over unencrypted HTTP.</p>
                </div>
                <div class="rem-card">
                    <h4>4. Invalidate Exposed Credentials</h4>
                    <p>Immediately rotate any passwords, API tokens (AWS, GitHub, Slack, Stripe), and secrets flagged in this audit report.</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
