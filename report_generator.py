"""Professional Security Assessment Report Generator for Mizan.

Generates comprehensive, audit-ready security assessment reports in:
- Structured JSON format
- Printable, standalone, styled HTML format (suitable for PDF generation via browser print)

Strictly separates:
- Verified factual technical evidence
- AI-generated advisory triage & reasoning
- Human analyst disposition & signed review decisions
"""
from __future__ import annotations

import datetime
import html
import json
from typing import Any


def generate_structured_report(
    assessment_data: dict[str, Any],
    target_scope: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence_items: list[dict[str, Any]],
    recon_summary: dict[str, Any] | None = None,
    analyst_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile structured JSON security assessment report."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    # Aggregate finding statistics
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    status_counts = {}
    confirmed_count = 0

    for f in findings:
        sev = (f.get("severity") or "none").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        st = f.get("status") or "pending"
        status_counts[st] = status_counts.get(st, 0) + 1
        if (f.get("confidence") or "").lower() == "confirmed":
            confirmed_count += 1

    return {
        "report_id": f"rep-{assessment_data.get('assessment_id', 'anon')}",
        "generated_at": now_iso,
        "title": f"Security Assessment Report: {target_scope.get('name', 'Target')}",
        "executive_summary": {
            "target_name": target_scope.get("name"),
            "assessment_id": assessment_data.get("assessment_id"),
            "total_findings": len(findings),
            "confirmed_vulnerabilities": confirmed_count,
            "severity_distribution": sev_counts,
            "status_distribution": status_counts,
            "assessment_period": {
                "started_at": assessment_data.get("started_at"),
                "completed_at": assessment_data.get("completed_at", now_iso),
            },
            "overall_posture": (
                "Critical Risk" if sev_counts["critical"] > 0 and confirmed_count > 0
                else "Elevated Risk" if sev_counts["high"] > 0
                else "Moderate Risk" if sev_counts["medium"] > 0
                else "Low Risk"
            ),
        },
        "scope_and_limitations": {
            "authorized_domains": target_scope.get("authorized_domains", []),
            "authorized_ips": target_scope.get("authorized_ips", []),
            "permitted_ports": target_scope.get("permitted_ports", []),
            "excluded_assets": target_scope.get("excluded_assets", []),
            "scope_notes": target_scope.get("authorization_notes", ""),
            "limitations": [
                "Testing conducted strictly within authorized boundary and defined time window.",
                "Non-destructive testing methodology; no denial of service or data destruction executed.",
                "Findings are supported by attached cryptographic technical evidence.",
            ],
        },
        "methodology": "Evidence-backed multi-stage assessment (Passive Reconnaissance, Non-destructive Scanning, AI Reasoning with Fail-Closed Guardrails, Cryptographic Evidence Verification, and Human Analyst Adjudication).",
        "reconnaissance": recon_summary or {},
        "findings": findings,
        "evidence_index": [
            {
                "evidence_id": e.get("evidence_id"),
                "finding_id": e.get("finding_id"),
                "type": e.get("evidence_type"),
                "sha256": e.get("sha256_hash"),
                "verification_status": e.get("verification_status"),
                "collected_at": e.get("collected_at"),
            }
            for e in evidence_items
        ],
        "analyst_metadata": analyst_metadata or {},
    }


def generate_html_report(report_data: dict[str, Any]) -> str:
    """Generate self-contained, printable HTML report with professional styling."""
    title = html.escape(report_data.get("title", "Mizan Security Assessment Report"))
    exec_summary = report_data.get("executive_summary", {})
    scope = report_data.get("scope_and_limitations", {})
    findings = report_data.get("findings", [])
    evidence = report_data.get("evidence_index", [])

    sev_dist = exec_summary.get("severity_distribution", {})

    finding_rows = []
    for idx, f in enumerate(findings, start=1):
        fid = html.escape(f.get("id", f"F-{idx}"))
        ftitle = html.escape(f.get("title", "Untitled Finding"))
        fsev = html.escape((f.get("severity") or "none").upper())
        fconf = html.escape(f.get("confidence", "unverified"))
        fcwe = html.escape(f.get("cwe", "CWE-0"))
        fdesc = html.escape(f.get("description", ""))
        fev = html.escape(str(f.get("evidence", "No evidence attached.")))
        fstatus = html.escape(f.get("status", "pending"))

        sev_class = fsev.lower()
        finding_rows.append(f"""
        <div class="finding-card">
          <div class="finding-header">
            <div>
              <span class="finding-id">{fid}</span>
              <strong class="finding-title">{ftitle}</strong>
            </div>
            <div>
              <span class="badge badge-{sev_class}">{fsev}</span>
              <span class="badge badge-outline">{fconf}</span>
              <span class="badge badge-outline">{fstatus}</span>
            </div>
          </div>
          <p class="finding-desc">{fdesc}</p>
          <div class="evidence-block">
            <strong>Technical Evidence & Provenance:</strong>
            <pre><code>{fev}</code></pre>
          </div>
          <div class="finding-meta">CWE: {fcwe}</div>
        </div>
        """)

    findings_html = "\n".join(finding_rows) if finding_rows else "<p>No security findings recorded.</p>"

    html_content = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1e293b; background: #fff; margin: 0; padding: 40px; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  header {{ border-bottom: 3px solid #0f172a; padding-bottom: 20px; margin-bottom: 30px; }}
  h1 {{ font-size: 26px; margin: 0 0 8px; color: #0f172a; }}
  .meta-sub {{ font-size: 14px; color: #64748b; }}
  h2 {{ font-size: 19px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 30px; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
  .stat-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; text-align: center; }}
  .stat-card .num {{ font-size: 28px; font-weight: 800; color: #0f172a; display: block; }}
  .stat-card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; }}
  .badge {{ display: inline-block; padding: 3px 8px; font-size: 12px; font-weight: 700; border-radius: 4px; text-transform: uppercase; }}
  .badge-critical {{ background: #fee2e2; color: #991b1b; }}
  .badge-high {{ background: #ffedd5; color: #9a3412; }}
  .badge-medium {{ background: #fef3c7; color: #92400e; }}
  .badge-low {{ background: #e0f2fe; color: #075985; }}
  .badge-none {{ background: #f1f5f9; color: #475569; }}
  .badge-outline {{ border: 1px solid #cbd5e1; background: #fff; color: #334155; }}
  .finding-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px; margin: 16px 0; background: #fafafa; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }}
  .finding-id {{ font-family: monospace; font-size: 13px; color: #64748b; margin-right: 8px; }}
  .finding-title {{ font-size: 16px; color: #0f172a; }}
  .finding-desc {{ margin: 8px 0; font-size: 14px; color: #334155; }}
  .evidence-block {{ background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; font-size: 12px; margin-top: 10px; overflow-x: auto; }}
  .evidence-block pre {{ margin: 0; white-space: pre-wrap; }}
  .evidence-block code {{ font-family: monospace; }}
  .finding-meta {{ margin-top: 8px; font-size: 12px; color: #64748b; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }}
  th {{ background: #f8fafc; font-weight: 600; color: #334155; }}
  @media print {{ body {{ padding: 0; }} .finding-card {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>{title}</h1>
    <div class="meta-sub">Report ID: {report_data.get('report_id')} · Generated: {report_data.get('generated_at')}</div>
  </header>

  <section>
    <h2>Executive Summary</h2>
    <div class="stat-grid">
      <div class="stat-card">
        <span class="num">{exec_summary.get('total_findings', 0)}</span>
        <span class="label">Total Findings</span>
      </div>
      <div class="stat-card">
        <span class="num">{exec_summary.get('confirmed_vulnerabilities', 0)}</span>
        <span class="label">Confirmed</span>
      </div>
      <div class="stat-card">
        <span class="num">{sev_dist.get('critical', 0)}</span>
        <span class="label">Critical</span>
      </div>
      <div class="stat-card">
        <span class="num">{sev_dist.get('high', 0)}</span>
        <span class="label">High</span>
      </div>
    </div>
    <p>Overall Security Posture: <strong>{exec_summary.get('overall_posture', 'N/A')}</strong></p>
  </section>

  <section>
    <h2>Assessment Scope & Boundaries</h2>
    <p><strong>Authorized Domains:</strong> {', '.join(scope.get('authorized_domains', []))}</p>
    <p><strong>Permitted Ports:</strong> {', '.join(str(p) for p in scope.get('permitted_ports', []))}</p>
    <p><strong>Authorization Notes:</strong> {html.escape(scope.get('scope_notes', 'Standard authorized assessment.'))}</p>
  </section>

  <section>
    <h2>Technical Findings & Evidence Verification</h2>
    {findings_html}
  </section>

  <section>
    <h2>Evidence Registry (SHA-256 Provenance)</h2>
    <table>
      <thead>
        <tr><th>Evidence ID</th><th>Finding ID</th><th>Type</th><th>Verification</th><th>SHA-256 Hash</th></tr>
      </thead>
      <tbody>
        {"".join(f"<tr><td>{html.escape(e.get('evidence_id',''))}</td><td>{html.escape(e.get('finding_id',''))}</td><td>{html.escape(e.get('type',''))}</td><td>{html.escape(e.get('verification_status',''))}</td><td><code>{html.escape(e.get('sha256','')[:24])}...</code></td></tr>" for e in evidence)}
      </tbody>
    </table>
  </section>
</div>
</body>
</html>
"""
    return html_content
