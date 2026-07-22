"""
BugBountyAgent - Report Service
=================================
This service generates professional reports from scan results.
"""

import os
import json
import html
import markdown
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path

from app.core import get_config, log_info, log_error, log_warning, get_timestamp
from app.models import Finding, Chain, Scan, Target, Profile


@dataclass
class ReportContext:
    """Context for report generation."""
    scan_id: str
    target: Target
    scan: Scan
    findings: List[Finding]
    chains: List[Chain]
    profile: Optional[Profile] = None
    format: str = 'json'  # json, html, pdf, markdown
    include_sensitive: bool = False


class ReportService:
    """
    Service for generating professional reports.
    Supports multiple formats: JSON, HTML, Markdown, PDF.
    """
    
    def __init__(self):
        self.report_dir = get_config('reports.save_dir', './data/reports')
        os.makedirs(self.report_dir, exist_ok=True)
        log_info("ReportService initialized")
    
    # ============================================================
    # Main Report Generation
    # ============================================================
    
    def generate_report(self, context: ReportContext) -> Optional[str]:
        """
        Generate a report from scan results.
        
        Args:
            context: Report context
            
        Returns:
            Optional[str]: Path to generated report
        """
        log_info(f"Generating report for scan: {context.scan_id}")
        
        # Create report directory
        report_id = f"report_{context.scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        report_path = os.path.join(self.report_dir, report_id)
        os.makedirs(report_path, exist_ok=True)
        
        # Generate based on format
        if context.format == 'json':
            return self._generate_json(context, report_path)
        elif context.format == 'html':
            return self._generate_html(context, report_path)
        elif context.format == 'markdown':
            return self._generate_markdown(context, report_path)
        elif context.format == 'pdf':
            return self._generate_pdf(context, report_path)
        else:
            log_error(f"Unsupported format: {context.format}")
            return None
    
    # ============================================================
    # JSON Report
    # ============================================================
    
    def _generate_json(self, context: ReportContext, report_path: str) -> str:
        """Generate JSON report."""
        data = self._build_report_data(context)
        
        filepath = os.path.join(report_path, 'report.json')
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        log_info(f"JSON report saved: {filepath}")
        return filepath
    
    def _build_report_data(self, context: ReportContext) -> Dict[str, Any]:
        """Build report data structure."""
        severity_counts = self._get_severity_counts(context.findings)
        chain_summary = self._get_chain_summary(context.chains)
        
        return {
            'metadata': {
                'report_id': f"report_{context.scan_id}",
                'generated_at': get_timestamp(),
                'scan_id': context.scan_id,
                'scan_type': context.scan.type if context.scan else 'unknown',
                'duration_seconds': context.scan.duration_seconds if context.scan else 0,
                'format': context.format
            },
            'target': {
                'url': context.target.url,
                'name': context.target.name or context.target.url,
                'description': context.target.description,
                'scope': context.target.scope,
                'exclude': context.target.exclude
            },
            'statistics': {
                'total_findings': len(context.findings),
                'severity_counts': severity_counts,
                'critical': severity_counts.get('critical', 0),
                'high': severity_counts.get('high', 0),
                'medium': severity_counts.get('medium', 0),
                'low': severity_counts.get('low', 0),
                'info': severity_counts.get('info', 0),
                'total_chains': len(context.chains),
                'exploitable_chains': chain_summary.get('exploitable', 0)
            },
            'findings': [self._format_finding(f) for f in context.findings],
            'chains': [self._format_chain(c) for c in context.chains],
            'profile': self._format_profile(context.profile) if context.profile else None
        }
    
    # ============================================================
    # HTML Report
    # ============================================================
    
    def _generate_html(self, context: ReportContext, report_path: str) -> str:
        """Generate HTML report."""
        data = self._build_report_data(context)
        
        html_content = self._render_html_template(data)
        
        filepath = os.path.join(report_path, 'report.html')
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        log_info(f"HTML report saved: {filepath}")
        return filepath
    
    def _render_html_template(self, data: Dict[str, Any]) -> str:
        """Render HTML template with report data."""
        # Build finding rows
        finding_rows = ''
        for f in data['findings']:
            severity_class = f['severity'].lower()
            finding_rows += f"""
            <tr class="severity-{severity_class}">
                <td><span class="severity-badge severity-{severity_class}">{f['severity']}</span></td>
                <td>{html.escape(f['type'])}</td>
                <td>{html.escape(f['title'])}</td>
                <td>{html.escape(f.get('url', 'N/A'))}</td>
                <td>{f.get('cvss_score', 'N/A')}</td>
            </tr>
            """
        
        # Build chain rows
        chain_rows = ''
        for c in data['chains']:
            chain_rows += f"""
            <tr>
                <td>{html.escape(c['name'])}</td>
                <td><span class="severity-badge severity-{c['severity'].lower()}">{c['severity']}</span></td>
                <td>{c['steps']}</td>
                <td>{'✅' if c['completed'] else '⏳'}</td>
            </tr>
            """
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugBountyAgent - Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e17;
            color: #e8edf5;
            padding: 40px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #111827;
            border-radius: 12px;
            padding: 40px;
            border: 1px solid #1e2d45;
        }}
        h1 {{ font-size: 2.5rem; color: #60a5fa; margin-bottom: 8px; }}
        h2 {{ font-size: 1.8rem; color: #94a3b8; margin-top: 30px; margin-bottom: 16px; }}
        h3 {{ font-size: 1.2rem; color: #c8d0dc; margin-top: 20px; margin-bottom: 10px; }}
        .meta {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 30px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin: 20px 0 30px 0;
        }}
        .stat-card {{
            background: #1a2332;
            padding: 16px 20px;
            border-radius: 8px;
            border: 1px solid #1e2d45;
            text-align: center;
        }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: #60a5fa; }}
        .stat-label {{ color: #94a3b8; font-size: 0.85rem; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0 24px 0;
            font-size: 0.9rem;
        }}
        th {{
            text-align: left;
            padding: 10px 12px;
            background: #1a2332;
            color: #94a3b8;
            border-bottom: 2px solid #1e2d45;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #1a2332;
            color: #c8d0dc;
        }}
        tr:hover td {{ background: #1a2332; }}
        .severity-badge {{
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; }}
        .severity-high {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; }}
        .severity-medium {{ background: rgba(250, 204, 21, 0.2); color: #facc15; }}
        .severity-low {{ background: rgba(34, 211, 238, 0.2); color: #22d3ee; }}
        .severity-info {{ background: rgba(59, 130, 246, 0.2); color: #3b82f6; }}
        .finding-detail {{
            background: #0a0e17;
            padding: 16px;
            border-radius: 8px;
            margin: 12px 0;
            border-left: 4px solid #3b82f6;
        }}
        .remediation {{
            background: rgba(34, 197, 94, 0.1);
            padding: 12px;
            border-radius: 6px;
            border-left: 4px solid #22c55e;
            margin: 8px 0;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #1e2d45;
            text-align: center;
            color: #64748b;
            font-size: 0.85rem;
        }}
        @media (max-width: 600px) {{
            body {{ padding: 16px; }}
            .container {{ padding: 20px; }}
            .stats-grid {{ grid-template-columns: 1fr 1fr; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>🐞 BugBountyAgent Report</h1>
    <p class="meta">
        Target: <strong>{html.escape(data['target']['url'])}</strong> |
        Generated: {data['metadata']['generated_at']} |
        Scan ID: {data['metadata']['scan_id']}
    </p>
    
    <h2>📊 Statistics</h2>
    <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">{data['statistics']['total_findings']}</div><div class="stat-label">Total Findings</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ef4444;">{data['statistics']['critical']}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#f59e0b;">{data['statistics']['high']}</div><div class="stat-label">High</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#facc15;">{data['statistics']['medium']}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#22d3ee;">{data['statistics']['low']}</div><div class="stat-label">Low</div></div>
        <div class="stat-card"><div class="stat-value">{data['statistics']['total_chains']}</div><div class="stat-label">Attack Chains</div></div>
    </div>
    
    <h2>🔍 Findings</h2>
    <table>
        <thead><tr><th>Severity</th><th>Type</th><th>Title</th><th>URL</th><th>CVSS</th></tr></thead>
        <tbody>
            {finding_rows}
        </tbody>
    </table>
    
    <h2>🔗 Attack Chains</h2>
    <table>
        <thead><tr><th>Name</th><th>Severity</th><th>Steps</th><th>Status</th></tr></thead>
        <tbody>
            {chain_rows}
        </tbody>
    </table>
    
    <div class="footer">
        Generated by BugBountyAgent v0.1.0 • For educational purposes only
    </div>
</div>
</body>
</html>"""
    
    # ============================================================
    # Markdown Report
    # ============================================================
    
    def _generate_markdown(self, context: ReportContext, report_path: str) -> str:
        """Generate Markdown report."""
        data = self._build_report_data(context)
        
        md = f"""# BugBountyAgent Report

**Target:** {data['target']['url']}  
**Generated:** {data['metadata']['generated_at']}  
**Scan ID:** {data['metadata']['scan_id']}  
**Duration:** {data['metadata']['duration_seconds']}s

---

## 📊 Statistics

| Metric | Value |
|--------|-------|
| Total Findings | {data['statistics']['total_findings']} |
| Critical | {data['statistics']['critical']} |
| High | {data['statistics']['high']} |
| Medium | {data['statistics']['medium']} |
| Low | {data['statistics']['low']} |
| Info | {data['statistics']['info']} |
| Attack Chains | {data['statistics']['total_chains']} |

---

## 🔍 Findings

"""
        for f in data['findings']:
            md += f"""
### {f['title']}

**Severity:** {f['severity'].upper()}  
**Type:** {f['type']}  
**URL:** {f.get('url', 'N/A')}  
**CVSS:** {f.get('cvss_score', 'N/A')}

**Description:**  
{f.get('description', 'No description')}

**Reproduction Steps:**  
{f.get('reproduction_steps', 'Not provided')}

**Remediation:**  
{f.get('remediation', 'Not provided')}

---
"""
        
        md += """
## 🔗 Attack Chains

"""
        for c in data['chains']:
            md += f"""
### {c['name']}

**Severity:** {c['severity'].upper()}  
**Status:** {'✅ Completed' if c['completed'] else '⏳ In Progress'}  
**Steps:** {c['steps']}

**Description:**  
{c.get('description', 'No description')}

---
"""
        
        md += """
---
*Generated by BugBountyAgent v0.1.0 • For educational purposes only*
"""
        
        filepath = os.path.join(report_path, 'report.md')
        with open(filepath, 'w') as f:
            f.write(md)
        
        log_info(f"Markdown report saved: {filepath}")
        return filepath
    
    # ============================================================
    # PDF Report
    # ============================================================
    
    def _generate_pdf(self, context: ReportContext, report_path: str) -> str:
        """Generate PDF report."""
        # First generate HTML, then convert to PDF
        html_path = self._generate_html(context, report_path)
        
        # Convert HTML to PDF using weasyprint or pdfkit
        try:
            from weasyprint import HTML
            pdf_path = os.path.join(report_path, 'report.pdf')
            HTML(filename=html_path).write_pdf(pdf_path)
            log_info(f"PDF report saved: {pdf_path}")
            return pdf_path
        except ImportError:
            log_warning("WeasyPrint not installed. Using fallback.")
            # Fallback: just return HTML
            return html_path
    
    # ============================================================
    # Helper Methods
    # ============================================================
    
    def _get_severity_counts(self, findings: List[Finding]) -> Dict[str, int]:
        """Get severity counts from findings."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts
    
    def _get_chain_summary(self, chains: List[Chain]) -> Dict[str, int]:
        """Get chain summary."""
        summary = {'total': len(chains), 'exploitable': 0, 'completed': 0}
        for c in chains:
            if c.is_complete():
                summary['completed'] += 1
            if c.is_exploitable():
                summary['exploitable'] += 1
        return summary
    
    def _format_finding(self, finding: Finding) -> Dict[str, Any]:
        """Format a finding for output."""
        return {
            'id': finding.id,
            'title': finding.title,
            'type': finding.type,
            'severity': finding.severity,
            'description': finding.description,
            'reproduction_steps': finding.reproduction_steps,
            'remediation': finding.remediation,
            'cvss_score': finding.cvss_score,
            'cve_id': finding.cve_id,
            'url': finding.url,
            'payload': finding.payload
        }
    
    def _format_chain(self, chain: Chain) -> Dict[str, Any]:
        """Format a chain for output."""
        return {
            'id': chain.id,
            'name': chain.name,
            'severity': chain.severity,
            'description': chain.description,
            'steps': len(chain.steps),
            'completed': chain.is_complete(),
            'exploitable': chain.is_exploitable()
        }
    
    def _format_profile(self, profile: Profile) -> Dict[str, Any]:
        """Format a profile for output."""
        return {
            'domain': profile.domain,
            'total_findings': profile.total_findings,
            'critical_findings': profile.critical_findings,
            'high_findings': profile.high_findings,
            'risk_score': profile.risk_score,
            'exposure_score': profile.exposure_score
        }
    
    # ============================================================
    # Public Methods
    # ============================================================
    
    def list_reports(self) -> List[Dict[str, Any]]:
        """List all available reports."""
        reports = []
        for item in os.listdir(self.report_dir):
            if os.path.isdir(os.path.join(self.report_dir, item)):
                reports.append({
                    'id': item,
                    'path': os.path.join(self.report_dir, item),
                    'created_at': datetime.fromtimestamp(os.path.getctime(os.path.join(self.report_dir, item))).isoformat()
                })
        return sorted(reports, key=lambda x: x['created_at'], reverse=True)