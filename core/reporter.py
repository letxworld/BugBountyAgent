"""
BugBountyAgent - Report Generator
==================================
Generates professional bug bounty reports in multiple formats.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .config import Config
from .filesystem import FileSystemController
from .utils import log_info, log_error, log_debug, get_timestamp


class Reporter:
    """
    Generates professional bug bounty reports.
    Supports JSON, Markdown, HTML, and PDF formats.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.filesystem = FileSystemController(config)
        self.reports_dir = config.get('system.reports_dir', './data/reports')
        
        # Ensure reports directory exists
        self.filesystem.create_directory(self.reports_dir)
        
        log_info("📄 Reporter initialized")
    
    # ============================================================
    # Main Report Generation
    # ============================================================
    
    def generate(self, target: str, findings: List[Dict], chains: List[Dict], 
                 format: str = 'json') -> str:
        """
        Generate a bug bounty report.
        
        Args:
            target: Target URL
            findings: List of findings
            chains: List of attack chains
            format: 'json', 'markdown', 'html', 'pdf'
            
        Returns:
            str: Path to the generated report
        """
        log_info(f"📄 Generating {format} report for {target}")
        
        # Build report data
        report_data = self._build_report_data(target, findings, chains)
        
        # Generate report in requested format
        if format == 'json':
            return self._generate_json(report_data)
        elif format == 'markdown':
            return self._generate_markdown(report_data)
        elif format == 'html':
            return self._generate_html(report_data)
        elif format == 'pdf':
            return self._generate_pdf(report_data)
        else:
            log_error(f"Unknown format: {format}")
            return self._generate_json(report_data)
    
    def _build_report_data(self, target: str, findings: List[Dict], 
                           chains: List[Dict]) -> Dict[str, Any]:
        """Build the report data structure."""
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get('severity', 'info').lower(), 5)
        )
        
        # Count severities
        severity_counts = self._count_severities(findings)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        return {
            'metadata': {
                'generated_at': get_timestamp(),
                'tool': 'BugBountyAgent',
                'version': '0.1.0',
                'target': target
            },
            'summary': {
                'total_findings': len(findings),
                'severity_counts': severity_counts,
                'chains': len(chains),
                'executive_summary': self._generate_executive_summary(findings, severity_counts)
            },
            'findings': sorted_findings,
            'chains': chains,
            'recommendations': recommendations,
            'timeline': self._generate_timeline(findings)
        }
    
    # ============================================================
    # JSON Report
    # ============================================================
    
    def _generate_json(self, report_data: Dict) -> str:
        """Generate JSON report."""
        filename = f"report_{report_data['metadata']['target'].replace('://', '_')}_{get_timestamp()}.json"
        path = os.path.join(self.reports_dir, filename)
        
        # Convert to JSON
        content = json.dumps(report_data, indent=2, default=str)
        self.filesystem.write_file(path, content)
        
        log_info(f"📄 JSON report saved: {path}")
        return path
    
    # ============================================================
    # Markdown Report
    # ============================================================
    
    def _generate_markdown(self, report_data: Dict) -> str:
        """Generate Markdown report."""
        filename = f"report_{report_data['metadata']['target'].replace('://', '_')}_{get_timestamp()}.md"
        path = os.path.join(self.reports_dir, filename)
        
        md = self._build_markdown_content(report_data)
        self.filesystem.write_file(path, md)
        
        log_info(f"📄 Markdown report saved: {path}")
        return path
    
    def _build_markdown_content(self, report_data: Dict) -> str:
        """Build Markdown content."""
        md = f"""# 🔍 Bug Bounty Report

**Target:** {report_data['metadata']['target']}  
**Generated:** {report_data['metadata']['generated_at']}  
**Tool:** {report_data['metadata']['tool']} v{report_data['metadata']['version']}

---

## 📊 Executive Summary

{report_data['summary']['executive_summary']}

### Statistics

| Metric | Value |
|--------|-------|
| Total Findings | {report_data['summary']['total_findings']} |
| Critical | {report_data['summary']['severity_counts'].get('critical', 0)} |
| High | {report_data['summary']['severity_counts'].get('high', 0)} |
| Medium | {report_data['summary']['severity_counts'].get('medium', 0)} |
| Low | {report_data['summary']['severity_counts'].get('low', 0)} |
| Info | {report_data['summary']['severity_counts'].get('info', 0)} |
| Attack Chains | {report_data['summary']['chains']} |

---

## 🔍 Findings

"""
        for i, finding in enumerate(report_data['findings'], 1):
            severity = finding.get('severity', 'info').upper()
            icon = self._severity_icon(finding.get('severity', 'info'))
            
            md += f"""
### {icon} Finding {i}: {finding.get('title', 'Unknown Vulnerability')}

**Severity:** {severity}  
**Type:** {finding.get('type', 'Unknown')}  
**Source:** {finding.get('source', 'Unknown')}  
**CVE:** {finding.get('cve_id', 'N/A')}  
**CVSS:** {finding.get('cvss_score', 'N/A')}

#### Description
{finding.get('description', 'No description provided')}

#### Steps to Reproduce
{finding.get('reproduction_steps', 'No reproduction steps provided')}

#### Remediation
{finding.get('remediation', 'No remediation provided')}

#### References
"""
            if 'references' in finding:
                for ref in finding['references']:
                    md += f"- {ref}\n"
            else:
                md += "- No references available\n"
            
            md += "\n---\n\n"
        
        # Attack Chains
        if report_data['chains']:
            md += f"""
## 🔗 Attack Chains

Found **{len(report_data['chains'])}** attack chains.

"""
            for chain in report_data['chains']:
                md += f"""
### {chain.get('name', 'Chain')}

**Severity:** {chain.get('severity', 'medium').upper()}  
**Steps:** {chain.get('total_steps', 0)}

"""
                for step in chain.get('steps', []):
                    md += f"- {step.get('description', 'Unknown step')}\n"
                
                md += "\n"
        
        # Recommendations
        md += f"""
## 💡 Recommendations

"""
        for i, rec in enumerate(report_data['recommendations'], 1):
            md += f"{i}. {rec}\n"
        
        # Timeline
        md += f"""
## 📅 Timeline

"""
        for entry in report_data['timeline']:
            md += f"- **{entry['time']}** — {entry['event']}\n"
        
        md += f"""
---

*Generated by BugBountyAgent v0.1.0 — AI-powered bug bounty hunting*

"""
        return md
    
    # ============================================================
    # HTML Report
    # ============================================================
    
    def _generate_html(self, report_data: Dict) -> str:
        """Generate HTML report."""
        filename = f"report_{report_data['metadata']['target'].replace('://', '_')}_{get_timestamp()}.html"
        path = os.path.join(self.reports_dir, filename)
        
        html = self._build_html_content(report_data)
        self.filesystem.write_file(path, html)
        
        log_info(f"📄 HTML report saved: {path}")
        return path
    
    def _build_html_content(self, report_data: Dict) -> str:
        """Build HTML content."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {report_data['metadata']['target']}</title>
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
        .finding {{
            background: #0a0e17;
            padding: 16px;
            border-radius: 8px;
            margin: 12px 0;
            border-left: 4px solid #3b82f6;
        }}
        .finding.critical {{ border-left-color: #ef4444; }}
        .finding.high {{ border-left-color: #f59e0b; }}
        .finding.medium {{ border-left-color: #facc15; }}
        .finding.low {{ border-left-color: #22d3ee; }}
        .finding.info {{ border-left-color: #3b82f6; }}
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
    <h1>🔍 Bug Bounty Report</h1>
    <p class="meta">
        <strong>Target:</strong> {report_data['metadata']['target']} |
        <strong>Generated:</strong> {report_data['metadata']['generated_at']} |
        <strong>Tool:</strong> {report_data['metadata']['tool']}
    </p>

    <h2>📊 Executive Summary</h2>
    <p>{report_data['summary']['executive_summary']}</p>

    <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">{report_data['summary']['total_findings']}</div><div class="stat-label">Total Findings</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ef4444;">{report_data['summary']['severity_counts'].get('critical', 0)}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#f59e0b;">{report_data['summary']['severity_counts'].get('high', 0)}</div><div class="stat-label">High</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#facc15;">{report_data['summary']['severity_counts'].get('medium', 0)}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#22d3ee;">{report_data['summary']['severity_counts'].get('low', 0)}</div><div class="stat-label">Low</div></div>
        <div class="stat-card"><div class="stat-value">{report_data['summary']['chains']}</div><div class="stat-label">Attack Chains</div></div>
    </div>

    <h2>🔍 Findings</h2>
    {''.join(self._html_findings(report_data['findings']))}

    <div class="footer">
        Generated by BugBountyAgent v0.1.0 — AI-powered bug bounty hunting
    </div>
</div>
</body>
</html>"""
    
    def _html_findings(self, findings: List[Dict]) -> List[str]:
        """Generate HTML for findings."""
        html_parts = []
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            icon = self._severity_icon(severity)
            html_parts.append(f"""
            <div class="finding {severity}">
                <h3>{icon} {finding.get('title', 'Unknown Vulnerability')}</h3>
                <p><span class="severity-badge severity-{severity}">{severity.upper()}</span></p>
                <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
                <p><strong>Remediation:</strong> {finding.get('remediation', 'Not provided')}</p>
            </div>
            """)
        return html_parts
    
    # ============================================================
    # PDF Report
    # ============================================================
    
    def _generate_pdf(self, report_data: Dict) -> str:
        """Generate PDF report."""
        # First generate HTML, then convert to PDF
        html_path = self._generate_html(report_data)
        
        # Try to convert to PDF using weasyprint
        try:
            from weasyprint import HTML
            pdf_path = html_path.replace('.html', '.pdf')
            HTML(filename=html_path).write_pdf(pdf_path)
            log_info(f"📄 PDF report saved: {pdf_path}")
            return pdf_path
        except ImportError:
            log_warning("WeasyPrint not installed. PDF generation disabled.")
            return html_path
        except Exception as e:
            log_error(f"PDF generation failed: {e}")
            return html_path
    
    # ============================================================
    # Helper Methods
    # ============================================================
    
    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            severity = f.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _severity_icon(self, severity: str) -> str:
        """Get emoji icon for severity."""
        icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }
        return icons.get(severity.lower(), '❓')
    
    def _generate_executive_summary(self, findings: List[Dict], 
                                    severity_counts: Dict[str, int]) -> str:
        """Generate executive summary."""
        total = len(findings)
        if total == 0:
            return "✅ No vulnerabilities were found during the scan. The target appears to be secure."
        
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        
        parts = []
        if critical > 0:
            parts.append(f"🔴 **{critical} critical** vulnerabilities were identified")
        if high > 0:
            parts.append(f"🟠 **{high} high** severity vulnerabilities were identified")
        if medium > 0:
            parts.append(f"🟡 **{medium} medium** severity vulnerabilities were identified")
        
        if parts:
            return f"A total of **{total}** vulnerabilities were found, including {', '.join(parts)}. Immediate attention is recommended for critical and high severity findings."
        else:
            return f"**{total}** low and informational findings were discovered. No critical or high severity vulnerabilities were found."
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        
        severity_counts = self._count_severities(findings)
        
        if severity_counts.get('critical', 0) > 0:
            recommendations.append("🔴 **Immediate Action Required**: Address critical vulnerabilities first")
        if severity_counts.get('high', 0) > 0:
            recommendations.append("🟠 **High Priority**: Fix high severity vulnerabilities as soon as possible")
        if severity_counts.get('medium', 0) > 0:
            recommendations.append("🟡 **Medium Priority**: Address medium severity issues in the next sprint")
        
        recommendations.append("✅ **Verification**: All findings should be verified before reporting")
        recommendations.append("📋 **Documentation**: Document all findings with reproduction steps")
        recommendations.append("🔒 **Responsible Disclosure**: Follow the program's disclosure guidelines")
        
        return recommendations
    
    def _generate_timeline(self, findings: List[Dict]) -> List[Dict]:
        """Generate timeline of findings."""
        timeline = []
        
        # Add scan start
        timeline.append({
            'time': get_timestamp(),
            'event': 'Scan started'
        })
        
        # Add findings
        for finding in findings:
            timeline.append({
                'time': finding.get('timestamp', get_timestamp()),
                'event': f"Found: {finding.get('title', 'Vulnerability')} ({finding.get('severity', 'info')})"
            })
        
        # Add scan end
        timeline.append({
            'time': get_timestamp(),
            'event': 'Scan completed'
        })
        
        return timeline