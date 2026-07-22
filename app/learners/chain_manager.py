"""
BugBountyAgent - Chain Manager
================================
This module handles attack chain building, correlation, and learning.
It connects findings together to form complete attack paths.
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict, field

from app.core import get_config, log_info, log_warning, log_error, log_debug, get_timestamp, generate_id
from app.knowledge import KnowledgeBase, Finding, AttackChain

# ============================================================
# Chain Templates
# ============================================================

CHAIN_TEMPLATES = {
    "subdomain_to_rce": {
        "name": "Subdomain → Open Port → Service → RCE",
        "steps": [
            "subdomain_discovery",
            "port_scan",
            "service_detection",
            "vulnerability_scan",
            "exploitation"
        ],
        "severity": "critical",
        "description": "Complete chain from subdomain discovery to remote code execution"
    },
    "api_chain": {
        "name": "API → IDOR → Privilege Escalation",
        "steps": [
            "api_discovery",
            "parameter_fuzzing",
            "idor_detection",
            "privilege_escalation"
        ],
        "severity": "high",
        "description": "API chain leading to privilege escalation"
    },
    "auth_chain": {
        "name": "Auth → Session → Account Takeover",
        "steps": [
            "auth_testing",
            "session_analysis",
            "token_prediction",
            "account_takeover"
        ],
        "severity": "critical",
        "description": "Authentication chain leading to account takeover"
    },
    "xss_chain": {
        "name": "XSS → Session Hijacking → Data Theft",
        "steps": [
            "xss_detection",
            "payload_delivery",
            "cookie_exfiltration",
            "session_hijacking"
        ],
        "severity": "high",
        "description": "Cross-site scripting chain to session hijacking"
    },
    "file_upload_chain": {
        "name": "File Upload → RCE → Shell Access",
        "steps": [
            "file_upload_detection",
            "extension_bypass",
            "webshell_upload",
            "remote_execution"
        ],
        "severity": "critical",
        "description": "File upload chain to remote code execution"
    }
}

# ============================================================
# Chain Manager Class
# ============================================================

class ChainManager:
    """
    Manages attack chain building, correlation, and learning.
    Connects findings to form complete attack paths.
    """
    
    def __init__(self):
        self.kb = KnowledgeBase()
        self.chains_dir = get_config('chain_hunting.chains_dir', './data/chains')
        os.makedirs(self.chains_dir, exist_ok=True)
        
        self.templates = CHAIN_TEMPLATES
        self.chains_cache = {}
        
        log_info("Chain Manager initialized")
    
    # ============================================================
    # Chain Building
    # ============================================================
    
    def build_chains(self, target: str) -> List[AttackChain]:
        """
        Build attack chains for a target by correlating findings.
        """
        log_info(f"Building chains for target: {target}")
        
        findings = self.kb.get_findings_by_target(target)
        if not findings:
            log_warning(f"No findings found for target: {target}")
            return []
        
        chains = []
        
        # Try each template
        for template_id, template in self.templates.items():
            chain = self._build_chain_from_template(target, findings, template)
            if chain:
                chains.append(chain)
                self.kb.save_chain(chain)
                log_info(f"Built chain: {chain.name} ({chain.severity})")
        
        # Find custom chains (patterns not in templates)
        custom_chains = self._find_custom_chains(target, findings)
        for chain in custom_chains:
            self.kb.save_chain(chain)
            log_info(f"Found custom chain: {chain.name} ({chain.severity})")
            chains.append(chain)
        
        return chains
    
    def _build_chain_from_template(self, target: str, findings: List[Finding], template: Dict) -> Optional[AttackChain]:
        """Build a chain from a template using available findings."""
        steps = []
        chain_findings = []
        
        for step_type in template['steps']:
            # Find matching findings
            matching = self._find_findings_by_type(findings, step_type)
            if matching:
                # Take the first match
                finding = matching[0]
                chain_findings.append(finding.id)
                steps.append({
                    'step': step_type,
                    'finding_id': finding.id,
                    'description': finding.description,
                    'severity': finding.severity
                })
            else:
                # Missing a step - chain is incomplete
                log_debug(f"Missing step for chain template: {step_type}")
                return None
        
        # All steps found - complete chain!
        chain = AttackChain(
            id=generate_id(),
            name=template['name'],
            target=target,
            steps=steps,
            findings=chain_findings,
            severity=template['severity'],
            description=template['description'],
            completed=True,
            timestamp=get_timestamp(),
            success_count=0,
            failure_count=0
        )
        
        return chain
    
    def _find_findings_by_type(self, findings: List[Finding], finding_type: str) -> List[Finding]:
        """Find findings by type (contains substring match)."""
        matches = []
        for f in findings:
            # Check if type contains the step type
            if finding_type.lower() in f.type.lower() or f.type.lower() in finding_type.lower():
                matches.append(f)
        return matches
    
    def _find_custom_chains(self, target: str, findings: List[Finding]) -> List[AttackChain]:
        """Find custom chains not matching templates."""
        chains = []
        
        # Group findings by category
        grouped = {}
        for f in findings:
            category = self._categorize_finding(f)
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(f)
        
        # Build chains from categories
        for category, category_findings in grouped.items():
            if len(category_findings) >= 2:
                chain = self._build_custom_chain(target, category, category_findings)
                if chain:
                    chains.append(chain)
        
        return chains
    
    def _categorize_finding(self, finding: Finding) -> str:
        """Categorize a finding for chain building."""
        categories = {
            'subdomain': ['subdomain', 'dns', 'domain'],
            'port': ['port', 'service', 'nmap'],
            'vuln': ['injection', 'xss', 'csrf', 'idor', 'ssrf', 'xxe'],
            'auth': ['auth', 'login', 'session', 'token', 'jwt'],
            'api': ['api', 'graphql', 'rest', 'endpoint'],
            'file': ['upload', 'download', 'file'],
            'config': ['misconfig', 'cors', 'header', 'ssl']
        }
        
        finding_lower = finding.type.lower()
        for cat, keywords in categories.items():
            for keyword in keywords:
                if keyword in finding_lower:
                    return cat
        
        return 'unknown'
    
    def _build_custom_chain(self, target: str, category: str, findings: List[Finding]) -> Optional[AttackChain]:
        """Build a custom chain from a category of findings."""
        steps = []
        chain_findings = []
        
        for f in findings:
            chain_findings.append(f.id)
            steps.append({
                'step': f.type,
                'finding_id': f.id,
                'description': f.description,
                'severity': f.severity
            })
        
        # Determine severity (highest in chain)
        severities = [f.severity for f in findings]
        severity_order = ['info', 'low', 'medium', 'high', 'critical']
        max_severity = max(severities, key=lambda x: severity_order.index(x))
        
        chain = AttackChain(
            id=generate_id(),
            name=f"Custom {category} Chain",
            target=target,
            steps=steps,
            findings=chain_findings,
            severity=max_severity,
            description=f"Chain of {len(findings)} {category}-related findings",
            completed=True,
            timestamp=get_timestamp(),
            success_count=0,
            failure_count=0
        )
        
        return chain
    
    # ============================================================
    # Chain Correlation
    # ============================================================
    
    def correlate_chains(self, target: str) -> List[AttackChain]:
        """
        Correlate chains to find higher-level attack patterns.
        """
        log_info(f"Correlating chains for target: {target}")
        
        chains = self.kb.get_chains_by_target(target)
        if len(chains) < 2:
            return chains
        
        # Find chains that can be merged
        correlated = []
        used = set()
        
        for i, chain1 in enumerate(chains):
            if i in used:
                continue
            
            merged_chain = chain1
            for j, chain2 in enumerate(chains):
                if i != j and j not in used:
                    if self._chains_are_related(chain1, chain2):
                        # Merge chains
                        merged_chain = self._merge_chains(merged_chain, chain2)
                        used.add(j)
            
            correlated.append(merged_chain)
            used.add(i)
        
        return correlated
    
    def _chains_are_related(self, chain1: AttackChain, chain2: AttackChain) -> bool:
        """Check if two chains are related."""
        # Check if they share findings
        shared = set(chain1.findings) & set(chain2.findings)
        if shared:
            return True
        
        # Check if they have related steps
        steps1 = set([s['step'] for s in chain1.steps])
        steps2 = set([s['step'] for s in chain2.steps])
        if steps1 & steps2:
            return True
        
        return False
    
    def _merge_chains(self, chain1: AttackChain, chain2: AttackChain) -> AttackChain:
        """Merge two chains into one."""
        # Combine steps (remove duplicates)
        combined_steps = []
        seen_steps = set()
        
        for s in chain1.steps + chain2.steps:
            key = f"{s['step']}_{s['finding_id']}"
            if key not in seen_steps:
                combined_steps.append(s)
                seen_steps.add(key)
        
        # Combine findings
        combined_findings = list(set(chain1.findings + chain2.findings))
        
        # Highest severity
        severity_order = ['info', 'low', 'medium', 'high', 'critical']
        severities = [chain1.severity, chain2.severity]
        max_severity = max(severities, key=lambda x: severity_order.index(x))
        
        return AttackChain(
            id=generate_id(),
            name=f"Correlated: {chain1.name} + {chain2.name}",
            target=chain1.target,
            steps=combined_steps,
            findings=combined_findings,
            severity=max_severity,
            description=f"Merged chain with {len(combined_findings)} findings",
            completed=True,
            timestamp=get_timestamp(),
            success_count=0,
            failure_count=0
        )
    
    # ============================================================
    # Chain Learning
    # ============================================================
    
    def learn_from_chain(self, chain: AttackChain, success: bool):
        """
        Learn from a chain's success or failure.
        """
        log_info(f"Learning from chain: {chain.name} (success: {success})")
        
        # Update chain stats
        if success:
            chain.success_count += 1
        else:
            chain.failure_count += 1
        
        self.kb.save_chain(chain)
        
        # Update patterns if successful
        if success and chain.success_count > 3:
            self._learn_pattern_from_chain(chain)
    
    def _learn_pattern_from_chain(self, chain: AttackChain):
        """
        Learn a pattern from a successful chain.
        """
        from app.knowledge import Pattern
        
        # Create pattern from chain
        pattern_id = generate_id()
        pattern = Pattern(
            id=pattern_id,
            name=f"Pattern: {chain.name}",
            category=chain.severity,
            detection_method="chain_pattern",
            indicators=[s['step'] for s in chain.steps],
            payloads=[],
            confidence=min(1.0, 0.5 + (chain.success_count * 0.1)),
            occurrences=chain.success_count,
            first_seen=chain.timestamp,
            last_seen=get_timestamp(),
            related_cves=[]
        )
        
        self.kb.save_pattern(pattern)
        log_info(f"Learned new pattern: {pattern.name} (confidence: {pattern.confidence})")
    
    # ============================================================
    # Chain Search & Retrieval
    # ============================================================
    
    def find_best_chains(self, target: str) -> List[AttackChain]:
        """
        Find the best (most complete) chains for a target.
        """
        chains = self.kb.get_chains_by_target(target)
        
        # Sort by success rate and severity
        def chain_score(chain):
            total = chain.success_count + chain.failure_count
            if total == 0:
                return 0
            success_rate = chain.success_count / total
            severity_score = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}[chain.severity]
            return success_rate * 10 + severity_score
        
        chains.sort(key=chain_score, reverse=True)
        return chains[:10]
    
    def get_chain_recommendations(self, target: str) -> Dict[str, Any]:
        """
        Get chain recommendations for a target.
        """
        recommendations = {
            'target': target,
            'available_chains': [],
            'suggested_chains': [],
            'missing_steps': [],
            'total_findings': 0
        }
        
        findings = self.kb.get_findings_by_target(target)
        recommendations['total_findings'] = len(findings)
        
        # Get existing chains
        chains = self.kb.get_chains_by_target(target)
        for chain in chains[:5]:
            recommendations['available_chains'].append({
                'name': chain.name,
                'severity': chain.severity,
                'steps': len(chain.steps),
                'findings': len(chain.findings)
            })
        
        # Suggest missing chains
        available_steps = set()
        for f in findings:
            available_steps.add(self._categorize_finding(f))
        
        for template_id, template in self.templates.items():
            missing = []
            for step in template['steps']:
                if step not in available_steps:
                    missing.append(step)
            if missing:
                recommendations['suggested_chains'].append({
                    'name': template['name'],
                    'missing_steps': missing,
                    'severity': template['severity']
                })
        
        return recommendations
    
    # ============================================================
    # Chain Export
    # ============================================================
    
    def export_chains(self, target: str, format: str = "json") -> str:
        """
        Export chains for a target in specified format.
        """
        chains = self.kb.get_chains_by_target(target)
        
        if not chains:
            return "No chains found for this target."
        
        export_data = {
            'target': target,
            'exported_at': get_timestamp(),
            'total_chains': len(chains),
            'chains': [asdict(c) for c in chains]
        }
        
        if format == "json":
            return json.dumps(export_data, indent=2, default=str)
        elif format == "markdown":
            return self._export_markdown(chains)
        else:
            return json.dumps(export_data, indent=2, default=str)
    
    def _export_markdown(self, chains: List[AttackChain]) -> str:
        """Export chains in Markdown format."""
        if not chains:
            return "No chains found."
        
        md = "# Attack Chains\n\n"
        
        for chain in chains:
            md += f"## {chain.name}\n\n"
            md += f"- **Severity:** {chain.severity.upper()}\n"
            md += f"- **Target:** {chain.target}\n"
            md += f"- **Status:** {'✅ Completed' if chain.completed else '⏳ In Progress'}\n"
            md += f"- **Steps:** {len(chain.steps)}\n"
            md += f"- **Findings:** {len(chain.findings)}\n\n"
            
            md += "### Steps\n\n"
            for i, step in enumerate(chain.steps, 1):
                md += f"{i}. **{step['step']}** — {step['description']}\n"
                md += f"   - Finding ID: `{step['finding_id']}`\n"
                md += f"   - Severity: {step['severity']}\n\n"
            
            md += "---\n\n"
        
        return md