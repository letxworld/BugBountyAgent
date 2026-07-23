"""
BugBountyAgent - Brain
=======================
AI decision making and vulnerability prioritization.
Builds attack chains from findings.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class Priority(Enum):
    """Priority levels for actions."""
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


@dataclass
class Decision:
    """A decision made by the brain."""
    action: str
    priority: Priority
    reason: str
    confidence: float
    data: Optional[Dict] = None


class Brain:
    """
    AI decision making engine.
    Prioritizes vulnerabilities, builds attack chains, and recommends actions.
    """
    
    def __init__(self, config):
        self.config = config
        self.confidence_threshold = config.get('learning.confidence_threshold', 0.7)
        print("🧠 Brain initialized")
    
    # ============================================================
    # Attack Chain Building
    # ============================================================
    
    def analyze_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Analyze findings and build attack chains.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List[Dict]: Attack chains
        """
        return self._build_chains(findings)
    
    def _build_chains(self, findings: List[Dict]) -> List[Dict]:
        """
        Build attack chains from findings.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List[Dict]: Attack chains
        """
        if not findings:
            return []
        
        chains = []
        
        # Group findings by target
        targets = {}
        for f in findings:
            target = f.get('target', 'unknown')
            if target not in targets:
                targets[target] = []
            targets[target].append(f)
        
        # Build chains for each target
        for target, target_findings in targets.items():
            if len(target_findings) >= 1:
                # Build step-by-step chain
                steps = []
                for idx, f in enumerate(target_findings):
                    step = {
                        'step': idx + 1,
                        'type': f.get('title', 'Unknown'),
                        'description': f.get('description', 'No description')[:200],
                        'finding_id': f.get('id', ''),
                        'severity': f.get('severity', 'info'),
                        'cve_id': f.get('cve_id', ''),
                        'url': f.get('url', '')
                    }
                    steps.append(step)
                
                # Determine chain severity (highest in chain)
                chain_severity = self._get_max_severity(target_findings)
                
                # Build chain description
                chain_desc = f"Attack chain consisting of {len(target_findings)} vulnerabilities on {target}"
                
                chain = {
                    'id': f"chain_{target}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    'name': f"Attack Chain: {target}",
                    'target': target,
                    'severity': chain_severity,
                    'steps': steps,
                    'total_steps': len(steps),
                    'finding_ids': [f.get('id', '') for f in target_findings],
                    'completed': True,
                    'timestamp': datetime.now().isoformat(),
                    'description': chain_desc,
                    'exploitable': chain_severity in ['critical', 'high'],
                    'success_rate': self._calculate_success_rate(target_findings)
                }
                chains.append(chain)
        
        # Sort chains by severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        chains.sort(key=lambda c: severity_order.get(c.get('severity', 'info'), 5))
        
        return chains
    
    def _calculate_success_rate(self, findings: List[Dict]) -> float:
        """Calculate estimated success rate based on findings."""
        if not findings:
            return 0.0
        
        # Higher severity findings increase success rate
        severity_weights = {'critical': 0.9, 'high': 0.7, 'medium': 0.5, 'low': 0.3, 'info': 0.1}
        
        total_weight = 0.0
        for f in findings:
            sev = f.get('severity', 'info').lower()
            total_weight += severity_weights.get(sev, 0.1)
        
        # Normalize
        rate = min(0.95, total_weight / len(findings) + 0.2)
        return round(rate, 2)
    
    def _get_max_severity(self, findings: List[Dict]) -> str:
        """Get the highest severity from findings."""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        max_sev = 'info'
        max_priority = 999
        
        for f in findings:
            sev = f.get('severity', 'info').lower()
            priority = severity_order.get(sev, 5)
            if priority < max_priority:
                max_priority = priority
                max_sev = sev
        
        return max_sev
    
    def recommend_chain(self, chains: List[Dict]) -> Optional[Dict]:
        """
        Recommend the best attack chain to exploit.
        
        Args:
            chains: List of attack chains
            
        Returns:
            Optional[Dict]: Best chain or None
        """
        if not chains:
            return None
        
        # Score chains based on severity and success rate
        severity_scores = {'critical': 100, 'high': 70, 'medium': 40, 'low': 20}
        scored = []
        
        for chain in chains:
            severity = chain.get('severity', 'medium')
            steps = len(chain.get('steps', []))
            success_rate = chain.get('success_rate', 0.5)
            
            score = severity_scores.get(severity, 30) + (steps * 5) + (success_rate * 50)
            scored.append((score, chain))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1] if scored else None
    
    # ============================================================
    # Decision Making
    # ============================================================
    
    def analyze_findings_for_decisions(self, findings: List[Dict]) -> List[Decision]:
        """
        Analyze findings and make decisions.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List[Decision]: Recommended decisions
        """
        decisions = []
        
        if not findings:
            return decisions
        
        # Group by severity
        critical = [f for f in findings if f.get('severity') == 'critical']
        high = [f for f in findings if f.get('severity') == 'high']
        medium = [f for f in findings if f.get('severity') == 'medium']
        
        # Critical findings first
        for finding in critical:
            decisions.append(Decision(
                action='exploit',
                priority=Priority.CRITICAL,
                reason=f"Critical vulnerability: {finding.get('title', 'Unknown')}",
                confidence=0.9,
                data=finding
            ))
        
        # High findings
        for finding in high:
            decisions.append(Decision(
                action='investigate',
                priority=Priority.HIGH,
                reason=f"High vulnerability: {finding.get('title', 'Unknown')}",
                confidence=0.8,
                data=finding
            ))
        
        # Medium findings
        for finding in medium:
            decisions.append(Decision(
                action='review',
                priority=Priority.MEDIUM,
                reason=f"Medium vulnerability: {finding.get('title', 'Unknown')}",
                confidence=0.6,
                data=finding
            ))
        
        # Sort by priority
        decisions.sort(key=lambda d: d.priority.value)
        
        return decisions
    
    def should_attack(self, finding: Dict) -> bool:
        """
        Determine if the agent should attack a finding.
        
        Args:
            finding: Finding to evaluate
            
        Returns:
            bool: Should attack
        """
        severity = finding.get('severity', 'info')
        confidence = finding.get('confidence', 0.5)
        
        # Only attack critical and high severity with high confidence
        if severity in ['critical', 'high'] and confidence >= self.confidence_threshold:
            return True
        return False
    
    def get_priority_order(self, findings: List[Dict]) -> List[Dict]:
        """
        Get findings in priority order.
        
        Args:
            findings: List of findings
            
        Returns:
            List[Dict]: Findings sorted by priority
        """
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        return sorted(
            findings,
            key=lambda f: priority_order.get(f.get('severity', 'info').lower(), 5)
        )
    
    def assess_risk(self, finding: Dict) -> float:
        """
        Assess the risk level of a finding.
        
        Args:
            finding: Finding to assess
            
        Returns:
            float: Risk score (0-10)
        """
        severity_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        severity = finding.get('severity', 'info')
        
        base_score = severity_scores.get(severity, 3)
        confidence = finding.get('confidence', 0.5)
        
        return round(base_score * confidence, 1)
    
    def get_attack_recommendations(self, chains: List[Dict]) -> Dict[str, Any]:
        """
        Get attack recommendations from chains.
        
        Args:
            chains: List of attack chains
            
        Returns:
            Dict: Recommendations
        """
        if not chains:
            return {
                'recommended_chain': None,
                'total_chains': 0,
                'exploitable_chains': 0,
                'message': 'No chains available'
            }
        
        exploitable = [c for c in chains if c.get('exploitable', False)]
        recommended = self.recommend_chain(chains)
        
        return {
            'recommended_chain': recommended,
            'total_chains': len(chains),
            'exploitable_chains': len(exploitable),
            'message': f'Found {len(chains)} chains, {len(exploitable)} exploitable'
        }