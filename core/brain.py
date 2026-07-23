"""
BugBountyAgent - Brain
=======================
AI decision making and vulnerability prioritization.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


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
    Prioritizes vulnerabilities and recommends actions.
    """
    
    def __init__(self, config):
        self.config = config
        self.confidence_threshold = config.get('learning.confidence_threshold', 0.7)
        print("🧠 Brain initialized")
    
    def analyze_findings(self, findings: List[Dict]) -> List[Decision]:
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
    
    def recommend_chain(self, chains: List[Dict]) -> Optional[Dict]:
        """
        Recommend the best attack chain.
        
        Args:
            chains: List of attack chains
            
        Returns:
            Optional[Dict]: Best chain
        """
        if not chains:
            return None
        
        # Score chains
        scored = []
        for chain in chains:
            severity = chain.get('severity', 'medium')
            steps = chain.get('total_steps', 0)
            
            severity_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}
            severity_score = severity_scores.get(severity, 3)
            
            score = severity_score + steps
            scored.append((score, chain))
        
        # Return highest scored chain
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1] if scored else None
    
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
        
        return base_score * confidence