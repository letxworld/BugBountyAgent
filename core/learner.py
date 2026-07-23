"""
BugBountyAgent - Self-Learning Engine
======================================
Learns from past findings to improve detection.
Identifies patterns, builds attack chains, and improves over time.
"""

import json
import hashlib
from typing import List, Dict, Any, Optional, Set
from collections import Counter
from datetime import datetime, timedelta

from .config import Config
from .filesystem import FileSystemController
from .logging import log_info, log_error, log_warning, log_debug, get_timestamp, generate_id


class Learner:
    """
    Self-learning engine that improves from past findings.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.filesystem = FileSystemController(config)
        self.patterns: List[Dict] = []
        self.knowledge_base: Dict[str, Any] = {}
        
        self.learning_enabled = config.get('learning.enabled', True)
        self.confidence_threshold = config.get('learning.confidence_threshold', 0.7)
        
        self._load_knowledge()
        log_info("🧠 Learner initialized")
    
    # ============================================================
    # Knowledge Management
    # ============================================================
    
    def _load_knowledge(self):
        """Load existing knowledge from disk."""
        # Load patterns
        self.patterns = self.filesystem.load_patterns()
        
        # Load knowledge base
        kb_path = self.config.get('learning.knowledge_path', './data/knowledge/knowledge.json')
        if self.filesystem.file_exists(kb_path):
            data = self.filesystem.read_json(kb_path)
            if data:
                self.knowledge_base = data
        
        log_debug(f"Loaded {len(self.patterns)} patterns")
    
    def _save_knowledge(self):
        """Save knowledge to disk."""
        # Save patterns
        for pattern in self.patterns:
            self.filesystem.save_pattern(pattern)
        
        # Save knowledge base
        kb_path = self.config.get('learning.knowledge_path', './data/knowledge/knowledge.json')
        self.filesystem.write_json(kb_path, self.knowledge_base)
    
    # ============================================================
    # Learning from Findings
    # ============================================================
    
    def learn(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Learn from a list of findings.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Dict: Learning results
        """
        if not self.learning_enabled:
            return {'message': 'Learning disabled'}
        
        if not findings:
            return {'message': 'No findings to learn from'}
        
        log_info(f"🧠 Learning from {len(findings)} findings")
        
        # Extract patterns
        new_patterns = self._extract_patterns(findings)
        
        # Update patterns
        updated = self._update_patterns(new_patterns)
        
        # Build attack chains
        chains = self._build_chains(findings)
        
        # Update knowledge base
        self._update_knowledge_base(findings)
        
        # Save everything
        self._save_knowledge()
        
        return {
            'findings_processed': len(findings),
            'new_patterns': len(new_patterns),
            'patterns_updated': updated,
            'chains_built': len(chains),
            'total_patterns': len(self.patterns)
        }
    
    def _extract_patterns(self, findings: List[Dict]) -> List[Dict]:
        """Extract patterns from findings."""
        patterns = []
        
        for finding in findings:
            # Create a pattern signature
            signature = self._create_signature(finding)
            
            pattern = {
                'id': generate_id(),
                'signature': signature,
                'title': finding.get('title', 'Unknown'),
                'severity': finding.get('severity', 'medium'),
                'type': self._categorize_finding(finding),
                'indicators': self._extract_indicators(finding),
                'confidence': 0.7,
                'occurrences': 1,
                'first_seen': get_timestamp(),
                'last_seen': get_timestamp(),
                'source': finding.get('source', 'unknown')
            }
            
            patterns.append(pattern)
        
        return patterns
    
    def _create_signature(self, finding: Dict) -> str:
        """Create a unique signature for a finding."""
        parts = [
            finding.get('title', '')[:50],
            finding.get('severity', ''),
            finding.get('type', ''),
            finding.get('source', '')
        ]
        text = '|'.join(parts).lower()
        return hashlib.md5(text.encode()).hexdigest()[:16]
    
    def _categorize_finding(self, finding: Dict) -> str:
        """Categorize a finding."""
        title = finding.get('title', '').lower()
        
        categories = {
            'injection': ['sql', 'injection', 'sqli'],
            'xss': ['xss', 'cross-site', 'script'],
            'csrf': ['csrf', 'cross-site request'],
            'ssrf': ['ssrf', 'server-side request'],
            'xxe': ['xxe', 'xml external'],
            'rce': ['rce', 'remote code', 'command injection'],
            'lfi': ['lfi', 'local file'],
            'rfi': ['rfi', 'remote file'],
            'idor': ['idor', 'insecure direct', 'object reference'],
            'auth': ['auth', 'authentication', 'login', 'session'],
            'misconfig': ['misconfig', 'misconfiguration', 'header'],
            'disclosure': ['disclosure', 'exposure', 'leak']
        }
        
        for category, keywords in categories.items():
            for keyword in keywords:
                if keyword in title:
                    return category
        
        return 'unknown'
    
    def _extract_indicators(self, finding: Dict) -> List[str]:
        """Extract indicators from a finding."""
        indicators = []
        
        # Extract from description
        description = finding.get('description', '')
        if description:
            # Common vulnerability indicators
            indicators.extend(self._find_indicators(description))
        
        # Extract from title
        title = finding.get('title', '')
        if title:
            indicators.extend(self._find_indicators(title))
        
        return list(set(indicators))[:10]  # Limit
    
    def _find_indicators(self, text: str) -> List[str]:
        """Find vulnerability indicators in text."""
        indicators = []
        
        patterns = {
            'sql_error': ['sql', 'syntax error', 'mysql', 'ora-', 'postgresql', 'sqlite'],
            'script_tag': ['<script>', '<img', 'onerror', 'onload', 'javascript:'],
            'path_traversal': ['../', '..\\', 'etc/passwd', 'windows\\win.ini'],
            'error_pattern': ['error', 'exception', 'stack trace', 'fatal', 'warning'],
            'info_disclosure': ['password', 'token', 'api_key', 'secret', 'key'],
            'server_info': ['server:', 'powered by', 'generator']
        }
        
        text_lower = text.lower()
        for category, keywords in patterns.items():
            for keyword in keywords:
                if keyword in text_lower:
                    indicators.append(category)
                    break
        
        return indicators
    
    def _update_patterns(self, new_patterns: List[Dict]) -> int:
        """Update existing patterns with new data."""
        updated = 0
        
        for new_pattern in new_patterns:
            # Check if pattern already exists
            existing = None
            for pattern in self.patterns:
                if pattern.get('signature') == new_pattern.get('signature'):
                    existing = pattern
                    break
            
            if existing:
                # Update existing pattern
                existing['occurrences'] += 1
                existing['last_seen'] = get_timestamp()
                existing['confidence'] = min(0.95, existing.get('confidence', 0.5) + 0.02)
                updated += 1
            else:
                # Add new pattern
                self.patterns.append(new_pattern)
                updated += 1
        
        return updated
    
    # ============================================================
    # Attack Chain Building
    # ============================================================
    
    def _build_chains(self, findings: List[Dict]) -> List[Dict]:
        """Build attack chains from findings."""
        chains = []
        
        # Group findings by type
        grouped = {}
        for finding in findings:
            category = self._categorize_finding(finding)
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(finding)
        
        # Build chains for each group
        chain_templates = {
            'injection': {
                'name': 'Injection Chain',
                'steps': ['injection', 'disclosure', 'exploitation'],
                'severity': 'critical'
            },
            'xss': {
                'name': 'XSS to Session Hijacking',
                'steps': ['xss', 'cookie_exfiltration', 'session_hijacking'],
                'severity': 'high'
            },
            'auth': {
                'name': 'Authentication Chain',
                'steps': ['auth_bypass', 'session_fixation', 'account_takeover'],
                'severity': 'critical'
            },
            'misconfig': {
                'name': 'Misconfiguration Chain',
                'steps': ['misconfig', 'disclosure', 'exploitation'],
                'severity': 'high'
            }
        }
        
        for category, category_findings in grouped.items():
            if category in chain_templates and len(category_findings) >= 1:
                template = chain_templates[category]
                chain = {
                    'id': generate_id(),
                    'name': template['name'],
                    'severity': template['severity'],
                    'steps': [
                        {
                            'step': f.get('title', 'Unknown'),
                            'description': f.get('description', ''),
                            'finding_id': f.get('id', '')
                        }
                        for f in category_findings
                    ],
                    'total_steps': len(category_findings),
                    'completed': False
                }
                chains.append(chain)
        
        return chains
    
    # ============================================================
    # Knowledge Base Update
    # ============================================================
    
    def _update_knowledge_base(self, findings: List[Dict]):
        """Update the knowledge base with new findings."""
        # Update total findings count
        self.knowledge_base['total_findings'] = self.knowledge_base.get('total_findings', 0) + len(findings)
        
        # Update severity counts
        if 'severity_counts' not in self.knowledge_base:
            self.knowledge_base['severity_counts'] = {}
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            self.knowledge_base['severity_counts'][severity] = self.knowledge_base['severity_counts'].get(severity, 0) + 1
        
        # Update type counts
        if 'type_counts' not in self.knowledge_base:
            self.knowledge_base['type_counts'] = {}
        
        for finding in findings:
            type_name = self._categorize_finding(finding)
            self.knowledge_base['type_counts'][type_name] = self.knowledge_base['type_counts'].get(type_name, 0) + 1
        
        # Update last learning time
        self.knowledge_base['last_learning'] = get_timestamp()
        
        # Update pattern confidence
        for pattern in self.patterns:
            if pattern.get('occurrences', 0) > 5:
                pattern['confidence'] = min(0.95, pattern.get('confidence', 0.5) + 0.05)
    
    # ============================================================
    # Pattern Matching
    # ============================================================
    
    def match_patterns(self, text: str) -> List[Dict]:
        """
        Match text against learned patterns.
        
        Args:
            text: Text to match
            
        Returns:
            List[Dict]: Matching patterns
        """
        matches = []
        
        for pattern in self.patterns:
            confidence = pattern.get('confidence', 0.5)
            if confidence < self.confidence_threshold:
                continue
            
            indicators = pattern.get('indicators', [])
            matched = 0
            text_lower = text.lower()
            
            for indicator in indicators:
                if indicator in text_lower:
                    matched += 1
            
            if matched > 0:
                match_score = matched / len(indicators) if indicators else 0
                if match_score > 0.3:
                    matches.append({
                        'pattern_id': pattern.get('id'),
                        'pattern_name': pattern.get('title', 'Unknown'),
                        'confidence': confidence * match_score,
                        'severity': pattern.get('severity', 'medium')
                    })
        
        return sorted(matches, key=lambda x: x['confidence'], reverse=True)[:10]
    
    # ============================================================
    # Statistics
    # ============================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get learning statistics."""
        stats = {
            'total_patterns': len(self.patterns),
            'learning_enabled': self.learning_enabled,
            'confidence_threshold': self.confidence_threshold,
            'knowledge_base': self.knowledge_base
        }
        
        # Pattern category distribution
        categories = Counter()
        for pattern in self.patterns:
            categories[pattern.get('type', 'unknown')] += 1
        
        stats['pattern_categories'] = dict(categories.most_common(10))
        
        # Confidence distribution
        confidence_levels = {'high': 0, 'medium': 0, 'low': 0}
        for pattern in self.patterns:
            conf = pattern.get('confidence', 0.5)
            if conf >= 0.8:
                confidence_levels['high'] += 1
            elif conf >= 0.5:
                confidence_levels['medium'] += 1
            else:
                confidence_levels['low'] += 1
        
        stats['confidence_distribution'] = confidence_levels
        
        return stats
    
    def get_patterns(self, category: Optional[str] = None) -> List[Dict]:
        """Get patterns, optionally filtered by category."""
        if category:
            return [p for p in self.patterns if p.get('type') == category]
        return self.patterns
    
    def get_high_confidence_patterns(self) -> List[Dict]:
        """Get patterns with high confidence."""
        return [p for p in self.patterns if p.get('confidence', 0) >= 0.8]