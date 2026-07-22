"""
BugBountyAgent - Profile Model
================================
Database model for target profiles with aggregated data.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, JSON, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Profile(Base):
    """Profile model representing a target's aggregated data."""
    
    __tablename__ = 'profiles'
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Relationships
    target_id = Column(String(36), ForeignKey('targets.id', ondelete='CASCADE'), nullable=False, unique=True)
    
    # Target information
    domain = Column(String(500), nullable=False, unique=True)
    name = Column(String(200), nullable=True)
    description = Column(Text, nullable=True)
    
    # Discovered assets
    subdomains = Column(JSON, nullable=True, default=list)
    ips = Column(JSON, nullable=True, default=list)
    ports = Column(JSON, nullable=True, default=list)
    technologies = Column(JSON, nullable=True, default=dict)
    endpoints = Column(JSON, nullable=True, default=list)
    
    # Vulnerability statistics (aggregated)
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    info_findings = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    
    # Chain statistics
    total_chains = Column(Integer, default=0)
    exploitable_chains = Column(Integer, default=0)
    exploited_chains = Column(Integer, default=0)
    
    # Scan history
    total_scans = Column(Integer, default=0)
    last_scan_at = Column(DateTime, nullable=True)
    first_scan_at = Column(DateTime, nullable=True)
    last_finding_at = Column(DateTime, nullable=True)
    
    # Risk scoring
    risk_score = Column(Float, default=0.0)  # 0.0 - 10.0
    exposure_score = Column(Float, default=0.0)  # 0.0 - 10.0
    vulnerability_score = Column(Float, default=0.0)  # 0.0 - 10.0
    
    # Security posture
    security_headers = Column(JSON, nullable=True, default=dict)
    ssl_info = Column(JSON, nullable=True, default=dict)
    dns_info = Column(JSON, nullable=True, default=dict)
    
    # Activity timeline (for trend analysis)
    finding_timeline = Column(JSON, nullable=True, default=list)  # [{date: count, severity: ...}]
    scan_timeline = Column(JSON, nullable=True, default=list)  # [{date: count, type: ...}]
    
    # Metadata
    tags = Column(JSON, nullable=True, default=list)
    notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    target = relationship("Target", back_populates="profile", uselist=False)
    
    def __repr__(self):
        return f"<Profile(id={self.id}, domain={self.domain}, risk_score={self.risk_score})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'target_id': self.target_id,
            'domain': self.domain,
            'name': self.name,
            'description': self.description,
            'subdomains': self.subdomains,
            'ips': self.ips,
            'ports': self.ports,
            'technologies': self.technologies,
            'endpoints': self.endpoints,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'info_findings': self.info_findings,
            'false_positives': self.false_positives,
            'total_chains': self.total_chains,
            'exploitable_chains': self.exploitable_chains,
            'exploited_chains': self.exploited_chains,
            'total_scans': self.total_scans,
            'last_scan_at': self.last_scan_at.isoformat() if self.last_scan_at else None,
            'first_scan_at': self.first_scan_at.isoformat() if self.first_scan_at else None,
            'last_finding_at': self.last_finding_at.isoformat() if self.last_finding_at else None,
            'risk_score': self.risk_score,
            'exposure_score': self.exposure_score,
            'vulnerability_score': self.vulnerability_score,
            'security_headers': self.security_headers,
            'ssl_info': self.ssl_info,
            'dns_info': self.dns_info,
            'finding_timeline': self.finding_timeline,
            'scan_timeline': self.scan_timeline,
            'tags': self.tags,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def update_statistics(self, findings: List = None, chains: List = None):
        """Update statistics from findings and chains."""
        # Update finding statistics
        if findings:
            self.total_findings = len(findings)
            self.critical_findings = sum(1 for f in findings if f.severity == 'critical')
            self.high_findings = sum(1 for f in findings if f.severity == 'high')
            self.medium_findings = sum(1 for f in findings if f.severity == 'medium')
            self.low_findings = sum(1 for f in findings if f.severity == 'low')
            self.info_findings = sum(1 for f in findings if f.severity == 'info')
            self.false_positives = sum(1 for f in findings if f.is_false_positive)
        
        # Update chain statistics
        if chains:
            self.total_chains = len(chains)
            self.exploitable_chains = sum(1 for c in chains if c.is_exploitable())
            self.exploited_chains = sum(1 for c in chains if c.status == 'exploited')
        
        # Update risk scores
        self._calculate_risk_scores()
    
    def _calculate_risk_scores(self):
        """Calculate risk scores based on findings and exposure."""
        # Vulnerability score (0-10)
        score = 0.0
        if self.total_findings > 0:
            score += min(3.0, self.critical_findings * 0.5)
            score += min(2.0, self.high_findings * 0.3)
            score += min(1.0, self.medium_findings * 0.1)
        
        self.vulnerability_score = min(10.0, score)
        
        # Exposure score (0-10) based on assets
        exposure = 0.0
        if self.subdomains:
            exposure += min(3.0, len(self.subdomains) * 0.1)
        if self.ports:
            exposure += min(3.0, len(self.ports) * 0.05)
        if self.endpoints:
            exposure += min(2.0, len(self.endpoints) * 0.02)
        
        self.exposure_score = min(10.0, exposure)
        
        # Overall risk score
        self.risk_score = (self.vulnerability_score * 0.7) + (self.exposure_score * 0.3)
        self.risk_score = min(10.0, self.risk_score)
    
    def add_finding_to_timeline(self, finding):
        """Add a finding to the timeline."""
        if not self.finding_timeline:
            self.finding_timeline = []
        
        date_str = finding.created_at.strftime('%Y-%m-%d') if finding.created_at else datetime.utcnow().strftime('%Y-%m-%d')
        
        # Find or create entry for this date
        entry = None
        for e in self.finding_timeline:
            if e.get('date') == date_str:
                entry = e
                break
        
        if not entry:
            entry = {
                'date': date_str,
                'count': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            self.finding_timeline.append(entry)
        
        entry['count'] += 1
        severity = finding.severity.lower()
        if severity in entry:
            entry[severity] += 1
    
    def add_scan_to_timeline(self, scan):
        """Add a scan to the timeline."""
        if not self.scan_timeline:
            self.scan_timeline = []
        
        date_str = scan.created_at.strftime('%Y-%m-%d') if scan.created_at else datetime.utcnow().strftime('%Y-%m-%d')
        
        # Find or create entry for this date
        entry = None
        for e in self.scan_timeline:
            if e.get('date') == date_str:
                entry = e
                break
        
        if not entry:
            entry = {
                'date': date_str,
                'count': 0,
                'types': {}
            }
            self.scan_timeline.append(entry)
        
        entry['count'] += 1
        if scan.type not in entry['types']:
            entry['types'][scan.type] = 0
        entry['types'][scan.type] += 1
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the profile."""
        return {
            'domain': self.domain,
            'total_scans': self.total_scans,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'info_findings': self.info_findings,
            'total_chains': self.total_chains,
            'exploitable_chains': self.exploitable_chains,
            'risk_score': round(self.risk_score, 2),
            'exposure_score': round(self.exposure_score, 2),
            'vulnerability_score': round(self.vulnerability_score, 2),
            'subdomains': len(self.subdomains or []),
            'ports': len(self.ports or []),
            'endpoints': len(self.endpoints or []),
            'technologies': len(self.technologies or {}),
            'last_scan_at': self.last_scan_at.isoformat() if self.last_scan_at else None,
            'last_finding_at': self.last_finding_at.isoformat() if self.last_finding_at else None
        }
    
    def get_risk_level(self) -> str:
        """Get the risk level based on risk score."""
        if self.risk_score >= 8.0:
            return 'Critical'
        elif self.risk_score >= 6.0:
            return 'High'
        elif self.risk_score >= 4.0:
            return 'Medium'
        elif self.risk_score >= 2.0:
            return 'Low'
        else:
            return 'Info'
    
    @classmethod
    def create_defaults(cls):
        """Create default profile configuration."""
        return {
            'subdomains': [],
            'ips': [],
            'ports': [],
            'technologies': {},
            'endpoints': [],
            'security_headers': {},
            'ssl_info': {},
            'dns_info': {},
            'finding_timeline': [],
            'scan_timeline': [],
            'tags': [],
            'notes': ''
        }