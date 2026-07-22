"""
BugBountyAgent - Finding Model
================================
Database model for discovered vulnerabilities.
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, JSON, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Finding(Base):
    """Finding model representing a discovered vulnerability."""
    
    __tablename__ = 'findings'
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Relationships
    target_id = Column(String(36), ForeignKey('targets.id', ondelete='CASCADE'), nullable=False)
    scan_id = Column(String(36), ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    chain_id = Column(String(36), ForeignKey('chains.id', ondelete='SET NULL'), nullable=True)
    
    # Finding details
    title = Column(String(200), nullable=False)
    type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    description = Column(Text, nullable=False)
    
    # Reproduction
    reproduction_steps = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    
    # Technical details
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(50), nullable=True)
    cve_id = Column(String(50), nullable=True)
    cwe_id = Column(String(50), nullable=True)
    
    # Location
    url = Column(String(500), nullable=True)
    endpoint = Column(String(200), nullable=True)
    parameter = Column(String(100), nullable=True)
    method = Column(String(10), nullable=True)
    
    # Evidence
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    payload = Column(Text, nullable=True)
    screenshot = Column(String(500), nullable=True)  # Path to screenshot
    
    # Status
    status = Column(String(20), default='new')  # new, triaged, confirmed, false_positive, fixed, duplicate
    is_false_positive = Column(Boolean, default=False)
    is_duplicate = Column(Boolean, default=False)
    duplicate_of = Column(String(36), nullable=True)
    
    # Metadata
    confidence = Column(Float, default=0.8)  # 0.0 - 1.0
    tags = Column(JSON, nullable=True, default=list)
    references = Column(JSON, nullable=True, default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    confirmed_at = Column(DateTime, nullable=True)
    fixed_at = Column(DateTime, nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    chain = relationship("Chain", back_populates="findings")
    
    def __repr__(self):
        return f"<Finding(id={self.id}, title={self.title}, severity={self.severity})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'target_id': self.target_id,
            'scan_id': self.scan_id,
            'chain_id': self.chain_id,
            'title': self.title,
            'type': self.type,
            'severity': self.severity,
            'description': self.description,
            'reproduction_steps': self.reproduction_steps,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'url': self.url,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'method': self.method,
            'request': self.request,
            'response': self.response,
            'payload': self.payload,
            'screenshot': self.screenshot,
            'status': self.status,
            'is_false_positive': self.is_false_positive,
            'is_duplicate': self.is_duplicate,
            'duplicate_of': self.duplicate_of,
            'confidence': self.confidence,
            'tags': self.tags,
            'references': self.references,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'confirmed_at': self.confirmed_at.isoformat() if self.confirmed_at else None,
            'fixed_at': self.fixed_at.isoformat() if self.fixed_at else None
        }
    
    def to_markdown(self) -> str:
        """Convert to markdown format for reporting."""
        md = f"""
## {self.title}

**Severity:** {self.severity.upper()}
**Type:** {self.type}
**Target:** {self.target.url if self.target else 'N/A'}
**URL:** {self.url or 'N/A'}
**Status:** {self.status}

### Description
{self.description}

### Reproduction Steps
{self.reproduction_steps or 'Not provided'}

### Remediation
{self.remediation or 'Not provided'}

### Technical Details
"""
        if self.cvss_score:
            md += f"- **CVSS Score:** {self.cvss_score}\n"
        if self.cve_id:
            md += f"- **CVE:** {self.cve_id}\n"
        if self.cwe_id:
            md += f"- **CWE:** {self.cwe_id}\n"
        if self.payload:
            md += f"- **Payload:** `{self.payload}`\n"
        
        md += f"\n*Found at: {self.created_at.isoformat() if self.created_at else 'N/A'}*\n"
        md += f"*Confidence: {int(self.confidence * 100)}%*\n"
        
        return md
    
    def get_severity_icon(self) -> str:
        """Get emoji icon for severity."""
        return {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }.get(self.severity, '❓')
    
    def get_status_icon(self) -> str:
        """Get emoji icon for status."""
        return {
            'new': '🆕',
            'triaged': '📋',
            'confirmed': '✅',
            'false_positive': '❌',
            'fixed': '🔧',
            'duplicate': '📎'
        }.get(self.status, '❓')
    
    @classmethod
    def create_defaults(cls):
        """Create default finding configuration."""
        return {
            'status': 'new',
            'confidence': 0.8,
            'tags': [],
            'references': [],
            'is_false_positive': False,
            'is_duplicate': False
        }