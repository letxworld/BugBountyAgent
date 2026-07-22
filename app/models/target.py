"""
BugBountyAgent - Target Model
===============================
Database model for targets being scanned.
"""

import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class Target(Base):
    """Target model representing a target being scanned."""
    
    __tablename__ = 'targets'
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Target information
    url = Column(String(500), nullable=False, unique=True)
    name = Column(String(200), nullable=True)
    description = Column(Text, nullable=True)
    
    # Scope
    scope = Column(JSON, nullable=True, default=list)  # List of scope patterns
    exclude = Column(JSON, nullable=True, default=list)  # List of exclude patterns
    
    # Status
    status = Column(String(20), default='pending')  # pending, active, scanning, completed, failed, paused
    
    # Statistics
    total_scans = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    
    # Metadata
    subdomains = Column(JSON, nullable=True, default=list)
    ports = Column(JSON, nullable=True, default=list)
    technologies = Column(JSON, nullable=True, default=dict)
    endpoints = Column(JSON, nullable=True, default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scan_at = Column(DateTime, nullable=True)
    last_finding_at = Column(DateTime, nullable=True)
    
    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")
    chains = relationship("Chain", back_populates="target", cascade="all, delete-orphan")
    profile = relationship("Profile", back_populates="target", uselist=False, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Target(id={self.id}, url={self.url}, status={self.status})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'url': self.url,
            'name': self.name,
            'description': self.description,
            'scope': self.scope,
            'exclude': self.exclude,
            'status': self.status,
            'total_scans': self.total_scans,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'subdomains': self.subdomains,
            'ports': self.ports,
            'technologies': self.technologies,
            'endpoints': self.endpoints,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_scan_at': self.last_scan_at.isoformat() if self.last_scan_at else None,
            'last_finding_at': self.last_finding_at.isoformat() if self.last_finding_at else None
        }
    
    def update_statistics(self):
        """Update statistics based on findings."""
        if self.findings:
            self.total_findings = len(self.findings)
            self.critical_findings = sum(1 for f in self.findings if f.severity == 'critical')
            self.high_findings = sum(1 for f in self.findings if f.severity == 'high')
            self.medium_findings = sum(1 for f in self.findings if f.severity == 'medium')
            self.low_findings = sum(1 for f in self.findings if f.severity == 'low')
            
            if self.findings:
                self.last_finding_at = max(f.created_at for f in self.findings)
    
    @classmethod
    def create_defaults(cls):
        """Create default target configuration."""
        return {
            'scope': [],
            'exclude': [],
            'status': 'pending',
            'subdomains': [],
            'ports': [],
            'technologies': {},
            'endpoints': []
        }