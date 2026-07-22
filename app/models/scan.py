"""
BugBountyAgent - Scan Model
=============================
Database model for scan sessions.
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, JSON, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Scan(Base):
    """Scan model representing a scan session."""
    
    __tablename__ = 'scans'
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Relationships
    target_id = Column(String(36), ForeignKey('targets.id', ondelete='CASCADE'), nullable=False)
    
    # Scan details
    name = Column(String(200), nullable=True)
    type = Column(String(20), nullable=False)  # quick, full, recon, custom, incremental
    status = Column(String(20), default='pending')  # pending, running, completed, failed, paused, stopped
    
    # Configuration
    config = Column(JSON, nullable=True, default=dict)  # Scan configuration snapshot
    
    # Results
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    info_findings = Column(Integer, default=0)
    
    total_chains = Column(Integer, default=0)
    completed_chains = Column(Integer, default=0)
    
    # Progress
    progress = Column(Float, default=0.0)  # 0.0 - 1.0
    current_stage = Column(String(50), nullable=True)  # recon, scanning, analysis, reporting
    current_target = Column(String(500), nullable=True)
    
    # Statistics
    duration_seconds = Column(Integer, default=0)
    packets_captured = Column(Integer, default=0)
    requests_sent = Column(Integer, default=0)
    requests_received = Column(Integer, default=0)
    
    # Logs
    log_file = Column(String(500), nullable=True)
    report_path = Column(String(500), nullable=True)
    output_dir = Column(String(500), nullable=True)
    
    # Metadata
    started_by = Column(String(50), default='system')  # system, user, api, schedule
    notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan(id={self.id}, type={self.type}, status={self.status})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'target_id': self.target_id,
            'name': self.name,
            'type': self.type,
            'status': self.status,
            'config': self.config,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'info_findings': self.info_findings,
            'total_chains': self.total_chains,
            'completed_chains': self.completed_chains,
            'progress': self.progress,
            'current_stage': self.current_stage,
            'current_target': self.current_target,
            'duration_seconds': self.duration_seconds,
            'packets_captured': self.packets_captured,
            'requests_sent': self.requests_sent,
            'requests_received': self.requests_received,
            'log_file': self.log_file,
            'report_path': self.report_path,
            'output_dir': self.output_dir,
            'started_by': self.started_by,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def get_status_icon(self) -> str:
        """Get emoji icon for status."""
        return {
            'pending': '⏳',
            'running': '🔄',
            'completed': '✅',
            'failed': '❌',
            'paused': '⏸️',
            'stopped': '⏹️'
        }.get(self.status, '❓')
    
    def get_stage_icon(self) -> str:
        """Get emoji icon for current stage."""
        return {
            'recon': '🔍',
            'scanning': '🔬',
            'analysis': '🧠',
            'reporting': '📄',
            'completed': '✅'
        }.get(self.current_stage or '', '⚡')
    
    def update_statistics(self):
        """Update statistics based on findings."""
        if self.findings:
            self.total_findings = len(self.findings)
            self.critical_findings = sum(1 for f in self.findings if f.severity == 'critical')
            self.high_findings = sum(1 for f in self.findings if f.severity == 'high')
            self.medium_findings = sum(1 for f in self.findings if f.severity == 'medium')
            self.low_findings = sum(1 for f in self.findings if f.severity == 'low')
            self.info_findings = sum(1 for f in self.findings if f.severity == 'info')
    
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.status == 'running'
    
    def is_completed(self) -> bool:
        """Check if scan is completed."""
        return self.status == 'completed'
    
    def is_failed(self) -> bool:
        """Check if scan failed."""
        return self.status == 'failed'
    
    def get_duration_string(self) -> str:
        """Get human-readable duration."""
        if self.duration_seconds < 60:
            return f"{self.duration_seconds}s"
        elif self.duration_seconds < 3600:
            minutes = self.duration_seconds // 60
            seconds = self.duration_seconds % 60
            return f"{minutes}m {seconds}s"
        else:
            hours = self.duration_seconds // 3600
            minutes = (self.duration_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    def get_progress_percentage(self) -> int:
        """Get progress as percentage."""
        return int(self.progress * 100)
    
    @classmethod
    def create_defaults(cls):
        """Create default scan configuration."""
        return {
            'status': 'pending',
            'progress': 0.0,
            'config': {},
            'notes': '',
            'started_by': 'system'
        }