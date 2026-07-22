"""
BugBountyAgent - Chain Model
==============================
Database model for attack chains that correlate findings together.
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, JSON, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Chain(Base):
    """Chain model representing an attack chain."""
    
    __tablename__ = 'chains'
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Relationships
    target_id = Column(String(36), ForeignKey('targets.id', ondelete='CASCADE'), nullable=False)
    
    # Chain details
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    
    # Steps
    steps = Column(JSON, nullable=True, default=list)  # List of step objects
    finding_ids = Column(JSON, nullable=True, default=list)  # List of finding IDs in chain
    
    # Status
    status = Column(String(20), default='incomplete')  # incomplete, complete, validated, exploited
    
    # Statistics
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    attempts = Column(Integer, default=0)
    
    # Metadata
    confidence = Column(Float, default=0.5)  # 0.0 - 1.0
    tags = Column(JSON, nullable=True, default=list)
    references = Column(JSON, nullable=True, default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    validated_at = Column(DateTime, nullable=True)
    exploited_at = Column(DateTime, nullable=True)
    
    # Relationships
    target = relationship("Target", back_populates="chains")
    findings = relationship("Finding", back_populates="chain", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Chain(id={self.id}, name={self.name}, severity={self.severity})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'target_id': self.target_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'steps': self.steps,
            'finding_ids': self.finding_ids,
            'status': self.status,
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'attempts': self.attempts,
            'confidence': self.confidence,
            'tags': self.tags,
            'references': self.references,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'validated_at': self.validated_at.isoformat() if self.validated_at else None,
            'exploited_at': self.exploited_at.isoformat() if self.exploited_at else None
        }
    
    def to_markdown(self) -> str:
        """Convert to markdown format for reporting."""
        md = f"""
## 🔗 Chain: {self.name}

**Severity:** {self.severity.upper()}
**Status:** {self.status}
**Confidence:** {int(self.confidence * 100)}%
**Steps:** {len(self.steps)}

### Description
{self.description or 'No description provided.'}

### Attack Steps
"""
        for i, step in enumerate(self.steps, 1):
            step_type = step.get('type', 'Unknown')
            step_desc = step.get('description', '')
            finding_id = step.get('finding_id', '')
            md += f"\n{i}. **{step_type}**\n"
            if step_desc:
                md += f"   {step_desc}\n"
            if finding_id:
                md += f"   *Finding: `{finding_id}`*\n"
        
        md += f"\n**Success Rate:** {self.success_count}/{self.attempts} attempts\n"
        md += f"**Created:** {self.created_at.isoformat() if self.created_at else 'N/A'}\n"
        
        return md
    
    def get_severity_icon(self) -> str:
        """Get emoji icon for severity."""
        return {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵'
        }.get(self.severity, '❓')
    
    def get_status_icon(self) -> str:
        """Get emoji icon for status."""
        return {
            'incomplete': '⏳',
            'complete': '✅',
            'validated': '✔️',
            'exploited': '💀'
        }.get(self.status, '❓')
    
    def is_complete(self) -> bool:
        """Check if chain is complete."""
        return self.status in ['complete', 'validated', 'exploited']
    
    def is_exploitable(self) -> bool:
        """Check if chain is exploitable."""
        return self.status == 'exploited' or (self.status == 'complete' and self.confidence > 0.7)
    
    def get_success_rate(self) -> float:
        """Get success rate as percentage."""
        if self.attempts == 0:
            return 0.0
        return (self.success_count / self.attempts) * 100
    
    def add_step(self, step_type: str, description: str, finding_id: Optional[str] = None) -> int:
        """Add a step to the chain."""
        step = {
            'type': step_type,
            'description': description,
            'finding_id': finding_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        if not self.steps:
            self.steps = []
        self.steps.append(step)
        
        if finding_id and finding_id not in self.finding_ids:
            if not self.finding_ids:
                self.finding_ids = []
            self.finding_ids.append(finding_id)
        
        return len(self.steps) - 1
    
    def record_attempt(self, success: bool):
        """Record an attempt on this chain."""
        self.attempts += 1
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1
        
        # Update confidence based on success rate
        if self.attempts > 0:
            rate = self.success_count / self.attempts
            self.confidence = min(0.95, 0.5 + (rate * 0.5))
    
    @classmethod
    def create_defaults(cls):
        """Create default chain configuration."""
        return {
            'status': 'incomplete',
            'confidence': 0.5,
            'steps': [],
            'finding_ids': [],
            'tags': [],
            'references': [],
            'success_count': 0,
            'failure_count': 0,
            'attempts': 0
        }