"""
BugBountyAgent - Knowledge Module
==================================
This module manages the knowledge base for storing and retrieving:
- Vulnerability patterns
- CVE data
- Learned attack patterns
- Successful chains
- Past findings
"""

from app.knowledge.knowledge_base import KnowledgeBase
from app.knowledge.pattern_matcher import PatternMatcher
from app.knowledge.cve_fetcher import CVEFetcher
from app.knowledge.chain_knowledge import ChainKnowledge

__all__ = [
    'KnowledgeBase',
    'PatternMatcher',
    'CVEFetcher',
    'ChainKnowledge'
]