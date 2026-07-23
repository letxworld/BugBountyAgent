"""
BugBountyAgent - State Management
===================================
Save and load agent state for persistence across sessions.
"""

import os
import json
from typing import Dict, Any, Optional
from datetime import datetime

from .config import Config
from .database import Database
from .utils import get_timestamp


class StateManager:
    """
    Manages agent state persistence.
    Saves and loads state across sessions.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.db = Database(config)
        self.state_file = config.get('system.state_file', './data/state.json')
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
    
    def save_state(self, state: Dict[str, Any]) -> bool:
        """
        Save agent state to file.
        
        Args:
            state: State dictionary to save
            
        Returns:
            bool: Success status
        """
        try:
            # Add metadata
            state['_metadata'] = {
                'saved_at': get_timestamp(),
                'version': '0.1.0'
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2, default=str)
            
            return True
            
        except Exception as e:
            print(f"Failed to save state: {e}")
            return False
    
    def load_state(self) -> Optional[Dict[str, Any]]:
        """
        Load agent state from file.
        
        Returns:
            Optional[Dict]: State dictionary or None
        """
        if not os.path.exists(self.state_file):
            return None
        
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            print(f"Failed to load state: {e}")
            return None
    
    def save_target(self, target: Dict[str, Any]) -> bool:
        """Save a target to database."""
        return self.db.save_target(target)
    
    def get_all_targets(self) -> List[Dict]:
        """Get all targets from database."""
        return self.db.get_all_targets()
    
    def save_finding(self, finding: Dict[str, Any]) -> bool:
        """Save a finding to database."""
        return self.db.save_finding(finding)
    
    def get_findings_by_target(self, target_id: str) -> List[Dict]:
        """Get findings for a target."""
        return self.db.get_findings_by_target(target_id)
    
    def save_chain(self, chain: Dict[str, Any]) -> bool:
        """Save a chain to database."""
        return self.db.save_chain(chain)
    
    def save_pattern(self, pattern: Dict[str, Any]) -> bool:
        """Save a pattern to database."""
        return self.db.save_pattern(pattern)
    
    def get_patterns(self) -> List[Dict]:
        """Get all patterns."""
        return self.db.get_patterns()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        return self.db.get_statistics()
    
    def clear_all(self) -> bool:
        """Clear all state (dangerous)."""
        try:
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
            return True
        except Exception as e:
            print(f"Failed to clear state: {e}")
            return False