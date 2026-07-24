"""
BugBountyAgent - State Management
===================================
Save and load agent state for persistence across sessions.
"""

import os
import json
from typing import Dict, Any, Optional, List

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
        
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        print("💾 StateManager initialized")
    
    # ============================================================
    # Target Operations
    # ============================================================
    
    def save_target(self, target: Dict[str, Any]) -> bool:
        return self.db.save_target(target)
    
    def get_target(self, target_id: str) -> Optional[Dict]:
        return self.db.get_target(target_id)
    
    def get_all_targets(self) -> List[Dict]:
        return self.db.get_all_targets()
    
    def delete_target(self, target_id: str) -> bool:
        return self.db.delete_target(target_id)
    
    # ============================================================
    # Finding Operations
    # ============================================================
    
    def save_finding(self, finding: Dict[str, Any]) -> bool:
        return self.db.save_finding(finding)
    
    def get_findings_by_target(self, target_id: str) -> List[Dict]:
        return self.db.get_findings_by_target(target_id)
    
    def get_all_findings(self) -> List[Dict]:
        return self.db.get_all_findings()
    
    def delete_finding(self, finding_id: str) -> bool:
        return self.db.delete_finding(finding_id)
    
    def clear_findings(self) -> bool:
        return self.db.clear_findings()
    
    # ============================================================
    # Chain Operations
    # ============================================================
    
    def save_chain(self, chain: Dict[str, Any]) -> bool:
        return self.db.save_chain(chain)
    
    def get_chains_by_target(self, target_id: str) -> List[Dict]:
        return self.db.get_chains_by_target(target_id)

    def get_all_chains(self) -> List[Dict]:
        return self.db.get_all_chains()
    
    # ============================================================
    # Scan Operations
    # ============================================================
    
    def save_scan(self, scan: Dict[str, Any]) -> bool:
        return self.db.save_scan(scan)
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        return self.db.get_scan(scan_id)
    
    def get_scans_by_target(self, target_id: str) -> List[Dict]:
        return self.db.get_scans_by_target(target_id)
    
    # ============================================================
    # Statistics
    # ============================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        return self.db.get_statistics()

    def save_state(self, state: Dict[str, Any]) -> bool:
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"❌ Failed to save state: {e}")
            return False
    
    def clear_all(self) -> bool:
        try:
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
            return self.db.clear_findings()
        except Exception as e:
            print(f"❌ Failed to clear state: {e}")
            return False
        
    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding by ID."""
        return self.db.delete_finding(finding_id)
    
    def clear_findings(self) -> bool:
        """Clear all findings."""
        return self.db.clear_findings()