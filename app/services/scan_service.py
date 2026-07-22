"""
BugBountyAgent - Scan Service
================================
This service orchestrates scan execution, managing the entire scan lifecycle.
"""

import os
import json
import time
import threading
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass

from app.core import get_config, log_info, log_error, log_warning, log_debug, get_timestamp
from app.models import Target, Scan, Finding, Chain, Profile
from app.agents.bug_hunter import BugHunter
from app.knowledge import KnowledgeBase
from app.system import SystemController
from app.learners import ChainManager


@dataclass
class ScanContext:
    """Context for a running scan."""
    scan_id: str
    target_id: str
    scan_type: str
    config: Dict[str, Any]
    start_time: float
    status: str  # running, completed, failed, paused
    progress: float
    current_stage: str
    findings: List[Finding]
    chains: List[Chain]
    callback: Optional[Callable] = None


class ScanService:
    """
    Service for orchestrating scan execution.
    Manages the entire scan lifecycle from start to completion.
    """
    
    def __init__(self):
        self.agent = BugHunter()
        self.kb = KnowledgeBase()
        self.system = SystemController()
        self.chain_manager = ChainManager()
        self.running_scans: Dict[str, ScanContext] = {}
        self.scan_threads: Dict[str, threading.Thread] = {}
        
        log_info("ScanService initialized")
    
    # ============================================================
    # Scan Lifecycle Management
    # ============================================================
    
    def start_scan(self, target_id: str, scan_type: str = 'full', 
                   config: Dict[str, Any] = None,
                   callback: Optional[Callable] = None) -> Optional[str]:
        """
        Start a new scan.
        
        Args:
            target_id: Target ID to scan
            scan_type: Type of scan (quick, full, recon, custom)
            config: Custom scan configuration
            callback: Progress callback function
            
        Returns:
            Optional[str]: Scan ID if started, None otherwise
        """
        # Validate target
        target = self.agent.get_target(target_id)
        if not target:
            log_error(f"Target not found: {target_id}")
            return None
        
        # Check if target is already being scanned
        for scan_id, context in self.running_scans.items():
            if context.target_id == target_id and context.status == 'running':
                log_warning(f"Target {target_id} is already being scanned")
                return None
        
        # Create scan record
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target_id,
            name=f"{scan_type}_scan_{get_timestamp()}",
            type=scan_type,
            status='pending',
            config=config or {},
            started_by='user'
        )
        
        # Save to database (implement when DB is ready)
        # scan.save()
        
        # Create scan context
        context = ScanContext(
            scan_id=scan.id,
            target_id=target_id,
            scan_type=scan_type,
            config=config or {},
            start_time=time.time(),
            status='pending',
            progress=0.0,
            current_stage='initializing',
            findings=[],
            chains=[],
            callback=callback
        )
        
        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(context,)
        )
        thread.daemon = True
        thread.start()
        
        self.running_scans[context.scan_id] = context
        self.scan_threads[context.scan_id] = thread
        
        log_info(f"Scan started: {scan.id} for target {target.url}")
        self._emit_update(context, f"🚀 Scan started for {target.url}")
        
        return scan.id
    
    def _run_scan(self, context: ScanContext):
        """Execute the scan (runs in background thread)."""
        context.status = 'running'
        self._emit_update(context, "🔍 Scan is running...")
        
        try:
            # Phase 1: Reconnaissance
            context.current_stage = 'reconnaissance'
            context.progress = 0.1
            self._emit_update(context, "🔍 Phase 1: Reconnaissance")
            self._run_reconnaissance(context)
            
            # Phase 2: Vulnerability Scanning
            context.current_stage = 'vulnerability_scanning'
            context.progress = 0.3
            self._emit_update(context, "🔬 Phase 2: Vulnerability Scanning")
            self._run_vulnerability_scanning(context)
            
            # Phase 3: Active Testing (if not in watch mode)
            if self.agent.mode in ['full', 'hybrid']:
                context.current_stage = 'active_testing'
                context.progress = 0.6
                self._emit_update(context, "⚡ Phase 3: Active Testing")
                self._run_active_testing(context)
            
            # Phase 4: Chain Building
            context.current_stage = 'chain_building'
            context.progress = 0.8
            self._emit_update(context, "🔗 Phase 4: Building Attack Chains")
            self._build_chains(context)
            
            # Phase 5: Reporting
            context.current_stage = 'reporting'
            context.progress = 0.95
            self._emit_update(context, "📄 Phase 5: Generating Report")
            self._generate_report(context)
            
            # Complete
            context.status = 'completed'
            context.progress = 1.0
            self._emit_update(context, f"✅ Scan complete! Found {len(context.findings)} findings")
            
        except Exception as e:
            context.status = 'failed'
            log_error(f"Scan failed: {e}")
            self._emit_update(context, f"❌ Scan failed: {e}")
        
        finally:
            self._save_results(context)
            self._cleanup(context)
    
    # ============================================================
    # Scan Phases
    # ============================================================
    
    def _run_reconnaissance(self, context: ScanContext):
        """Run reconnaissance phase."""
        target = self.agent.get_target(context.target_id)
        if not target:
            return
        
        # Subdomain discovery
        self._emit_update(context, "   📋 Discovering subdomains...")
        subdomains = self.agent._discover_subdomains(target.url)
        if subdomains:
            context.findings.extend(self._create_subdomain_findings(target, subdomains))
            self._emit_update(context, f"   ✅ Found {len(subdomains)} subdomains")
        
        # Port scanning
        self._emit_update(context, "   🔌 Scanning ports...")
        ports = self.agent._scan_ports(target.url)
        if ports:
            self._emit_update(context, f"   ✅ Found {len(ports)} open ports")
        
        # Technology detection
        self._emit_update(context, "   🏷️ Detecting technologies...")
        tech = self.agent._detect_technologies(target.url)
        if tech:
            self._emit_update(context, f"   ✅ Detected: {', '.join(tech.keys())}")
    
    def _run_vulnerability_scanning(self, context: ScanContext):
        """Run vulnerability scanning phase."""
        target = self.agent.get_target(context.target_id)
        if not target:
            return
        
        # Run Nuclei
        self._emit_update(context, "   🔬 Running Nuclei scan...")
        nuclei_findings = self.agent._run_nuclei(target.url)
        context.findings.extend(nuclei_findings)
        if nuclei_findings:
            self._emit_update(context, f"   ✅ Found {len(nuclei_findings)} vulnerabilities via Nuclei")
        
        # Run Nmap scripts
        self._emit_update(context, "   🔍 Running Nmap scripts...")
        nmap_findings = self.agent._run_nmap_scripts(target.url)
        context.findings.extend(nmap_findings)
        
        # Run Nikto
        self._emit_update(context, "   🌐 Running Nikto...")
        nikto_findings = self.agent._run_nikto(target.url)
        context.findings.extend(nikto_findings)
    
    def _run_active_testing(self, context: ScanContext):
        """Run active testing phase (requires browser)."""
        if not self.agent.browser:
            self._emit_update(context, "   ⚠️ Browser not available. Skipping active testing.")
            return
        
        # Navigate to target
        target = self.agent.get_target(context.target_id)
        if not target:
            return
        
        self.agent.browser.navigate(target.url)
        
        # Analyze page
        page_findings = self.agent._analyze_page(target.url)
        context.findings.extend(page_findings)
        
        # Test forms
        form_findings = self.agent._test_forms()
        context.findings.extend(form_findings)
    
    def _build_chains(self, context: ScanContext):
        """Build attack chains from findings."""
        target = self.agent.get_target(context.target_id)
        if not target:
            return
        
        chains = self.chain_manager.build_chains(target.url)
        context.chains.extend(chains)
        
        if chains:
            self._emit_update(context, f"   ✅ Built {len(chains)} attack chains")
    
    def _generate_report(self, context: ScanContext):
        """Generate a report from scan results."""
        target = self.agent.get_target(context.target_id)
        if not target:
            return
        
        report_data = {
            'target': target.url,
            'scan_id': context.scan_id,
            'scan_type': context.scan_type,
            'start_time': datetime.fromtimestamp(context.start_time).isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration': time.time() - context.start_time,
            'total_findings': len(context.findings),
            'findings': [f.to_dict() for f in context.findings],
            'chains': [c.to_dict() for c in context.chains]
        }
        
        # Save report
        report_dir = get_config('reports.save_dir', './data/reports')
        os.makedirs(report_dir, exist_ok=True)
        
        report_path = f"{report_dir}/scan_{context.scan_id}_{get_timestamp()}.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        log_info(f"Report saved: {report_path}")
        self._emit_update(context, f"📄 Report saved: {report_path}")
    
    # ============================================================
    # Helper Methods
    # ============================================================
    
    def _create_subdomain_findings(self, target: Target, subdomains: List[str]) -> List[Finding]:
        """Create findings from discovered subdomains."""
        findings = []
        for subdomain in subdomains[:10]:  # Limit to 10
            finding = Finding(
                id=str(uuid.uuid4()),
                target_id=target.id,
                title=f"Discovered Subdomain: {subdomain}",
                type="subdomain_discovery",
                severity="info",
                description=f"Subdomain discovered during reconnaissance: {subdomain}",
                url=subdomain,
                reproduction_steps=f"1. Run subdomain discovery on {target.url}",
                remediation="Review if subdomain should be in scope"
            )
            findings.append(finding)
        return findings
    
    def _emit_update(self, context: ScanContext, message: str):
        """Emit an update through the callback."""
        if context.callback:
            try:
                context.callback({
                    'type': 'scan_update',
                    'scan_id': context.scan_id,
                    'stage': context.current_stage,
                    'progress': context.progress,
                    'message': message,
                    'timestamp': get_timestamp()
                })
            except Exception as e:
                log_debug(f"Callback error: {e}")
    
    def _save_results(self, context: ScanContext):
        """Save scan results to database."""
        # This will be implemented when the database is fully integrated
        pass
    
    def _cleanup(self, context: ScanContext):
        """Clean up scan resources."""
        if context.scan_id in self.running_scans:
            del self.running_scans[context.scan_id]
        if context.scan_id in self.scan_threads:
            del self.scan_threads[context.scan_id]
    
    # ============================================================
    # Public Methods
    # ============================================================
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a scan."""
        context = self.running_scans.get(scan_id)
        if not context:
            return None
        
        return {
            'scan_id': context.scan_id,
            'target_id': context.target_id,
            'status': context.status,
            'progress': context.progress,
            'current_stage': context.current_stage,
            'findings_found': len(context.findings),
            'chains_found': len(context.chains),
            'duration': time.time() - context.start_time
        }
    
    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan."""
        context = self.running_scans.get(scan_id)
        if not context:
            return False
        
        context.status = 'stopped'
        self._emit_update(context, f"⏹️ Scan stopped by user")
        log_info(f"Scan stopped: {scan_id}")
        return True
    
    def get_running_scans(self) -> List[Dict[str, Any]]:
        """Get all running scans."""
        return [{
            'scan_id': context.scan_id,
            'target_id': context.target_id,
            'status': context.status,
            'progress': context.progress,
            'current_stage': context.current_stage,
            'findings_found': len(context.findings),
            'duration': time.time() - context.start_time
        } for context in self.running_scans.values() if context.status == 'running']