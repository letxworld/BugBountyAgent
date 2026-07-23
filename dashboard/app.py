"""
BugBountyAgent - Dashboard Application
=======================================
Full web dashboard with live logs, target management, scan control,
findings viewer, chain builder, and report generator.
"""

import os
import sys
import json
import time
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import get_config
from core.agent import BugBountyAgent
from core.system import SystemController
from core.tools import ToolManager
from core.state import StateManager
from core.utils import get_timestamp, log_info, log_error, log_warning

# ============================================================
# Flask App Initialization
# ============================================================

app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)

app.config['SECRET_KEY'] = 'bugbounty-secret-key-change-in-production'
app.config['DEBUG'] = True

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=False, engineio_logger=False)

# ============================================================
# Global State
# ============================================================

config = get_config()
agent = BugBountyAgent(config)
system = SystemController(config)
tools = ToolManager(config)
state = StateManager(config)

active_connections = {}
scan_callbacks = {}

# ============================================================
# Routes - Pages
# ============================================================

@app.route('/')
def index():
    """Main dashboard."""
    return render_template('index.html')

@app.route('/targets')
def targets_page():
    """Targets management page."""
    return render_template('targets.html')

@app.route('/findings')
def findings_page():
    """Findings viewer page."""
    return render_template('findings.html')

@app.route('/chains')
def chains_page():
    """Chains builder page."""
    return render_template('chains.html')

# ============================================================
# API Routes - System
# ============================================================

@app.route('/api/status')
def api_status():
    """Get system status."""
    try:
        status = agent.get_status()
        stats = state.get_statistics()
        tool_status = tools.check_all_tools()
        
        return jsonify({
            'status': 'running',
            'agent': status,
            'knowledge_base': stats,
            'tools': {
                'installed': sum(1 for t in tool_status.values() if t.installed),
                'total': len(tool_status),
                'details': {k: {'installed': v.installed, 'version': v.version} for k, v in tool_status.items()}
            },
            'timestamp': get_timestamp()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/info')
def api_system_info():
    """Get system information."""
    try:
        info = system.get_system_info()
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/clean', methods=['POST'])
def api_system_clean():
    """Clean up old data."""
    try:
        data = request.get_json() or {}
        days = data.get('days', 30)
        result = system.cleanup_old_data(days)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API Routes - Targets
# ============================================================

@app.route('/api/targets')
def api_targets():
    """List all targets."""
    try:
        targets = agent.list_targets()
        return jsonify({'targets': targets})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets', methods=['POST'])
def api_add_target():
    """Add a target."""
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'URL required'}), 400
        
        target_id = agent.add_target(url)
        return jsonify({
            'success': True,
            'target_id': target_id,
            'url': url
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<target_id>', methods=['DELETE'])
def api_remove_target(target_id):
    """Remove a target."""
    try:
        success = agent.remove_target(target_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<target_id>')
def api_get_target(target_id):
    """Get target details."""
    try:
        target = agent.get_target(target_id)
        if target:
            return jsonify(target)
        return jsonify({'error': 'Target not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API Routes - Scans
# ============================================================

@app.route('/api/targets/<target_id>/scan', methods=['POST'])
def api_start_scan(target_id):
    """Start a scan on a target."""
    try:
        data = request.get_json() or {}
        scan_type = data.get('type', 'full')
        
        def callback(update):
            # This will be handled via WebSocket
            socketio.emit('scan_update', update)
        
        scan_id = agent.scan(target_id, scan_type)
        
        if scan_id:
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'target_id': target_id,
                'type': scan_type
            })
        return jsonify({'error': 'Failed to start scan'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<scan_id>')
def api_get_scan(scan_id):
    """Get scan details."""
    try:
        result = agent.get_scan_result(scan_id)
        if result:
            return jsonify({
                'scan_id': scan_id,
                'target_id': result.target_id,
                'findings': len(result.findings),
                'chains': len(result.chains),
                'duration': result.duration,
                'report_path': result.report_path
            })
        return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<scan_id>/stop', methods=['POST'])
def api_stop_scan(scan_id):
    """Stop a running scan."""
    try:
        success = agent.stop_scan(scan_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API Routes - Findings
# ============================================================

@app.route('/api/findings')
def api_findings():
    """Get findings with filters."""
    try:
        target_id = request.args.get('target')
        limit = request.args.get('limit', 100, type=int)
        
        findings = agent.get_findings(target_id)
        
        # Apply limit
        findings = findings[:limit]
        
        return jsonify({
            'findings': findings,
            'total': len(findings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/<finding_id>')
def api_get_finding(finding_id):
    """Get a specific finding."""
    try:
        finding = agent.get_finding(finding_id)
        if finding:
            return jsonify(finding)
        return jsonify({'error': 'Finding not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/statistics')
def api_findings_statistics():
    """Get finding statistics."""
    try:
        findings = agent.get_findings()
        
        stats = {
            'total': len(findings),
            'by_severity': {},
            'by_type': {}
        }
        
        for f in findings:
            severity = f.get('severity', 'info')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            f_type = f.get('type', 'unknown')
            stats['by_type'][f_type] = stats['by_type'].get(f_type, 0) + 1
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API Routes - Chains
# ============================================================

@app.route('/api/chains')
def api_chains():
    """Get attack chains."""
    try:
        target_id = request.args.get('target')
        chains = agent.get_chains(target_id)
        return jsonify({
            'chains': chains,
            'total': len(chains)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API Routes - Reports
# ============================================================

@app.route('/api/reports/<scan_id>')
def api_get_report(scan_id):
    """Get scan report."""
    try:
        result = agent.get_scan_result(scan_id)
        if result and result.report_path:
            return send_file(
                result.report_path,
                as_attachment=True,
                download_name=f'report_{scan_id}.json'
            )
        return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<scan_id>/generate', methods=['POST'])
def api_generate_report(scan_id):
    """Generate a report for a scan."""
    try:
        data = request.get_json() or {}
        format_type = data.get('format', 'json')
        
        result = agent.get_scan_result(scan_id)
        if not result:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Generate report (implemented in reporter)
        from core.reporter import Reporter
        reporter = Reporter(config)
        
        target = agent.get_target(result.target_id)
        if not target:
            return jsonify({'error': 'Target not found'}), 404
        
        report_path = reporter.generate(
            target['url'],
            result.findings,
            result.chains,
            format_type
        )
        
        return jsonify({
            'success': True,
            'report_path': report_path,
            'format': format_type
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# API Routes - Tools
# ============================================================

@app.route('/api/tools')
def api_tools():
    """List security tools."""
    try:
        tool_status = tools.check_all_tools()
        return jsonify({
            'tools': {
                name: {
                    'installed': info.installed,
                    'version': info.version,
                    'path': info.path,
                    'enabled': info.enabled
                }
                for name, info in tool_status.items()
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/<tool_name>/install', methods=['POST'])
def api_install_tool(tool_name):
    """Install a tool."""
    try:
        success = tools.install_tool(tool_name)
        return jsonify({
            'success': success,
            'tool': tool_name
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# WebSocket Events
# ============================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    client_id = request.sid
    active_connections[client_id] = {'connected_at': get_timestamp()}
    log_info(f"Dashboard client connected: {client_id}")
    emit('connected', {'status': 'ok', 'message': 'Connected to BugBountyAgent'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    client_id = request.sid
    if client_id in active_connections:
        del active_connections[client_id]
    log_info(f"Dashboard client disconnected: {client_id}")

@socketio.on('get_status')
def handle_get_status():
    """Send status update."""
    try:
        status = agent.get_status()
        stats = state.get_statistics()
        tool_status = tools.check_all_tools()
        
        emit('status_update', {
            'agent': status,
            'knowledge_base': stats,
            'tools': {
                'installed': sum(1 for t in tool_status.values() if t.installed),
                'total': len(tool_status)
            },
            'timestamp': get_timestamp()
        })
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('start_scan')
def handle_start_scan(data):
    """Start a scan from dashboard."""
    try:
        target_id = data.get('target_id')
        scan_type = data.get('type', 'full')
        
        if not target_id:
            emit('error', {'message': 'target_id required'})
            return
        
        def callback(update):
            emit('scan_update', update)
        
        scan_id = agent.scan(target_id, scan_type)
        
        if scan_id:
            emit('scan_started', {
                'scan_id': scan_id,
                'target_id': target_id,
                'status': 'running'
            })
        else:
            emit('error', {'message': 'Failed to start scan'})
            
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('stop_scan')
def handle_stop_scan(data):
    """Stop a running scan."""
    try:
        scan_id = data.get('scan_id')
        if not scan_id:
            emit('error', {'message': 'scan_id required'})
            return
        
        success = agent.stop_scan(scan_id)
        emit('scan_stopped', {
            'scan_id': scan_id,
            'success': success
        })
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('add_target')
def handle_add_target(data):
    """Add a target from dashboard."""
    try:
        url = data.get('url')
        if not url:
            emit('error', {'message': 'URL required'})
            return
        
        target_id = agent.add_target(url)
        emit('target_added', {
            'target_id': target_id,
            'url': url
        })
        emit('log_message', {
            'level': 'success',
            'message': f'🎯 Target added: {url}',
            'timestamp': get_timestamp()
        })
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('refresh_targets')
def handle_refresh_targets():
    """Refresh targets list."""
    try:
        targets = agent.list_targets()
        emit('targets_updated', {'targets': targets})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('log_message')
def handle_log_message(data):
    """Handle manual log message."""
    emit('log_message', {
        'level': data.get('level', 'info'),
        'message': data.get('message', ''),
        'timestamp': get_timestamp()
    })

# ============================================================
# Dashboard Runner
# ============================================================

def run_dashboard(host='0.0.0.0', port=5000, debug=True):
    """Run the dashboard server."""
    print(f"📡 BugBountyAgent Dashboard")
    print(f"   Host: {host}")
    print(f"   Port: {port}")
    print(f"   Debug: {debug}")
    print()
    print(f"🌐 Access at: http://localhost:{port}")
    print()
    print("Press Ctrl+C to stop")
    print()
    
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)

if __name__ == '__main__':
    run_dashboard()