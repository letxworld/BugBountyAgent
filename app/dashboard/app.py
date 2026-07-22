"""
BugBountyAgent - Dashboard Application
=======================================
This is the main Flask application that serves the dashboard UI and API.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_config, log_info, log_error, log_warning, get_timestamp
from app.agents.bug_hunter import BugHunter
from app.knowledge import KnowledgeBase
from app.system import SystemController

# ============================================================
# Flask App Initialization
# ============================================================

app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)

app.config['SECRET_KEY'] = get_config('dashboard.secret_key', 'dev-secret-key-change-me')
app.config['DEBUG'] = get_config('dashboard.debug', True)

# Enable CORS
CORS(app)

# Initialize SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    logger=False,
    engineio_logger=False
)

# ============================================================
# Global State
# ============================================================

# Initialize components
agent = BugHunter()
knowledge_base = KnowledgeBase()
system = SystemController()

# Store active socket connections
active_connections = {}

# ============================================================
# Routes
# ============================================================

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    """Get system status."""
    try:
        status = {
            'status': 'running',
            'agent': agent.get_status(),
            'system': system.get_system_info(),
            'knowledge_base': knowledge_base.get_statistics(),
            'timestamp': get_timestamp()
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets')
def api_targets():
    """List all targets."""
    try:
        targets = agent.list_targets()
        return jsonify({
            'targets': [{
                'id': t.id,
                'url': t.url,
                'status': t.status,
                'findings': len(t.findings),
                'start_time': t.start_time,
                'end_time': t.end_time
            } for t in targets]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets', methods=['POST'])
def api_add_target():
    """Add a new target."""
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        scope = data.get('scope', [url])
        exclude = data.get('exclude', [])
        
        target_id = agent.add_target(url, scope, exclude)
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

@app.route('/api/targets/<target_id>/scan', methods=['POST'])
def api_start_scan(target_id):
    """Start a scan on a target."""
    try:
        data = request.get_json() or {}
        scan_type = data.get('type', 'full')
        
        scan_id = agent.start_scan(target_id, scan_type)
        if not scan_id:
            return jsonify({'error': 'Failed to start scan'}), 400
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'target_id': target_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<scan_id>')
def api_get_scan(scan_id):
    """Get scan results."""
    try:
        result = agent.get_scan_result(scan_id)
        if not result:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify({
            'scan_id': scan_id,
            'findings': len(result.findings),
            'chains': len(result.chains),
            'summary': result.summary,
            'duration': result.duration,
            'report_path': result.report_path
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings')
def api_findings():
    """Get all findings."""
    try:
        limit = request.args.get('limit', 100, type=int)
        target = request.args.get('target', None)
        
        if target:
            findings = knowledge_base.get_findings_by_target(target, limit)
        else:
            findings = knowledge_base.get_all_findings(limit)
        
        return jsonify({
            'findings': [{
                'id': f.id,
                'target': f.target,
                'type': f.type,
                'severity': f.severity,
                'description': f.description[:200] + '...' if len(f.description) > 200 else f.description,
                'timestamp': f.timestamp
            } for f in findings]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings/<finding_id>')
def api_get_finding(finding_id):
    """Get a specific finding."""
    try:
        finding = knowledge_base.get_finding(finding_id)
        if not finding:
            return jsonify({'error': 'Finding not found'}), 404
        
        return jsonify({
            'id': finding.id,
            'target': finding.target,
            'type': finding.type,
            'severity': finding.severity,
            'description': finding.description,
            'reproduction_steps': finding.reproduction_steps,
            'remediation': finding.remediation,
            'cvss_score': finding.cvss_score,
            'cve_id': finding.cve_id,
            'url': finding.url,
            'payload': finding.payload,
            'timestamp': finding.timestamp
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chains')
def api_chains():
    """Get attack chains."""
    try:
        target = request.args.get('target', None)
        
        if target:
            chains = knowledge_base.get_chains_by_target(target)
        else:
            # Get all chains (limited)
            chains = []
        
        return jsonify({
            'chains': [{
                'id': c.id,
                'name': c.name,
                'target': c.target,
                'severity': c.severity,
                'steps': len(c.steps),
                'findings': len(c.findings),
                'completed': c.completed,
                'timestamp': c.timestamp
            } for c in chains[:50]]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics')
def api_statistics():
    """Get knowledge base statistics."""
    try:
        stats = knowledge_base.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<scan_id>')
def api_get_report(scan_id):
    """Download a report."""
    try:
        result = agent.get_scan_result(scan_id)
        if not result or not result.report_path:
            return jsonify({'error': 'Report not found'}), 404
        
        return send_file(
            result.report_path,
            as_attachment=True,
            download_name=f"report_{scan_id}.json"
        )
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

@app.route('/api/config')
def api_get_config():
    """Get current configuration."""
    try:
        config = get_config()
        # Remove sensitive data
        sensitive_keys = ['api_key', 'password', 'secret', 'token']
        def clean_config(obj):
            if isinstance(obj, dict):
                return {k: '***' if any(s in k.lower() for s in sensitive_keys) else clean_config(v) 
                        for k, v in obj.items()}
            return obj
        
        return jsonify(clean_config(config))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# SocketIO Events
# ============================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    client_id = request.sid
    active_connections[client_id] = {
        'connected_at': get_timestamp(),
        'ip': request.remote_addr
    }
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
    """Send status to client."""
    try:
        status = {
            'agent': agent.get_status(),
            'system': system.get_system_info(),
            'knowledge_base': knowledge_base.get_statistics(),
            'timestamp': get_timestamp()
        }
        emit('status_update', status)
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
        
        scan_id = agent.start_scan(target_id, scan_type, callback)
        
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

@socketio.on('get_findings')
def handle_get_findings(data):
    """Get findings via WebSocket."""
    try:
        target = data.get('target')
        limit = data.get('limit', 100)
        
        if target:
            findings = knowledge_base.get_findings_by_target(target, limit)
        else:
            findings = knowledge_base.get_all_findings(limit)
        
        emit('findings_update', {
            'findings': [{
                'id': f.id,
                'target': f.target,
                'type': f.type,
                'severity': f.severity,
                'description': f.description[:200] + '...' if len(f.description) > 200 else f.description,
                'timestamp': f.timestamp
            } for f in findings]
        })
    except Exception as e:
        emit('error', {'message': str(e)})

# ============================================================
# Create App Function
# ============================================================

def create_app():
    """Create and configure the Flask app."""
    return app

def run_dashboard(host=None, port=None, debug=None):
    """Run the dashboard server."""
    host = host or get_config('dashboard.host', '0.0.0.0')
    port = port or get_config('dashboard.port', 5000)
    debug = debug if debug is not None else get_config('dashboard.debug', True)
    
    log_info(f"Starting dashboard at http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug)

# ============================================================
# Main Entry Point
# ============================================================

if __name__ == '__main__':
    run_dashboard()