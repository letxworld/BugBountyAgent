"""
BugBountyAgent - Dashboard Application
=======================================
Fully functional dashboard with real-time updates.
"""

import os
import sys
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import get_config
from core.agent import BugBountyAgent
from core.tools import ToolManager
from core.utils import get_timestamp

# ============================================================
# Flask App
# ============================================================

app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)

app.config['SECRET_KEY'] = 'bugbounty-secret-key'
app.config['DEBUG'] = True

CORS(app)

# Use threading to avoid eventlet issues
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=False, engineio_logger=False)

# ============================================================
# SINGLETON: Only ONE instance of everything
# ============================================================

_agent = None
_tools = None
_initialized = False

def get_agent():
    """Get the SINGLE agent instance (Singleton pattern)."""
    global _agent
    if _agent is None:
        print("🐞 Creating SINGLE agent instance...")
        config = get_config()
        _agent = BugBountyAgent(config)
        _agent._socketio = socketio
        if hasattr(_agent, 'scanner') and hasattr(_agent.scanner, '_socketio'):
            _agent.scanner._socketio = socketio
    return _agent

def get_tools():
    """Get the SINGLE tools instance."""
    global _tools
    if _tools is None:
        _tools = ToolManager(get_config())
    return _tools

# ============================================================
# Routes - Pages
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/targets')
def targets_page():
    return render_template('targets.html')

@app.route('/findings')
def findings_page():
    return render_template('findings.html')

@app.route('/chains')
def chains_page():
    return render_template('chains.html')

# ============================================================
# API Routes
# ============================================================

@app.route('/api/status')
def api_status():
    try:
        agent = get_agent()
        status = agent.get_status()
        return jsonify({'status': 'running', 'agent': status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets', methods=['GET'])
def api_targets():
    try:
        agent = get_agent()
        targets = agent.list_targets()
        return jsonify({'targets': targets})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets', methods=['POST'])
def api_add_target():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'URL required'}), 400
        agent = get_agent()
        target_id = agent.add_target(url)
        return jsonify({'success': True, 'target_id': target_id, 'url': url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<target_id>', methods=['DELETE'])
def api_remove_target(target_id):
    try:
        agent = get_agent()
        success = agent.remove_target(target_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/targets/<target_id>/scan', methods=['POST'])
def api_start_scan(target_id):
    try:
        data = request.get_json() or {}
        scan_type = data.get('type', 'full')
        agent = get_agent()
        scan_id = agent.scan(target_id, scan_type)
        if scan_id:
            return jsonify({'success': True, 'scan_id': scan_id})
        return jsonify({'error': 'Failed to start scan'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings', methods=['GET'])
def api_findings():
    try:
        agent = get_agent()
        findings = agent.get_findings()
        return jsonify({'findings': findings, 'total': len(findings)})
    except Exception as e:
        return jsonify({'error': str(e), 'findings': []}), 500

@app.route('/api/findings/<finding_id>', methods=['GET'])
def api_get_finding(finding_id):
    try:
        agent = get_agent()
        finding = agent.get_finding(finding_id)
        if finding:
            return jsonify(finding)
        return jsonify({'error': 'Not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chains', methods=['GET'])
def api_chains():
    try:
        agent = get_agent()
        chains = agent.get_chains()
        return jsonify({'chains': chains, 'total': len(chains)})
    except Exception as e:
        return jsonify({'error': str(e), 'chains': []}), 500

@app.route('/api/tools', methods=['GET'])
def api_tools():
    try:
        tools = get_tools()
        tool_status = tools.check_all_tools()
        return jsonify({'tools': {
            name: {'installed': info.installed, 'version': info.version}
            for name, info in tool_status.items()
        }})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================
# SocketIO Events
# ============================================================

@socketio.on('connect')
def handle_connect():
    print("[SOCKET] Client connected")
    emit('log_message', {'level': 'info', 'message': '🟢 Connected to server', 'timestamp': get_timestamp()})

@socketio.on('disconnect')
def handle_disconnect():
    print("[SOCKET] Client disconnected")

@socketio.on('get_status')
def handle_get_status():
    try:
        agent = get_agent()
        emit('status_update', {'agent': agent.get_status()})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('refresh_targets')
def handle_refresh_targets():
    try:
        agent = get_agent()
        emit('targets_updated', {'targets': agent.list_targets()})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('get_findings')
def handle_get_findings(data):
    try:
        agent = get_agent()
        emit('findings_update', {'findings': agent.get_findings()})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('get_chains')
def handle_get_chains(data):
    try:
        agent = get_agent()
        emit('chains_update', {'chains': agent.get_chains()})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('add_target')
def handle_add_target(data):
    try:
        url = data.get('url')
        if not url:
            emit('error', {'message': 'URL required'})
            return
        agent = get_agent()
        target_id = agent.add_target(url)
        emit('target_added', {'target_id': target_id, 'url': url})
        emit('log_message', {'level': 'success', 'message': f'🎯 Target added: {url}', 'timestamp': get_timestamp()})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('remove_target')
def handle_remove_target(data):
    try:
        target_id = data.get('target_id')
        if not target_id:
            emit('error', {'message': 'target_id required'})
            return
        agent = get_agent()
        success = agent.remove_target(target_id)
        if success:
            emit('target_removed', {'target_id': target_id})
            emit('log_message', {'level': 'info', 'message': f'🗑️ Target removed', 'timestamp': get_timestamp()})
        else:
            emit('error', {'message': 'Target not found'})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('start_scan')
def handle_start_scan(data):
    try:
        target_id = data.get('target_id')
        if not target_id:
            emit('error', {'message': 'target_id required'})
            return
        agent = get_agent()
        scan_id = agent.scan(target_id, 'full')
        if scan_id:
            emit('scan_started', {'scan_id': scan_id, 'target_id': target_id})
            emit('log_message', {'level': 'info', 'message': f'🚀 Scan started: {scan_id}', 'timestamp': get_timestamp()})
        else:
            emit('error', {'message': 'Failed to start scan'})
    except Exception as e:
        emit('error', {'message': str(e)})

# ============================================================
# Run
# ============================================================

def create_app():
    return app

def run_dashboard(host='0.0.0.0', port=5000, debug=True):
    print("📡 BugBountyAgent Dashboard")
    print(f"   Host: {host}")
    print(f"   Port: {port}")
    print()
    print(f"🌐 Access at: http://localhost:{port}")
    print()
    print("Press Ctrl+C to stop")
    print()
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)

if __name__ == '__main__':
    run_dashboard()
