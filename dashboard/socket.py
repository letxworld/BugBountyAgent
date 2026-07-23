"""
BugBountyAgent - Dashboard Socket Handlers
============================================
WebSocket handlers for real-time communication.
"""

from flask_socketio import emit
from dashboard.app import socketio, agent, state, tools, system
from core.utils import get_timestamp, log_info, log_error


# ============================================================
# Connection Events
# ============================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    log_info("Dashboard client connected")
    emit('connected', {
        'status': 'ok',
        'message': 'Connected to BugBountyAgent',
        'timestamp': get_timestamp()
    })
    emit('log_message', {
        'level': 'info',
        'message': '🟢 Connected to BugBountyAgent server',
        'timestamp': get_timestamp()
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    log_info("Dashboard client disconnected")


# ============================================================
# Status Events
# ============================================================

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


@socketio.on('ping')
def handle_ping():
    """Handle ping request."""
    emit('pong', {'timestamp': get_timestamp()})


# ============================================================
# Target Events
# ============================================================

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
            'url': url,
            'timestamp': get_timestamp()
        })
        emit('log_message', {
            'level': 'success',
            'message': f'🎯 Target added: {url} (ID: {target_id})',
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


@socketio.on('remove_target')
def handle_remove_target(data):
    """Remove a target."""
    try:
        target_id = data.get('target_id')
        if not target_id:
            emit('error', {'message': 'target_id required'})
            return
        
        success = agent.remove_target(target_id)
        if success:
            emit('target_removed', {'target_id': target_id})
            emit('log_message', {
                'level': 'info',
                'message': f'🗑️ Target removed: {target_id}',
                'timestamp': get_timestamp()
            })
        else:
            emit('error', {'message': 'Target not found'})
    except Exception as e:
        emit('error', {'message': str(e)})


# ============================================================
# Scan Events
# ============================================================

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
                'type': scan_type,
                'status': 'running',
                'timestamp': get_timestamp()
            })
            emit('log_message', {
                'level': 'info',
                'message': f'🚀 Scan started: {scan_id} on {target_id}',
                'timestamp': get_timestamp()
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
        if success:
            emit('scan_stopped', {
                'scan_id': scan_id,
                'success': True,
                'timestamp': get_timestamp()
            })
            emit('log_message', {
                'level': 'warning',
                'message': f'⏹️ Scan stopped: {scan_id}',
                'timestamp': get_timestamp()
            })
        else:
            emit('error', {'message': 'Scan not found or not running'})
    except Exception as e:
        emit('error', {'message': str(e)})


# ============================================================
# Finding Events
# ============================================================

@socketio.on('get_findings')
def handle_get_findings(data):
    """Get findings with filters."""
    try:
        target_id = data.get('target')
        limit = data.get('limit', 100)
        
        findings = agent.get_findings(target_id)
        findings = findings[:limit]
        
        emit('findings_update', {
            'findings': findings,
            'total': len(findings),
            'timestamp': get_timestamp()
        })
    except Exception as e:
        emit('error', {'message': str(e)})


@socketio.on('get_finding_details')
def handle_get_finding_details(data):
    """Get finding details."""
    try:
        finding_id = data.get('finding_id')
        if not finding_id:
            emit('error', {'message': 'finding_id required'})
            return
        
        finding = agent.get_finding(finding_id)
        if finding:
            emit('finding_details', finding)
        else:
            emit('error', {'message': 'Finding not found'})
    except Exception as e:
        emit('error', {'message': str(e)})


# ============================================================
# Chain Events
# ============================================================

@socketio.on('get_chains')
def handle_get_chains(data):
    """Get attack chains."""
    try:
        target_id = data.get('target')
        chains = agent.get_chains(target_id)
        
        emit('chains_update', {
            'chains': chains,
            'total': len(chains),
            'timestamp': get_timestamp()
        })
    except Exception as e:
        emit('error', {'message': str(e)})


# ============================================================
# Report Events
# ============================================================

@socketio.on('generate_report')
def handle_generate_report(data):
    """Generate a report."""
    try:
        scan_id = data.get('scan_id')
        format_type = data.get('format', 'json')
        
        if not scan_id:
            emit('error', {'message': 'scan_id required'})
            return
        
        result = agent.get_scan_result(scan_id)
        if not result:
            emit('error', {'message': 'Scan not found'})
            return
        
        # Generate report using reporter
        from core.reporter import Reporter
        from core.config import get_config
        
        config = get_config()
        reporter = Reporter(config)
        
        target = agent.get_target(result.target_id)
        if not target:
            emit('error', {'message': 'Target not found'})
            return
        
        report_path = reporter.generate(
            target['url'],
            result.findings,
            result.chains,
            format_type
        )
        
        emit('report_generated', {
            'scan_id': scan_id,
            'report_path': report_path,
            'format': format_type,
            'timestamp': get_timestamp()
        })
        emit('log_message', {
            'level': 'success',
            'message': f'📄 Report generated: {report_path}',
            'timestamp': get_timestamp()
        })
    except Exception as e:
        emit('error', {'message': str(e)})


# ============================================================
# Tool Events
# ============================================================

@socketio.on('get_tools')
def handle_get_tools():
    """Get tool status."""
    try:
        tool_status = tools.check_all_tools()
        emit('tools_update', {
            'tools': {
                name: {
                    'installed': info.installed,
                    'version': info.version,
                    'path': info.path,
                    'enabled': info.enabled
                }
                for name, info in tool_status.items()
            },
            'timestamp': get_timestamp()
        })
    except Exception as e:
        emit('error', {'message': str(e)})


@socketio.on('install_tool')
def handle_install_tool(data):
    """Install a tool."""
    try:
        tool_name = data.get('tool_name')
        if not tool_name:
            emit('error', {'message': 'tool_name required'})
            return
        
        emit('log_message', {
            'level': 'info',
            'message': f'🔧 Installing tool: {tool_name}...',
            'timestamp': get_timestamp()
        })
        
        success = tools.install_tool(tool_name)
        
        if success:
            emit('tool_installed', {
                'tool': tool_name,
                'success': True,
                'timestamp': get_timestamp()
            })
            emit('log_message', {
                'level': 'success',
                'message': f'✅ Tool installed: {tool_name}',
                'timestamp': get_timestamp()
            })
        else:
            emit('error', {'message': f'Failed to install: {tool_name}'})
    except Exception as e:
        emit('error', {'message': str(e)})


# ============================================================
# System Events
# ============================================================

@socketio.on('system_info')
def handle_system_info():
    """Get system information."""
    try:
        info = system.get_system_info()
        emit('system_info_update', info)
    except Exception as e:
        emit('error', {'message': str(e)})


@socketio.on('cleanup')
def handle_cleanup(data):
    """Clean up old data."""
    try:
        days = data.get('days', 30)
        
        emit('log_message', {
            'level': 'info',
            'message': f'🧹 Cleaning up data older than {days} days...',
            'timestamp': get_timestamp()
        })
        
        # This would need to be implemented in system
        emit('cleanup_complete', {
            'days': days,
            'timestamp': get_timestamp()
        })
    except Exception as e:
        emit('error', {'message': str(e)})


# ============================================================
# Register Function
# ============================================================

def register_socket_handlers(socketio_app):
    """Register socket handlers with socketio app."""
    # This is a compatibility function
    # Handlers are already registered via decorators
    pass