"""
BugBountyAgent - Dashboard Socket Handlers
============================================
WebSocket handlers for real-time communication.
"""

from flask_socketio import emit
from dashboard.app import socketio, get_agent


@socketio.on('connect')
def handle_connect():
    print("[SOCKET] Client connected")
    emit('connected', {'status': 'ok'})


@socketio.on('disconnect')
def handle_disconnect():
    print("[SOCKET] Client disconnected")


@socketio.on('get_status')
def handle_get_status():
    try:
        agent = get_agent()
        status = agent.get_status()
        emit('status_update', {'agent': status})
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
        emit('log_message', {
            'level': 'success',
            'message': f'🎯 Target added: {url}'
        })
    except Exception as e:
        emit('error', {'message': str(e)})


@socketio.on('refresh_targets')
def handle_refresh_targets():
    try:
        agent = get_agent()
        targets = agent.list_targets()
        emit('targets_updated', {'targets': targets})
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
        else:
            emit('error', {'message': 'Failed to start scan'})
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
        else:
            emit('error', {'message': 'Target not found'})
    except Exception as e:
        emit('error', {'message': str(e)})


def register_socket_handlers(socketio_app):
    pass
