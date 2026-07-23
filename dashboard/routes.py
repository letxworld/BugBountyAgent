"""
BugBountyAgent - Dashboard Routes
===================================
Flask routes for the dashboard API.
"""

from flask import jsonify, request, send_file
from dashboard.app import app, agent, state, tools, system


# ============================================================
# API Routes - Status & System
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
                'total': len(tool_status)
            },
            'timestamp': __import__('core.utils').get_timestamp()
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


def register_routes(app):
    """Register routes with app (compatibility)."""
    pass