/**
 * BugBountyAgent - Complete Dashboard JavaScript
 */

const socket = io();

let state = {
    targets: [],
    findings: [],
    chains: [],
    scans: [],
    isScanning: false,
    currentPage: 'dashboard'
};

// ============================================================
// Connection Events
// ============================================================

socket.on('connect', () => {
    console.log('🟢 Connected to server');
    updateConnectionStatus('connected');
    addLog('info', '🟢 Connected to BugBountyAgent server');
    refreshAll();
});

socket.on('disconnect', () => {
    console.log('🔴 Disconnected from server');
    updateConnectionStatus('disconnected');
    addLog('error', '🔴 Disconnected from server');
});

socket.on('log_message', (data) => {
    addLog(data.level, data.message);
});

socket.on('status_update', (data) => {
    console.log('📊 Status update:', data);
    updateStats(data.agent);
});

socket.on('targets_updated', (data) => {
    console.log('🎯 Targets updated:', data);
    state.targets = data.targets || [];
    renderTargets();
    renderTargetsTable();
    updateStatsFromTargets();
});

socket.on('target_added', (data) => {
    console.log('✅ Target added:', data);
    showToast(`✅ Target added: ${data.url}`, 'success');
    addLog('success', `🎯 Target added: ${data.url}`);
    refreshAll();
});

socket.on('target_removed', (data) => {
    console.log('🗑️ Target removed:', data);
    showToast(`🗑️ Target removed`, 'info');
    refreshAll();
});

socket.on('findings_update', (data) => {
    console.log('🔍 Findings update:', data);
    state.findings = data.findings || [];
    renderFindings();
    renderFindingsTable();
    updateStatsFromFindings();
});

socket.on('chains_update', (data) => {
    console.log('🔗 Chains update:', data);
    state.chains = data.chains || [];
    renderChains();
    updateStatsFromChains();
});

socket.on('scan_started', (data) => {
    console.log('🚀 Scan started:', data);
    state.isScanning = true;
    showToast(`🚀 Scan started: ${data.scan_id}`, 'info');
    addLog('info', `🚀 Scan started: ${data.scan_id}`);
    updateConnectionStatus('scanning');
});

socket.on('scan_completed', (data) => {
    console.log('✅ Scan completed:', data);
    state.isScanning = false;
    showToast(`✅ Scan completed! Found ${data.findings || 0} findings`, 'success');
    addLog('success', `✅ Scan completed: ${data.findings || 0} findings`);
    updateConnectionStatus('connected');
    refreshAll();
});

socket.on('scan_stopped', (data) => {
    console.log('⏹️ Scan stopped:', data);
    state.isScanning = false;
    showToast(`⏹️ Scan stopped`, 'info');
    addLog('warning', `⏹️ Scan stopped: ${data.scan_id}`);
    updateConnectionStatus('connected');
    refreshAll();
});

socket.on('error', (data) => {
    console.error('❌ Error:', data);
    showToast(`❌ ${data.message}`, 'error');
    addLog('error', `❌ ${data.message}`);
});

// ============================================================
// Connection Status
// ============================================================

function updateConnectionStatus(status) {
    const dot = document.querySelector('#connectionStatus .status-dot');
    const text = document.querySelector('#connectionStatus .status-text');
    if (dot) {
        dot.className = 'status-dot ' + status;
    }
    if (text) {
        const labels = { connected: 'Connected', disconnected: 'Disconnected', scanning: 'Scanning...' };
        text.textContent = labels[status] || status;
    }
}

// ============================================================
// Stats
// ============================================================

function updateStats(agent) {
    if (!agent) return;
    const el = (id) => document.getElementById(id);
    if (el('statTargets')) el('statTargets').textContent = agent.targets || 0;
    if (el('statScans')) el('statScans').textContent = agent.running_scans || 0;
}

function updateStatsFromTargets() {
    const el = document.getElementById('statTargets');
    if (el) el.textContent = state.targets.length;
}

function updateStatsFromFindings() {
    const el = document.getElementById('statFindings');
    if (el) el.textContent = state.findings.length;
}

function updateStatsFromChains() {
    const el = document.getElementById('statChains');
    if (el) el.textContent = state.chains.length;
}

// ============================================================
// Logging
// ============================================================

function addLog(level, message) {
    const container = document.getElementById('logContainer');
    if (!container) return;
    
    const entry = document.createElement('div');
    entry.className = `log-entry log-${level}`;
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `<span class="log-time">[${time}]</span><span class="log-message">${message}</span>`;
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
    
    while (container.children.length > 500) {
        container.removeChild(container.firstChild);
    }
}

function clearLog() {
    const container = document.getElementById('logContainer');
    if (container) container.innerHTML = '';
    addLog('info', '🧹 Log cleared');
}

function exportLog() {
    const container = document.getElementById('logContainer');
    if (!container) return;
    
    const entries = container.querySelectorAll('.log-entry');
    let text = `BugBountyAgent Log Export\n${new Date().toISOString()}\n${'='.repeat(50)}\n\n`;
    entries.forEach(e => {
        const time = e.querySelector('.log-time')?.textContent || '';
        const msg = e.querySelector('.log-message')?.textContent || '';
        text += `${time} ${msg}\n`;
    });
    
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bugbounty_log_${new Date().toISOString().slice(0,10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('📤 Log exported', 'success');
}

// ============================================================
// Toast
// ============================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer') || (() => {
        const div = document.createElement('div');
        div.id = 'toastContainer';
        div.className = 'toast-container';
        document.body.appendChild(div);
        return div;
    })();
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(20px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ============================================================
// Targets
// ============================================================

function renderTargetsTable() {
    const tbody = document.getElementById('targetsTableBody');
    if (!tbody) return;
    
    if (!state.targets || state.targets.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No targets found. Add your first target!</td></tr>`;
        return;
    }
    
    tbody.innerHTML = state.targets.map(t => `
        <tr>
            <td><code>${t.id || 'N/A'}</code></td>
            <td><a href="${t.url || '#'}" target="_blank">${t.url || 'N/A'}</a></td>
            <td><span class="severity-badge severity-${t.status || 'pending'}">${t.status || 'pending'}</span></td>
            <td>${t.findings ? t.findings.length : 0}</td>
            <td>${t.added ? t.added.slice(0, 16) : 'N/A'}</td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="startScan('${t.id}')" ${state.isScanning ? 'disabled' : ''}>
                    ${state.isScanning ? '⏳' : '▶'} Scan
                </button>
                <button class="btn btn-sm btn-danger" onclick="removeTarget('${t.id}')">✕</button>
            </td>
        </tr>
    `).join('');
}

function renderTargets() {
    // Dashboard summary
    const el = document.getElementById('targetsSummary');
    if (el) {
        el.textContent = `${state.targets.length} targets`;
    }
}

// ============================================================
// Findings
// ============================================================

function renderFindings() {
    // Dashboard recent findings
    const tbody = document.getElementById('findingsTableBody');
    if (!tbody) return;
    
    if (!state.findings || state.findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No findings yet. Start a scan!</td></tr>`;
        return;
    }
    
    const recent = state.findings.slice(0, 10);
    tbody.innerHTML = recent.map(f => `
        <tr>
            <td><span class="severity-badge severity-${f.severity || 'info'}">${f.severity || 'info'}</span></td>
            <td>${f.title || 'Unknown'}</td>
            <td>${f.target || 'N/A'}</td>
            <td>${f.timestamp ? f.timestamp.slice(0, 16) : 'N/A'}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="deleteFinding('${f.id}')">🗑️</button>
            </td>
        </tr>
    `).join('');
}

function renderFindingsTable() {
    // Findings page full table
    const tbody = document.getElementById('findingsTableBody');
    if (!tbody) return;
    
    if (!state.findings || state.findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No findings yet. Start a scan!</td></tr>`;
        return;
    }
    
    tbody.innerHTML = state.findings.map(f => `
        <tr>
            <td><span class="severity-badge severity-${f.severity || 'info'}">${f.severity || 'info'}</span></td>
            <td>${f.title || 'Unknown'}</td>
            <td>${f.target || 'N/A'}</td>
            <td>${f.timestamp ? f.timestamp.slice(0, 16) : 'N/A'}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="deleteFinding('${f.id}')">🗑️</button>
            </td>
        </tr>
    `).join('');
    
    // Update statistics
    updateFindingStats();
}

function updateFindingStats() {
    const stats = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    state.findings.forEach(f => {
        stats.total++;
        const sev = f.severity?.toLowerCase() || 'info';
        if (sev === 'critical') stats.critical++;
        else if (sev === 'high') stats.high++;
        else if (sev === 'medium') stats.medium++;
        else if (sev === 'low') stats.low++;
        else stats.info++;
    });
    
    ['statTotal', 'statCritical', 'statHigh', 'statMedium', 'statLow', 'statInfo'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            const key = id.replace('stat', '').toLowerCase();
            el.textContent = stats[key] || 0;
        }
    });
}

function deleteFinding(findingId) {
    if (!confirm('Delete this finding?')) return;
    fetch(`/api/findings/${findingId}`, { method: 'DELETE' })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                showToast('🗑️ Finding deleted', 'success');
                refreshAll();
            } else {
                showToast('❌ Failed to delete finding', 'error');
            }
        })
        .catch(err => showToast('❌ Error: ' + err.message, 'error'));
}

// ============================================================
// Chains
// ============================================================

function renderChains() {
    const container = document.getElementById('chainsList');
    if (!container) return;
    
    if (!state.chains || state.chains.length === 0) {
        container.innerHTML = `<div class="text-center text-muted" style="padding:40px;">No attack chains found</div>`;
        return;
    }
    
    const el = document.getElementById('statTotal');
    if (el) el.textContent = state.chains.length;
    
    container.innerHTML = state.chains.map(c => `
        <div class="chain-card" style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:var(--radius); padding:16px 20px; margin-bottom:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <div style="display:flex; align-items:center; gap:12px;">
                        <span class="severity-badge severity-${c.severity || 'medium'}">${c.severity || 'medium'}</span>
                        <h4 style="color:var(--text-primary);">${c.name || 'Unknown Chain'}</h4>
                    </div>
                    <div style="color:var(--text-muted); font-size:13px; margin-top:4px;">
                        ${c.total_steps || c.steps?.length || 0} steps · ${c.findings?.length || 0} findings
                        ${c.completed ? '✅ Completed' : '⏳ In Progress'}
                    </div>
                </div>
                <div style="color:var(--text-muted); font-size:12px;">
                    ${c.timestamp ? c.timestamp.slice(0, 16) : ''}
                </div>
            </div>
        </div>
    `).join('');
}

// ============================================================
// Scans - Stop All
// ============================================================

function stopAllScans() {
    if (!confirm('Stop all running scans?')) return;
    fetch('/api/scans/stop-all', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                showToast('⏹️ All scans stopped', 'info');
                addLog('warning', '⏹️ All scans stopped by user');
                refreshAll();
            }
        })
        .catch(err => showToast('❌ Error: ' + err.message, 'error'));
}

// ============================================================
// Refresh All
// ============================================================

function refreshAll() {
    refreshStatus();
    refreshTargets();
    refreshFindings();
    refreshChains();
}

function refreshStatus() {
    socket.emit('get_status');
}

function refreshTargets() {
    socket.emit('refresh_targets');
}

function refreshFindings() {
    socket.emit('get_findings', {});
}

function refreshChains() {
    socket.emit('get_chains', {});
}

function refreshData() {
    console.log('🔄 Refreshing all data...');
    refreshAll();
}

// ============================================================
// Modal
// ============================================================

function showAddTarget() {
    const overlay = document.getElementById('modalOverlay');
    if (overlay) overlay.classList.add('active');
}

function closeModal() {
    const overlay = document.getElementById('modalOverlay');
    if (overlay) overlay.classList.remove('active');
}

function saveTarget() {
    const urlInput = document.getElementById('targetUrl');
    if (!urlInput) return;
    const url = urlInput.value.trim();
    if (!url) {
        showToast('⚠️ Please enter a URL', 'warning');
        return;
    }
    socket.emit('add_target', { url: url });
    closeModal();
    urlInput.value = '';
}

// ============================================================
// Scans
// ============================================================

function startScan(targetId) {
    if (!targetId) {
        showToast('⚠️ No target selected', 'warning');
        return;
    }
    if (state.isScanning) {
        showToast('⚠️ A scan is already running', 'warning');
        return;
    }
    socket.emit('start_scan', { target_id: targetId, type: 'full' });
    showToast('🚀 Starting scan...', 'info');
    addLog('info', `🚀 Starting scan on target ${targetId}`);
}

function removeTarget(targetId) {
    if (!targetId) return;
    if (!confirm('Remove this target?')) return;
    socket.emit('remove_target', { target_id: targetId });
}

function startQuickScan() {
    if (state.targets.length === 0) {
        showToast('⚠️ No targets available', 'warning');
        showAddTarget();
        return;
    }
    startScan(state.targets[0]?.id);
}

function runFullScan() {
    startQuickScan();
}

function generateReport() {
    showToast('📄 Report generation coming soon', 'info');
}

// ============================================================
// Page Detection
// ============================================================

function detectPage() {
    const path = window.location.pathname;
    if (path === '/findings') {
        renderFindingsTable();
        updateFindingStats();
    }
    if (path === '/targets') {
        renderTargetsTable();
    }
    if (path === '/chains') {
        renderChains();
    }
}

// ============================================================
// Init
// ============================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('📄 Page loaded');
    setTimeout(() => {
        refreshAll();
        setTimeout(detectPage, 500);
    }, 500);
});

// Auto-refresh every 15 seconds
setInterval(refreshAll, 15000);

// Expose functions globally
window.addLog = addLog;
window.clearLog = clearLog;
window.exportLog = exportLog;
window.refreshData = refreshData;
window.showAddTarget = showAddTarget;
window.startQuickScan = startQuickScan;
window.runFullScan = runFullScan;
window.startScan = startScan;
window.removeTarget = removeTarget;
window.deleteFinding = deleteFinding;
window.stopAllScans = stopAllScans;
window.generateReport = generateReport;
window.showToast = showToast;
window.closeModal = closeModal;
window.saveTarget = saveTarget;

console.log('✅ Dashboard JS loaded');
