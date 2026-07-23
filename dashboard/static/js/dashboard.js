/**
 * BugBountyAgent - Complete Dashboard JavaScript
 */

const socket = io();

let state = {
    targets: [],
    findings: [],
    chains: [],
    scans: [],
    isScanning: false
};

// ============================================================
// DOM References
// ============================================================

function getElement(id) {
    return document.getElementById(id);
}

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
    const el = (id) => getElement(id);
    if (el('statTargets')) el('statTargets').textContent = agent.targets || 0;
    if (el('statScans')) el('statScans').textContent = agent.running_scans || 0;
}

function updateStatsFromTargets() {
    const el = getElement('statTargets');
    if (el) el.textContent = state.targets.length;
}

function updateStatsFromFindings() {
    const el = getElement('statFindings');
    if (el) el.textContent = state.findings.length;
}

function updateStatsFromChains() {
    const el = getElement('statChains');
    if (el) el.textContent = state.chains.length;
}

// ============================================================
// Logging
// ============================================================

function addLog(level, message) {
    const container = getElement('logContainer');
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
    const container = getElement('logContainer');
    if (container) container.innerHTML = '';
    addLog('info', '🧹 Log cleared');
}

function exportLog() {
    const container = getElement('logContainer');
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
    const container = getElement('toastContainer') || (() => {
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

function renderTargets() {
    // Dashboard targets table
    const tbody = getElement('findingsTableBody');
    if (!tbody) return;
    
    // Actually this is for the dashboard - we want to show targets in a different way
    // The dashboard shows findings, not targets
}

function renderTargetsTable() {
    const tbody = getElement('targetsTableBody');
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

// ============================================================
// Findings
// ============================================================

function renderFindings() {
    // Dashboard recent findings
    const tbody = getElement('findingsTableBody');
    if (!tbody) return;
    
    if (!state.findings || state.findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No findings yet. Start a scan!</td></tr>`;
        return;
    }
    
    const recent = state.findings.slice(0, 10);
    tbody.innerHTML = recent.map(f => `
        <tr onclick="viewFinding('${f.id}')" style="cursor:pointer;">
            <td><span class="severity-badge severity-${f.severity || 'info'}">${f.severity || 'info'}</span></td>
            <td>${f.title || 'Unknown'}</td>
            <td>${f.target || 'N/A'}</td>
            <td>${f.timestamp ? f.timestamp.slice(0, 16) : 'N/A'}</td>
        </tr>
    `).join('');
}

function renderFindingsTable() {
    // Findings page full table
    const tbody = getElement('findingsTableBody');
    if (!tbody) return;
    
    // If this is called from findings page, render all findings
    const isFindingsPage = window.location.pathname === '/findings';
    
    if (!state.findings || state.findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No findings yet. Start a scan!</td></tr>`;
        return;
    }
    
    const displayFindings = isFindingsPage ? state.findings : state.findings.slice(0, 10);
    
    // Update statistics on findings page
    updateFindingStats();
    
    tbody.innerHTML = displayFindings.map(f => `
        <tr onclick="viewFinding('${f.id}')" style="cursor:pointer;">
            <td><span class="severity-badge severity-${f.severity || 'info'}">${f.severity || 'info'}</span></td>
            <td>${f.title || 'Unknown'}</td>
            <td>${f.target || 'N/A'}</td>
            <td>${f.cve_id || '-'}</td>
            <td>${f.timestamp ? f.timestamp.slice(0, 16) : 'N/A'}</td>
        </tr>
    `).join('');
}

function updateFindingStats() {
    const stats = { total: 0, critical: 0, high: 0, medium: 0 };
    state.findings.forEach(f => {
        stats.total++;
        const sev = f.severity?.toLowerCase() || 'info';
        if (sev === 'critical') stats.critical++;
        else if (sev === 'high') stats.high++;
        else if (sev === 'medium') stats.medium++;
    });
    
    ['statTotal', 'statCritical', 'statHigh', 'statMedium'].forEach(id => {
        const el = getElement(id);
        if (el) {
            const key = id.replace('stat', '').toLowerCase();
            el.textContent = stats[key] || 0;
        }
    });
}

// ============================================================
// Chains
// ============================================================

function renderChains() {
    const container = getElement('chainsList');
    if (!container) return;
    
    if (!state.chains || state.chains.length === 0) {
        container.innerHTML = `<div class="text-center text-muted" style="padding:40px;">No attack chains found</div>`;
        return;
    }
    
    // Update stats
    const el = getElement('statTotal');
    if (el) el.textContent = state.chains.length;
    
    container.innerHTML = state.chains.map(c => `
        <div class="chain-card" onclick="viewChain('${c.id}')" style="cursor:pointer; background:var(--bg-card); border:1px solid var(--border-color); border-radius:var(--radius); padding:16px 20px; margin-bottom:12px;">
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
// Modal
// ============================================================

function showAddTarget() {
    const overlay = getElement('modalOverlay');
    const title = getElement('modalTitle');
    if (title) title.textContent = '🎯 Add Target';
    if (overlay) overlay.classList.add('active');
}

function closeModal() {
    const overlay = getElement('modalOverlay');
    if (overlay) overlay.classList.remove('active');
}

function saveTarget() {
    const urlInput = getElement('targetUrl');
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

function viewFinding(findingId) {
    fetch(`/api/findings/${findingId}`)
        .then(res => res.json())
        .then(data => {
            const overlay = getElement('findingDetailModal') || getElement('modalOverlay');
            const title = getElement('findingDetailTitle') || getElement('modalTitle');
            const body = getElement('findingDetailBody') || getElement('modalBody');
            
            if (title) title.textContent = `🔍 ${data.title || 'Finding Details'}`;
            if (body) {
                body.innerHTML = `
                    <div class="finding-detail">
                        <p><strong>Severity:</strong> <span class="severity-badge severity-${data.severity || 'info'}">${data.severity || 'info'}</span></p>
                        <p><strong>Type:</strong> ${data.type || 'Unknown'}</p>
                        <p><strong>Target:</strong> ${data.target || 'N/A'}</p>
                        <p><strong>Description:</strong> ${data.description || 'No description'}</p>
                        ${data.cve_id ? `<p><strong>CVE:</strong> ${data.cve_id}</p>` : ''}
                        ${data.cvss_score ? `<p><strong>CVSS:</strong> ${data.cvss_score}</p>` : ''}
                        ${data.remediation ? `<p><strong>Remediation:</strong> ${data.remediation}</p>` : ''}
                        ${data.reproduction_steps ? `<p><strong>Reproduction Steps:</strong><br/>${data.reproduction_steps}</p>` : ''}
                        <p><strong>Found:</strong> ${data.timestamp || 'N/A'}</p>
                    </div>
                `;
            }
            if (overlay) overlay.classList.add('active');
        })
        .catch(err => showToast(`❌ Failed to load: ${err.message}`, 'error'));
}

function viewChain(chainId) {
    const chain = state.chains.find(c => c.id === chainId);
    if (!chain) return;
    
    const overlay = getElement('chainDetailModal') || getElement('modalOverlay');
    const title = getElement('chainDetailTitle') || getElement('modalTitle');
    const body = getElement('chainDetailBody') || getElement('modalBody');
    
    if (title) title.textContent = `🔗 ${chain.name || 'Chain Details'}`;
    if (body) {
        body.innerHTML = `
            <div style="display:flex; flex-direction:column; gap:12px;">
                <p><strong>Severity:</strong> <span class="severity-badge severity-${chain.severity || 'medium'}">${chain.severity || 'medium'}</span></p>
                <p><strong>Status:</strong> ${chain.completed ? '✅ Completed' : '⏳ In Progress'}</p>
                <p><strong>Target:</strong> ${chain.target || 'N/A'}</p>
                <p><strong>Steps:</strong> ${chain.total_steps || chain.steps?.length || 0}</p>
                ${chain.description ? `<p><strong>Description:</strong> ${chain.description}</p>` : ''}
                ${chain.steps && chain.steps.length ? `
                    <div>
                        <strong>Attack Steps:</strong>
                        <ul style="margin-top:8px; padding-left:20px;">
                            ${chain.steps.map(s => `<li style="padding:4px 0; color:var(--text-secondary);">${s.step || s}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                <p style="color:var(--text-muted); font-size:12px;">Created: ${chain.timestamp || 'N/A'}</p>
            </div>
        `;
    }
    if (overlay) overlay.classList.add('active');
}

function closeFindingDetail() {
    const overlay = getElement('findingDetailModal');
    if (overlay) overlay.classList.remove('active');
    closeModal();
}

function closeChainDetail() {
    const overlay = getElement('chainDetailModal');
    if (overlay) overlay.classList.remove('active');
    closeModal();
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
// Refresh Functions
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
    refreshAll();
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
window.viewFinding = viewFinding;
window.viewChain = viewChain;
window.generateReport = generateReport;
window.showToast = showToast;
window.closeModal = closeModal;
window.closeFindingDetail = closeFindingDetail;
window.closeChainDetail = closeChainDetail;
window.saveTarget = saveTarget;
window.refreshTargets = refreshTargets;
window.refreshFindings = refreshFindings;
window.refreshChains = refreshChains;

console.log('✅ Dashboard JS loaded');
