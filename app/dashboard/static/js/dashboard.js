/**
 * BugBountyAgent - Dashboard JavaScript
 * =====================================
 * Handles WebSocket communication, real-time updates,
 * UI interactions, and all frontend logic.
 */

// ============================================================
// Global State
// ============================================================
const state = {
    connected: false,
    targets: [],
    findings: [],
    chains: [],
    scans: [],
    currentPage: 'dashboard',
    socket: null
};

// ============================================================
// DOM References
// ============================================================
const DOM = {
    // Stats
    statTargets: document.getElementById('statTargets'),
    statFindings: document.getElementById('statFindings'),
    statChains: document.getElementById('statChains'),
    statScans: document.getElementById('statScans'),
    
    // Log
    logContainer: document.getElementById('logContainer'),
    
    // Findings Table
    findingsTableBody: document.getElementById('findingsTableBody'),
    
    // Status
    connectionStatus: document.getElementById('connectionStatus'),
    agentMode: document.getElementById('agentMode'),
    
    // Modal
    modalOverlay: document.getElementById('modalOverlay'),
    modalTitle: document.getElementById('modalTitle'),
    modalBody: document.getElementById('modalBody'),
    modal: document.getElementById('modal'),
    
    // Page Elements
    pageTitle: document.getElementById('pageTitle'),
    pageSubtitle: document.getElementById('pageSubtitle')
};

// ============================================================
// SocketIO Connection
// ============================================================
function connectSocket() {
    state.socket = io();
    
    state.socket.on('connect', () => {
        state.connected = true;
        updateConnectionStatus('connected');
        addLog('info', '🟢 Connected to BugBountyAgent server');
        addLog('info', '🤖 Agent initialized in Hybrid mode');
        addLog('info', '📡 Waiting for commands...');
        refreshData();
    });
    
    state.socket.on('disconnect', () => {
        state.connected = false;
        updateConnectionStatus('disconnected');
        addLog('error', '🔴 Disconnected from server');
    });
    
    state.socket.on('connected', (data) => {
        addLog('success', `✅ ${data.message}`);
    });
    
    state.socket.on('status_update', (data) => {
        updateStats(data);
    });
    
    state.socket.on('scan_update', (data) => {
        addLog('info', `📡 ${data.message}`);
        if (data.type === 'update') {
            // Update scan progress
        }
    });
    
    state.socket.on('scan_started', (data) => {
        addLog('success', `🚀 Scan started: ${data.scan_id} on target ${data.target_id}`);
        updateConnectionStatus('scanning');
    });
    
    state.socket.on('scan_stopped', (data) => {
        addLog('warning', `⏹️ Scan stopped: ${data.scan_id}`);
        updateConnectionStatus('connected');
    });
    
    state.socket.on('findings_update', (data) => {
        state.findings = data.findings || [];
        renderFindings();
    });
    
    state.socket.on('error', (data) => {
        addLog('error', `❌ ${data.message}`);
    });
    
    state.socket.on('log_message', (data) => {
        addLog(data.level || 'info', data.message);
    });
}

// ============================================================
// Connection Status
// ============================================================
function updateConnectionStatus(status) {
    const dot = DOM.connectionStatus.querySelector('.status-dot');
    const text = DOM.connectionStatus.querySelector('.status-text');
    
    dot.className = 'status-dot';
    dot.classList.add(status);
    
    const labels = {
        connected: 'Connected',
        disconnected: 'Disconnected',
        scanning: 'Scanning...'
    };
    text.textContent = labels[status] || status;
}

// ============================================================
// Logging
// ============================================================
function addLog(level, message) {
    const entry = document.createElement('div');
    entry.className = `log-entry log-${level}`;
    
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `
        <span class="log-time">[${time}]</span>
        <span class="log-message">${message}</span>
    `;
    
    DOM.logContainer.appendChild(entry);
    DOM.logContainer.scrollTop = DOM.logContainer.scrollHeight;
}

function clearLog() {
    DOM.logContainer.innerHTML = '';
    addLog('info', '🧹 Log cleared');
}

function exportLog() {
    const entries = DOM.logContainer.querySelectorAll('.log-entry');
    let logText = '';
    entries.forEach(entry => {
        const time = entry.querySelector('.log-time')?.textContent || '';
        const message = entry.querySelector('.log-message')?.textContent || '';
        logText += `${time} ${message}\n`;
    });
    
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bugbounty_log_${new Date().toISOString().slice(0,10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// ============================================================
// Stats Update
// ============================================================
function updateStats(data) {
    const agent = data.agent || {};
    const kb = data.knowledge_base || {};
    
    DOM.statTargets.textContent = agent.targets || 0;
    DOM.statFindings.textContent = kb.total_findings || 0;
    DOM.statChains.textContent = kb.total_chains || 0;
    DOM.statScans.textContent = Object.keys(agent.running_scans || {}).length || 0;
    
    if (agent.mode) {
        DOM.agentMode.textContent = `Mode: ${agent.mode.charAt(0).toUpperCase() + agent.mode.slice(1)}`;
    }
}

// ============================================================
// Findings
// ============================================================
function renderFindings() {
    const findings = state.findings.slice(0, 10);
    
    if (findings.length === 0) {
        DOM.findingsTableBody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted">No findings yet. Start a scan!</td>
            </tr>
        `;
        return;
    }
    
    DOM.findingsTableBody.innerHTML = findings.map(f => `
        <tr onclick="viewFinding('${f.id}')" style="cursor:pointer;">
            <td><span class="severity-badge severity-${f.severity}">${f.severity}</span></td>
            <td>${escapeHtml(f.type)}</td>
            <td>${escapeHtml(f.target)}</td>
            <td>${escapeHtml(f.description)}</td>
            <td>${f.timestamp || '--'}</td>
        </tr>
    `).join('');
}

function viewFinding(id) {
    // Fetch and show finding details
    fetch(`/api/findings/${id}`)
        .then(res => res.json())
        .then(data => {
            showModal('Finding Details', `
                <div class="finding-detail">
                    <p><strong>Type:</strong> ${escapeHtml(data.type)}</p>
                    <p><strong>Severity:</strong> <span class="severity-badge severity-${data.severity}">${data.severity}</span></p>
                    <p><strong>Target:</strong> ${escapeHtml(data.target)}</p>
                    <p><strong>Description:</strong> ${escapeHtml(data.description)}</p>
                    ${data.cvss_score ? `<p><strong>CVSS Score:</strong> ${data.cvss_score}</p>` : ''}
                    ${data.cve_id ? `<p><strong>CVE:</strong> ${data.cve_id}</p>` : ''}
                    ${data.reproduction_steps ? `<p><strong>Reproduction Steps:</strong><br/>${escapeHtml(data.reproduction_steps)}</p>` : ''}
                    ${data.remediation ? `<p><strong>Remediation:</strong> ${escapeHtml(data.remediation)}</p>` : ''}
                    ${data.payload ? `<p><strong>Payload:</strong> <code>${escapeHtml(data.payload)}</code></p>` : ''}
                    ${data.url ? `<p><strong>URL:</strong> <a href="${escapeHtml(data.url)}" target="_blank">${escapeHtml(data.url)}</a></p>` : ''}
                </div>
            `);
        })
        .catch(err => addLog('error', `Failed to load finding: ${err.message}`));
}

// ============================================================
// Targets
// ============================================================
function showAddTarget() {
    showModal('Add Target', `
        <div class="form-group">
            <label for="targetUrl">Target URL</label>
            <input type="text" id="targetUrl" placeholder="https://example.com" />
        </div>
        <div class="form-group">
            <label for="targetScope">Scope (comma separated)</label>
            <input type="text" id="targetScope" placeholder="*.example.com" />
        </div>
        <div class="form-group">
            <label for="targetExclude">Exclude (comma separated)</label>
            <input type="text" id="targetExclude" placeholder="*.dev.example.com" />
        </div>
    `, () => {
        const url = document.getElementById('targetUrl').value.trim();
        if (!url) {
            showToast('Please enter a URL', 'error');
            return;
        }
        
        const scope = document.getElementById('targetScope').value.split(',').map(s => s.trim()).filter(Boolean);
        const exclude = document.getElementById('targetExclude').value.split(',').map(s => s.trim()).filter(Boolean);
        
        fetch('/api/targets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, scope, exclude })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                showToast(`Target added: ${url}`, 'success');
                addLog('success', `🎯 Target added: ${url} (ID: ${data.target_id})`);
                closeModal();
                refreshData();
            } else {
                showToast(`Failed to add target: ${data.error}`, 'error');
            }
        })
        .catch(err => {
            showToast(`Error: ${err.message}`, 'error');
        });
    });
}

// ============================================================
// Scans
// ============================================================
function startQuickScan() {
    // Get first target or prompt
    fetch('/api/targets')
        .then(res => res.json())
        .then(data => {
            const targets = data.targets || [];
            if (targets.length === 0) {
                showToast('No targets available. Add a target first.', 'warning');
                showAddTarget();
                return;
            }
            
            const targetId = targets[0].id;
            startScan(targetId, 'quick');
        })
        .catch(err => {
            showToast(`Error: ${err.message}`, 'error');
        });
}

function runFullScan() {
    fetch('/api/targets')
        .then(res => res.json())
        .then(data => {
            const targets = data.targets || [];
            if (targets.length === 0) {
                showToast('No targets available. Add a target first.', 'warning');
                showAddTarget();
                return;
            }
            
            // If multiple targets, show selection
            if (targets.length === 1) {
                startScan(targets[0].id, 'full');
            } else {
                showModal('Select Target', `
                    <p>Select a target to scan:</p>
                    ${targets.map(t => `
                        <button class="btn btn-secondary btn-block" onclick="startScan('${t.id}', 'full')" style="margin:4px 0;">
                            ${t.url}
                        </button>
                    `).join('')}
                `);
            }
        })
        .catch(err => {
            showToast(`Error: ${err.message}`, 'error');
        });
}

function startScan(targetId, scanType) {
    addLog('info', `🚀 Starting ${scanType} scan on target ${targetId}`);
    showToast(`Starting ${scanType} scan...`, 'info');
    
    fetch(`/api/targets/${targetId}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: scanType })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            addLog('success', `✅ Scan started: ${data.scan_id}`);
            showToast(`Scan started: ${data.scan_id}`, 'success');
            refreshData();
        } else {
            showToast(`Failed to start scan: ${data.error}`, 'error');
        }
    })
    .catch(err => {
        showToast(`Error: ${err.message}`, 'error');
    });
}

// ============================================================
// Reports
// ============================================================
function generateReport() {
    fetch('/api/scans')
        .then(res => res.json())
        .then(data => {
            const scans = data.scans || [];
            if (scans.length === 0) {
                showToast('No scans found. Run a scan first.', 'warning');
                return;
            }
            
            const latestScan = scans[0];
            downloadReport(latestScan.id);
        })
        .catch(err => {
            showToast(`Error: ${err.message}`, 'error');
        });
}

function downloadReport(scanId) {
    window.open(`/api/reports/${scanId}`, '_blank');
    addLog('info', `📄 Downloading report for scan: ${scanId}`);
}

// ============================================================
// Refresh Data
// ============================================================
function refreshData() {
    if (!state.connected) {
        showToast('Not connected to server', 'error');
        return;
    }
    
    // Request status update
    state.socket.emit('get_status');
    
    // Fetch findings
    fetch('/api/findings?limit=10')
        .then(res => res.json())
        .then(data => {
            state.findings = data.findings || [];
            renderFindings();
        })
        .catch(err => addLog('error', `Failed to refresh findings: ${err.message}`));
}

// ============================================================
// Modal
// ============================================================
function showModal(title, content, onSave) {
    DOM.modalTitle.textContent = title;
    DOM.modalBody.innerHTML = content;
    
    // Add save button if onSave provided
    const footer = DOM.modal.querySelector('.modal-footer');
    if (onSave) {
        footer.innerHTML = `
            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn btn-primary" id="modalSaveBtn">Save</button>
        `;
        document.getElementById('modalSaveBtn').addEventListener('click', onSave);
    } else {
        footer.innerHTML = `
            <button class="btn btn-secondary" onclick="closeModal()">Close</button>
        `;
    }
    
    DOM.modalOverlay.classList.add('active');
}

function closeModal() {
    DOM.modalOverlay.classList.remove('active');
}

// Close modal on overlay click
DOM.modalOverlay.addEventListener('click', (e) => {
    if (e.target === DOM.modalOverlay) {
        closeModal();
    }
});

// ============================================================
// Toast Notifications
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
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 4000);
}

// ============================================================
// Page Navigation
// ============================================================
function showPage(page) {
    state.currentPage = page;
    
    // Update nav
    document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.page === page);
    });
    
    // Update header
    const titles = {
        dashboard: ['Dashboard', 'Overview of your bug hunting operations'],
        targets: ['Targets', 'Manage your targets'],
        findings: ['Findings', 'All discovered vulnerabilities'],
        chains: ['Chains', 'Attack chains and correlations'],
        scans: ['Scans', 'Scan history and results'],
        settings: ['Settings', 'Agent configuration']
    };
    
    const [title, subtitle] = titles[page] || ['Page', ''];
    DOM.pageTitle.textContent = title;
    DOM.pageSubtitle.textContent = subtitle;
    
    // Load page content
    switch(page) {
        case 'dashboard':
            refreshData();
            break;
        case 'findings':
            loadFindingsPage();
            break;
        case 'chains':
            loadChainsPage();
            break;
        // Other pages
    }
}

function loadFindingsPage() {
    fetch('/api/findings?limit=100')
        .then(res => res.json())
        .then(data => {
            const findings = data.findings || [];
            // Render full findings table
        });
}

function loadChainsPage() {
    fetch('/api/chains')
        .then(res => res.json())
        .then(data => {
            const chains = data.chains || [];
            // Render chains
        });
}

// ============================================================
// Utilities
// ============================================================
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(timestamp) {
    if (!timestamp) return '--';
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch {
        return timestamp;
    }
}

// ============================================================
// Event Listeners
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    // Connect to server
    connectSocket();
    
    // Setup navigation
    document.querySelectorAll('.nav-item').forEach(el => {
        el.addEventListener('click', (e) => {
            e.preventDefault();
            showPage(el.dataset.page);
        });
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
});

// ============================================================
// Expose functions to global scope for inline onclick handlers
// ============================================================
window.addLog = addLog;
window.clearLog = clearLog;
window.exportLog = exportLog;
window.refreshData = refreshData;
window.showAddTarget = showAddTarget;
window.startQuickScan = startQuickScan;
window.runFullScan = runFullScan;
window.generateReport = generateReport;
window.startScan = startScan;
window.viewFinding = viewFinding;
window.showModal = showModal;
window.closeModal = closeModal;
window.showToast = showToast;
window.showPage = showPage;
window.downloadReport = downloadReport;