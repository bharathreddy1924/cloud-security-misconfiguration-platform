const sample = {
  resources: [
    { id: "bucket-customer-uploads", type: "s3", publicAccess: true, encryptionEnabled: false },
    { id: "sg-admin-access", type: "security-group", ingress: [{ port: 22, cidr: "0.0.0.0/0" }] },
    { id: "iam-developer-policy", type: "iam-policy", action: "*", resource: "*" },
    { id: "prod-reporting-db", type: "database", publiclyAccessible: true },
    { id: "audit-trail-main", type: "cloudtrail", enabled: false },
    { id: "encrypted-volume-01", type: "ebs", encrypted: true }
  ]
};

const $ = id => document.getElementById(id);
if ($('payload')) {
  $('payload').value = JSON.stringify(sample, null, 2);
}

// Initialize authenticated session and populate user metadata
async function initAuth() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.status === 401) {
      window.location.href = '/login?status=session_expired';
      return;
    }
    const data = await res.json();
    if (data.authenticated && data.user) {
      const userProfile = $('userProfile');
      const userName = $('userName');
      const userEmail = $('userEmail');
      const userAvatar = $('userAvatar');

      if (userName) userName.textContent = data.user.name || 'Security Auditor';
      if (userEmail) userEmail.textContent = data.user.email || '';
      if (userAvatar && data.user.picture) {
        userAvatar.referrerPolicy = 'no-referrer';
        userAvatar.onerror = () => {
          userAvatar.style.display = 'none';
        };
        userAvatar.src = data.user.picture;
        userAvatar.style.display = 'inline-block';
      }
      if (userProfile) {
        userProfile.style.display = 'flex';
      }
      // Load recent scan history for authenticated user
      loadScanHistory();
    }
  } catch (err) {
    console.warn('Authentication status check failed:', err);
  }
}

initAuth();

if ($('sampleBtn')) {
  $('sampleBtn').addEventListener('click', () => {
    $('payload').value = JSON.stringify(sample, null, 2);
    runScan();
  });
}

if ($('scanBtn')) {
  $('scanBtn').addEventListener('click', runScan);
}

if ($('clearBtn')) {
  $('clearBtn').addEventListener('click', () => {
    $('resourceCount').textContent = '0';
    $('findingCount').textContent = '0';
    $('criticalCount').textContent = '0';
    $('highCount').textContent = '0';
    $('findings').className = 'empty';
    $('findings').textContent = 'Run a scan to view detected risks and remediation steps.';
    $('resultTag').textContent = 'No scan yet';
    $('message').textContent = '';
  });
}

async function runScan() {
  $('message').textContent = 'Scanning…';
  try {
    const body = JSON.parse($('payload').value);
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (response.status === 401) {
      $('message').textContent = 'Session expired. Redirecting to login…';
      setTimeout(() => {
        window.location.href = '/login?status=session_expired';
      }, 1000);
      return;
    }

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Request failed');

    $('resourceCount').textContent = data.resourceCount;
    $('findingCount').textContent = data.summary.total;
    $('criticalCount').textContent = data.summary.critical;
    $('highCount').textContent = data.summary.high;
    $('resultTag').textContent = `${data.summary.total} finding(s)`;
    $('message').textContent = data.persistence === 'saved' ? 'Scan complete • history saved' : 'Scan complete • database not connected';
    renderFindings(data.findings);

    // Refresh history after scan if saved to MongoDB
    if (data.persistence === 'saved') {
      loadScanHistory();
    }
  } catch (err) {
    $('message').textContent = err.message;
  }
}

function renderFindings(items) {
  const root = $('findings');
  if (!items.length) {
    root.className = 'empty';
    root.textContent = 'No configured rules were triggered for this inventory.';
    return;
  }
  root.className = '';
  root.innerHTML = items.map(item => `
    <article class="finding">
      <div class="finding-top">
        <div>
          <h3>${escapeHtml(item.title)}</h3>
          <p>${escapeHtml(item.resourceId)} · ${escapeHtml(item.resourceType)} · ${escapeHtml(item.ruleId)}</p>
        </div>
        <span class="severity sev-${item.severity}">${item.severity}</span>
      </div>
      <p>${escapeHtml(item.description)}</p>
      <p><strong>Remediation:</strong> ${escapeHtml(item.remediation)}</p>
    </article>`).join('');
}

// ==========================================
// Scan History Management
// ==========================================

async function loadScanHistory() {
  const loading = $('historyLoading');
  const errorBox = $('historyError');
  const tag = $('historyTag');
  const refreshBtn = $('refreshHistoryBtn');

  if (loading) loading.style.display = 'block';
  if (errorBox) {
    errorBox.style.display = 'none';
    errorBox.textContent = '';
  }
  if (refreshBtn) refreshBtn.disabled = true;

  try {
    const res = await fetch('/api/scans');
    if (res.status === 401) {
      window.location.href = '/login?status=session_expired';
      return;
    }
    if (res.status === 503) {
      if (errorBox) {
        errorBox.textContent = 'MongoDB persistence is offline. Historical scan records cannot be loaded.';
        errorBox.style.display = 'flex';
      }
      if (tag) tag.textContent = 'DB offline';
      renderHistory([]);
      return;
    }
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || errData.message || `Request failed with HTTP ${res.status}`);
    }

    const scans = await res.json();
    if (tag) {
      tag.textContent = scans.length === 1 ? '1 record' : `${scans.length} records`;
    }
    renderHistory(scans);
  } catch (err) {
    console.warn('Failed to load scan history:', err);
    if (errorBox) {
      errorBox.textContent = `Unable to load scan history: ${err.message}`;
      errorBox.style.display = 'flex';
    }
    if (tag) tag.textContent = 'Error loading';
  } finally {
    if (loading) loading.style.display = 'none';
    if (refreshBtn) refreshBtn.disabled = false;
  }
}

function renderHistory(items) {
  const root = $('historyList');
  if (!root) return;
  if (!items || !items.length) {
    root.innerHTML = '<div class="empty">No previous scan history found for your account. Run a scan above to save your first posture assessment.</div>';
    return;
  }

  root.innerHTML = items.map((item, idx) => {
    const total = item.summary?.total ?? (item.findings?.length || 0);
    const critical = item.summary?.critical ?? 0;
    const high = item.summary?.high ?? 0;
    const medium = item.summary?.medium ?? 0;
    const low = item.summary?.low ?? 0;
    const resourceCount = item.resourceCount ?? 0;
    const isClean = total === 0;
    const statusText = isClean ? 'Compliant' : 'Findings Detected';
    const statusClass = isClean ? 'history-status-clean' : 'history-status-risks';
    const dateFormatted = formatDateTime(item.createdAt);

    return `
      <article class="history-item" data-scan-index="${idx}">
        <div class="history-top">
          <div class="history-title-group">
            <span class="history-date">${escapeHtml(dateFormatted)}</span>
            <span class="history-time">${resourceCount} resource${resourceCount === 1 ? '' : 's'} assessed</span>
          </div>
          <div class="history-badges">
            <span class="history-status ${statusClass}">${escapeHtml(statusText)}</span>
          </div>
        </div>
        <div class="history-details">
          <div class="history-meta">
            <span>Total Findings: <strong>${total}</strong></span>
          </div>
          <div class="sev-pills">
            <span class="sev-pill crit" title="Critical Findings">${critical} Critical</span>
            <span class="sev-pill high" title="High Findings">${high} High</span>
            <span class="sev-pill med" title="Medium Findings">${medium} Medium</span>
            <span class="sev-pill low" title="Low Findings">${low} Low</span>
          </div>
        </div>
      </article>
    `;
  }).join('');
}

function formatDateTime(isoString) {
  if (!isoString) return 'Unknown date';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return String(isoString);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  } catch (_) {
    return String(isoString);
  }
}

if ($('refreshHistoryBtn')) {
  $('refreshHistoryBtn').addEventListener('click', loadScanHistory);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}
