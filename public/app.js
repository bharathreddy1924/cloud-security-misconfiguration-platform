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
        userAvatar.src = data.user.picture;
        userAvatar.style.display = 'inline-block';
      }
      if (userProfile) {
        userProfile.style.display = 'flex';
      }
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

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}
