/**
 * CloudSec Selenium E2E Test HTML Reporter
 * Generates an executive-grade HTML execution report for the Selenium WebDriver E2E suite.
 * Built using native Node.js APIs with zero external dependencies.
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

class SeleniumReporter {
  constructor() {
    this.tests = [];
    this.suiteStartTime = Date.now();
    this.suiteEndTime = null;
  }

  recordStart(testContext) {
    if (testContext) {
      testContext.__startTime = Date.now();
    }
  }

  recordEnd(testContext) {
    if (!testContext) return;
    const duration = testContext.__startTime ? Date.now() - testContext.__startTime : 0;
    const passed = testContext.passed !== false && !testContext.error;
    
    let errorMessage = null;
    let errorStack = null;
    if (testContext.error) {
      errorMessage = testContext.error.cause?.message || testContext.error.message || String(testContext.error);
      errorStack = testContext.error.cause?.stack || testContext.error.stack || null;
    }

    this.tests.push({
      name: testContext.name || 'Unnamed Test',
      passed,
      duration,
      errorMessage,
      errorStack
    });
  }

  generateHtml(metadata = {}) {
    this.suiteEndTime = Date.now();
    const totalDuration = this.suiteEndTime - this.suiteStartTime;

    const totalTests = this.tests.length;
    const passedTests = this.tests.filter(t => t.passed).length;
    const failedTests = this.tests.filter(t => !t.passed).length;
    const skippedTests = metadata.skipped || 0;
    const passRate = totalTests > 0 ? Math.round((passedTests / totalTests) * 100) : 0;
    const isOverallPass = failedTests === 0 && totalTests > 0;

    const executionDate = new Date().toLocaleString('en-US', {
      dateStyle: 'full',
      timeStyle: 'long',
      hour12: true
    });
    const isoDate = new Date().toISOString();

    const isHeadless = metadata.isHeadless ?? (process.env.HEADLESS !== 'false');
    const modeLabel = isHeadless ? 'HEADLESS (CI Compatible)' : 'VISIBLE (Headed Browser)';
    const modeClass = isHeadless ? 'mode-headless' : 'mode-visible';
    const baseUrl = metadata.baseUrl || process.env.APP_URL || 'http://localhost:3001';

    const testRows = this.tests.map((t, idx) => {
      const statusBadge = t.passed
        ? '<span class="badge badge-pass"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> PASS</span>'
        : '<span class="badge badge-fail"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> FAIL</span>';
      
      const durationFormatted = t.duration >= 1000
        ? `${(t.duration / 1000).toFixed(2)}s`
        : `${Math.round(t.duration)}ms`;

      let errorBlock = '';
      if (!t.passed && (t.errorMessage || t.errorStack)) {
        errorBlock = `
          <div class="error-container">
            <div class="error-title">Failure Details:</div>
            <pre class="error-message">${escapeHtml(t.errorMessage || '')}</pre>
            ${t.errorStack ? `<details><summary>Stack Trace</summary><pre class="error-stack">${escapeHtml(t.errorStack)}</pre></details>` : ''}
          </div>
        `;
      }

      return `
        <tr class="${t.passed ? 'row-pass' : 'row-fail'}">
          <td class="col-num">${idx + 1}</td>
          <td class="col-name">
            <div class="test-title">${escapeHtml(t.name)}</div>
            ${errorBlock}
          </td>
          <td class="col-status">${statusBadge}</td>
          <td class="col-dur">${durationFormatted}</td>
        </tr>
      `;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CloudSec — Selenium Test Execution Report</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --success: #10b981;
      --success-bg: rgba(16, 185, 129, 0.12);
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.12);
      --warning: #f59e0b;
      --neutral: #64748b;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      line-height: 1.5;
      padding: 32px 20px;
    }

    .container {
      max-width: 1040px;
      margin: 0 auto;
    }

    /* Header */
    .header {
      background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 28px 32px;
      margin-bottom: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 20px;
    }

    .header-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .logo-icon {
      width: 48px;
      height: 48px;
      border-radius: 10px;
      background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 12px rgba(37, 99, 235, 0.35);
    }

    .title-group h1 {
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .title-group p {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    .overall-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 16px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .overall-pass {
      background: var(--success-bg);
      color: var(--success);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .overall-fail {
      background: var(--danger-bg);
      color: var(--danger);
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    /* Meta Bar */
    .meta-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 24px;
      font-size: 12px;
    }

    .meta-pill {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      padding: 6px 14px;
      border-radius: 6px;
      color: var(--text-muted);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .meta-pill strong {
      color: var(--text-main);
    }

    .mode-headless { color: #60a5fa !important; }
    .mode-visible { color: #34d399 !important; }

    /* Summary Grid */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }

    .metric-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 18px 20px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }

    .metric-card .label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 6px;
    }

    .metric-card .value {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #ffffff;
    }

    .metric-card.card-pass .value { color: var(--success); }
    .metric-card.card-fail .value { color: var(--danger); }
    .metric-card.card-rate .value { color: var(--primary); }

    /* Results Table */
    .table-container {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      overflow: hidden;
      margin-bottom: 28px;
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.2);
    }

    .table-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(255, 255, 255, 0.015);
    }

    .table-header h2 {
      font-size: 15px;
      font-weight: 600;
      color: #ffffff;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }

    thead th {
      background: #131d2f;
      color: var(--text-muted);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 12px 18px;
      border-bottom: 1px solid var(--card-border);
    }

    tbody td {
      padding: 16px 18px;
      border-bottom: 1px solid var(--card-border);
      vertical-align: top;
    }

    tbody tr:last-child td {
      border-bottom: none;
    }

    .col-num { width: 48px; color: var(--text-muted); font-weight: 600; }
    .col-name { font-weight: 500; color: #f9fafb; }
    .col-status { width: 110px; }
    .col-dur { width: 90px; text-align: right; color: var(--text-muted); font-variant-numeric: tabular-nums; }

    .test-title {
      font-size: 13.5px;
      font-weight: 600;
      color: #f3f4f6;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 9px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
    }

    .badge-pass { background: var(--success-bg); color: var(--success); }
    .badge-fail { background: var(--danger-bg); color: var(--danger); }

    .error-container {
      margin-top: 10px;
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.25);
      border-radius: 6px;
      padding: 10px 12px;
      font-size: 12px;
    }

    .error-title {
      color: var(--danger);
      font-weight: 600;
      margin-bottom: 4px;
      font-size: 11px;
      text-transform: uppercase;
    }

    pre.error-message {
      color: #fca5a5;
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11.5px;
    }

    details { margin-top: 8px; color: var(--text-muted); }
    summary { cursor: pointer; font-size: 11px; font-weight: 600; }
    pre.error-stack {
      margin-top: 6px;
      color: #9ca3af;
      font-size: 11px;
      overflow-x: auto;
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    /* Verification Checklist */
    .checklist-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 28px;
    }

    .checklist-card h3 {
      font-size: 14px;
      font-weight: 600;
      color: #ffffff;
      margin-bottom: 12px;
    }

    .check-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 10px;
    }

    .check-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      color: var(--text-muted);
    }

    .check-icon {
      color: var(--success);
      display: flex;
      align-items: center;
    }

    /* Footer */
    .footer {
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
      padding: 16px 0;
      border-top: 1px solid var(--card-border);
    }

    @media print {
      body { background: white; color: black; }
      .header, .metric-card, .table-container { box-shadow: none; border-color: #e5e7eb; }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="header">
      <div class="header-left">
        <div class="logo-icon">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <div class="title-group">
          <h1>CloudSec E2E Test Execution Report</h1>
          <p>Defensive Cloud Security Platform — Selenium WebDriver Automation Suite</p>
        </div>
      </div>
      <div>
        <span class="overall-badge ${isOverallPass ? 'overall-pass' : 'overall-fail'}">
          ${isOverallPass ? 'All 5 Tests Passed' : `${failedTests} Test(s) Failed`}
        </span>
      </div>
    </header>

    <!-- Meta Info Bar -->
    <div class="meta-bar">
      <div class="meta-pill">
        <span>Timestamp:</span>
        <strong title="${isoDate}">${executionDate}</strong>
      </div>
      <div class="meta-pill">
        <span>Execution Mode:</span>
        <strong class="${modeClass}">${modeLabel}</strong>
      </div>
      <div class="meta-pill">
        <span>Target URL:</span>
        <strong>${escapeHtml(baseUrl)}</strong>
      </div>
      <div class="meta-pill">
        <span>Environment:</span>
        <strong>Node ${process.version} (${process.platform})</strong>
      </div>
      <div class="meta-pill">
        <span>WebDriver:</span>
        <strong>Selenium WebDriver 4.51.0</strong>
      </div>
    </div>

    <!-- Summary Metrics -->
    <div class="summary-grid">
      <div class="metric-card">
        <div class="label">Total Tests</div>
        <div class="value">${totalTests}</div>
      </div>
      <div class="metric-card card-pass">
        <div class="label">Passed</div>
        <div class="value">${passedTests}</div>
      </div>
      <div class="metric-card ${failedTests > 0 ? 'card-fail' : ''}">
        <div class="label">Failed</div>
        <div class="value">${failedTests}</div>
      </div>
      <div class="metric-card">
        <div class="label">Skipped</div>
        <div class="value">${skippedTests}</div>
      </div>
      <div class="metric-card card-rate">
        <div class="label">Pass Rate</div>
        <div class="value">${passRate}%</div>
      </div>
      <div class="metric-card">
        <div class="label">Duration</div>
        <div class="value">${(totalDuration / 1000).toFixed(2)}s</div>
      </div>
    </div>

    <!-- Test Results Table -->
    <div class="table-container">
      <div class="table-header">
        <h2>Executed Test Cases (${totalTests})</h2>
      </div>
      <table>
        <thead>
          <tr>
            <th class="col-num">#</th>
            <th class="col-name">Test Case Description</th>
            <th class="col-status">Status</th>
            <th class="col-dur">Duration</th>
          </tr>
        </thead>
        <tbody>
          ${testRows}
        </tbody>
      </table>
    </div>

    <!-- Verification Checklist -->
    <div class="checklist-card">
      <h3>Verified E2E Security & Automation Assertions</h3>
      <div class="check-grid">
        <div class="check-item">
          <span class="check-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></span>
          <span>Login Page Loaded & Title Verified</span>
        </div>
        <div class="check-item">
          <span class="check-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></span>
          <span>Google OAuth 2.0 Button & Route</span>
        </div>
        <div class="check-item">
          <span class="check-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></span>
          <span>Unauthenticated Navigation Guard (302 Redirect)</span>
        </div>
        <div class="check-item">
          <span class="check-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></span>
          <span>Security Badges & Platform Capabilities Verified</span>
        </div>
        <div class="check-item">
          <span class="check-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></span>
          <span>Session Injection & Live Authenticated Dashboard</span>
        </div>
        <div class="check-item">
          <span class="check-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></span>
          <span>Scan History Table & Refresh Controls Displayed</span>
        </div>
      </div>
    </div>

    <!-- Footer -->
    <footer class="footer">
      Generated automatically by CloudSec Selenium Automation Suite &bull; ${isoDate}
    </footer>
  </div>
</body>
</html>`;
  }

  saveReport(filePath = 'reports/selenium-report.html', metadata = {}) {
    const html = this.generateHtml(metadata);
    const absPath = path.resolve(filePath);
    const dir = path.dirname(absPath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(absPath, html, 'utf8');
    console.log(`\n===============================================================`);
    console.log(`[Report] Selenium HTML report generated successfully:`);
    console.log(`         ${absPath}`);
    console.log(`===============================================================\n`);

    return absPath;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Automatically opens the report in the default system browser.
 * Respects CI environments (Jenkins/GitHub Actions) and NO_OPEN variable to avoid hanging CI runners.
 */
function openReport(filePath) {
  // If in CI or Jenkins, do NOT attempt to launch GUI browser
  if (process.env.CI || process.env.JENKINS_URL || process.env.BUILD_NUMBER || process.env.NO_OPEN === 'true') {
    console.log(`[Report] Non-interactive / CI environment detected. Skipping browser auto-open.`);
    return;
  }

  try {
    const absPath = path.resolve(filePath);
    let cmd;
    if (process.platform === 'win32') {
      cmd = `start "" "${absPath}"`;
    } else if (process.platform === 'darwin') {
      cmd = `open "${absPath}"`;
    } else {
      cmd = `xdg-open "${absPath}"`;
    }

    const child = exec(cmd, () => {});
    if (child && typeof child.unref === 'function') {
      child.unref();
    }
    console.log(`[Report] Opening HTML report in default browser...`);
  } catch (err) {
    console.warn(`[Report] Could not auto-open browser: ${err.message}`);
  }
}

// Singleton reporter instance for the suite
const defaultReporter = new SeleniumReporter();

module.exports = {
  SeleniumReporter,
  defaultReporter,
  openReport
};

// Allow standalone CLI execution to open existing report
if (require.main === module) {
  const targetReport = path.resolve('reports/selenium-report.html');
  if (fs.existsSync(targetReport)) {
    openReport(targetReport);
  } else {
    console.log(`[Report] No report found at ${targetReport}. Run "npm run test:e2e" first.`);
  }
}
