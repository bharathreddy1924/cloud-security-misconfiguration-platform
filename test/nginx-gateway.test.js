const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const https = require('https');
const { spawnSync } = require('child_process');

const HTTP_URL = process.env.GATEWAY_HTTP_URL || 'http://localhost:3001';
const HTTPS_URL = process.env.GATEWAY_HTTPS_URL || 'https://localhost:3443';
const CERT_PATH = path.join(__dirname, '..', 'nginx', 'certs', 'cloudsec.crt');

// Helper to determine if Nginx container is running and accessible
async function isNginxRunning() {
  try {
    const res = await fetch(`${HTTP_URL}/api/health`, { signal: AbortSignal.timeout(1500) });
    return res.status === 200;
  } catch (_) {
    return false;
  }
}

// Discovers trusted CAs: cloudsec.crt (self-signed dev cert), explicit GATEWAY_CA_CERT_PATH, or local mkcert root CA
function getTrustedCaCertificates() {
  const cas = [];

  // 1. Include repository dev certificate (acts as CA when self-signed)
  if (fs.existsSync(CERT_PATH)) {
    cas.push(fs.readFileSync(CERT_PATH));
  }

  // 2. Explicit CA certificate path via environment variable (e.g. Jenkins/CI or custom root CA)
  if (process.env.GATEWAY_CA_CERT_PATH !== undefined) {
    const explicitCaPath = process.env.GATEWAY_CA_CERT_PATH;
    if (!explicitCaPath || !fs.existsSync(explicitCaPath)) {
      throw new Error(`GATEWAY_CA_CERT_PATH is configured ('${explicitCaPath}'), but the file does not exist.`);
    }
    try {
      cas.push(fs.readFileSync(explicitCaPath));
    } catch (err) {
      throw new Error(`Failed to read CA certificate from GATEWAY_CA_CERT_PATH ('${explicitCaPath}'): ${err.message}`);
    }
    return cas;
  }

  // 3. Fallback: discover local mkcert root CA across platforms (Windows, macOS, Linux) without hardcoding paths
  const candidateMkcertPaths = [];
  if (process.env.LOCALAPPDATA) {
    candidateMkcertPaths.push(path.join(process.env.LOCALAPPDATA, 'mkcert', 'rootCA.pem'));
  }
  const home = process.env.HOME || process.env.USERPROFILE;
  if (home) {
    candidateMkcertPaths.push(path.join(home, 'AppData', 'Local', 'mkcert', 'rootCA.pem'));
    candidateMkcertPaths.push(path.join(home, 'Library', 'Application Support', 'mkcert', 'rootCA.pem'));
    candidateMkcertPaths.push(path.join(home, '.local', 'share', 'mkcert', 'rootCA.pem'));
  }
  if (process.env.XDG_DATA_HOME) {
    candidateMkcertPaths.push(path.join(process.env.XDG_DATA_HOME, 'mkcert', 'rootCA.pem'));
  }

  try {
    const res = spawnSync('mkcert', ['-CAROOT'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    if (res.status === 0 && res.stdout) {
      const caroot = res.stdout.trim();
      if (caroot) {
        candidateMkcertPaths.unshift(path.join(caroot, 'rootCA.pem'));
      }
    }
  } catch (_) {}

  for (const p of candidateMkcertPaths) {
    if (p && fs.existsSync(p)) {
      try {
        cas.push(fs.readFileSync(p));
        break;
      } catch (_) {}
    }
  }

  return cas.length > 0 ? cas : undefined;
}

// Helper for HTTPS fetch using verified CA certificates with strict verification
function httpsGet(urlPath) {
  return new Promise((resolve, reject) => {
    const ca = getTrustedCaCertificates();
    const url = new URL(urlPath, HTTPS_URL);
    const req = https.request({
      hostname: url.hostname,
      port: url.port || 3443,
      path: url.pathname + url.search,
      method: 'GET',
      ca,
      rejectUnauthorized: true,
      timeout: 3000
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('HTTPS request timed out'));
    });
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Nginx Gateway Security & Rate Limiting Test Suite
// ---------------------------------------------------------------------------

test('Nginx Gateway: Security headers on HTTP endpoint (:3001)', async (t) => {
  const active = await isNginxRunning();
  if (!active) {
    t.skip('Nginx container is not active on port 3001; skipping live gateway test');
    return;
  }

  const res = await fetch(`${HTTP_URL}/api/health`);
  assert.equal(res.status, 200);

  // 1. Version disclosure prevention (server_tokens off)
  const serverHeader = res.headers.get('server');
  assert.equal(serverHeader, 'nginx', 'Server header must not reveal version number');

  // 2. Framework fingerprint suppression (app.disable("x-powered-by"))
  assert.equal(res.headers.get('x-powered-by'), null, 'X-Powered-By must be absent');

  // 3. Security headers
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');

  // 4. Content Security Policy
  const csp = res.headers.get('content-security-policy');
  assert.ok(csp, 'CSP header must be present');
  assert.ok(csp.includes("default-src 'self'"));
  assert.ok(csp.includes('lh3.googleusercontent.com'));
});

test('Nginx Gateway: Security headers and TLS verification on HTTPS endpoint (:3443)', async (t) => {
  const active = await isNginxRunning();
  if (!active) {
    t.skip('Nginx container is not active; skipping HTTPS gateway test');
    return;
  }

  const res = await httpsGet('/api/health');
  assert.equal(res.status, 200);

  // 1. Server header and no fingerprint
  assert.equal(res.headers['server'], 'nginx');
  assert.equal(res.headers['x-powered-by'], undefined);

  // 2. Security headers over TLS
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN');
  assert.equal(res.headers['referrer-policy'], 'strict-origin-when-cross-origin');

  const csp = res.headers['content-security-policy'];
  assert.ok(csp);
  assert.ok(csp.includes("default-src 'self'"));
});

test('Nginx Gateway: getTrustedCaCertificates fails clearly when GATEWAY_CA_CERT_PATH does not exist', () => {
  const origEnv = process.env.GATEWAY_CA_CERT_PATH;
  try {
    process.env.GATEWAY_CA_CERT_PATH = path.join(__dirname, 'non-existent-ca.pem');
    assert.throws(
      () => getTrustedCaCertificates(),
      /GATEWAY_CA_CERT_PATH is configured/
    );
  } finally {
    if (origEnv !== undefined) {
      process.env.GATEWAY_CA_CERT_PATH = origEnv;
    } else {
      delete process.env.GATEWAY_CA_CERT_PATH;
    }
  }
});

test('Nginx Gateway: Explicit GATEWAY_CA_CERT_PATH environment variable is loaded and trusted', async (t) => {
  const active = await isNginxRunning();
  if (!active) {
    t.skip('Nginx container is not active; skipping explicit CA path test');
    return;
  }

  // 1. Check configured GATEWAY_CA_CERT_PATH first (e.g. CI / Jenkins LocalSystem environment)
  let rootCaPath = null;
  if (process.env.GATEWAY_CA_CERT_PATH && fs.existsSync(process.env.GATEWAY_CA_CERT_PATH)) {
    rootCaPath = process.env.GATEWAY_CA_CERT_PATH;
  } else {
    // 2. Fall back to user-local mkcert discovery
    const candidatePaths = [
      process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'mkcert', 'rootCA.pem'),
      (process.env.HOME || process.env.USERPROFILE) && path.join(process.env.HOME || process.env.USERPROFILE, 'AppData', 'Local', 'mkcert', 'rootCA.pem'),
      (process.env.HOME || process.env.USERPROFILE) && path.join(process.env.HOME || process.env.USERPROFILE, 'Library', 'Application Support', 'mkcert', 'rootCA.pem'),
      (process.env.HOME || process.env.USERPROFILE) && path.join(process.env.HOME || process.env.USERPROFILE, '.local', 'share', 'mkcert', 'rootCA.pem')
    ].filter(Boolean);

    try {
      const res = spawnSync('mkcert', ['-CAROOT'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      if (res.status === 0 && res.stdout) {
        const caroot = res.stdout.trim();
        if (caroot) candidatePaths.unshift(path.join(caroot, 'rootCA.pem'));
      }
    } catch (_) {}

    rootCaPath = candidatePaths.find(p => fs.existsSync(p));
  }

  if (!rootCaPath) {
    t.skip('Neither GATEWAY_CA_CERT_PATH nor local mkcert rootCA.pem is available in environment; skipping explicit CA integration test');
    return;
  }

  const origEnv = process.env.GATEWAY_CA_CERT_PATH;
  try {
    process.env.GATEWAY_CA_CERT_PATH = rootCaPath;
    const certs = getTrustedCaCertificates();
    assert.ok(Array.isArray(certs) && certs.length >= 2, 'Must include dev certificate and the explicit rootCA.pem');

    const rootCaBytes = fs.readFileSync(rootCaPath);
    const hasRootCa = certs.some(c => Buffer.isBuffer(c) && c.equals(rootCaBytes));
    assert.ok(hasRootCa, 'Explicit GATEWAY_CA_CERT_PATH certificate must be present in the trusted CA list');

    const res = await httpsGet('/api/health');
    assert.equal(res.status, 200, 'HTTPS request must succeed using explicit GATEWAY_CA_CERT_PATH');
  } finally {
    if (origEnv !== undefined) {
      process.env.GATEWAY_CA_CERT_PATH = origEnv;
    } else {
      delete process.env.GATEWAY_CA_CERT_PATH;
    }
  }
});

test('Nginx Gateway: Rate limiting on authentication routes (/auth/) returns HTTP 429 upon bursting', async (t) => {
  const active = await isNginxRunning();
  if (!active) {
    t.skip('Nginx container is not active; skipping rate limiting test');
    return;
  }

  // Rate limit for /auth/ is 5r/s with burst=10.
  // Sending 25 concurrent requests will cleanly exceed the burst limit.
  const requests = Array.from({ length: 25 }, () =>
    fetch(`${HTTP_URL}/auth/google`, { redirect: 'manual' })
  );

  const responses = await Promise.all(requests);
  const statusCodes = responses.map(r => r.status);

  const has429 = statusCodes.includes(429);
  assert.ok(has429, `Rapid auth requests must trigger rate limiting (HTTP 429). Received status codes: ${statusCodes.slice(0, 15).join(', ')}...`);
});

test('Nginx Gateway: Protected API endpoints strictly reject unauthenticated requests via reverse proxy', async (t) => {
  const active = await isNginxRunning();
  if (!active) {
    t.skip('Nginx container is not active; skipping gateway authorization test');
    return;
  }

  // POST /api/scan rejected with 401
  const scanRes = await fetch(`${HTTP_URL}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resources: [{ id: 'test', type: 's3' }] })
  });
  assert.equal(scanRes.status, 401);
  const scanData = await scanRes.json();
  assert.equal(scanData.error, 'Unauthorized');

  // GET /api/scans rejected with 401
  const scansRes = await fetch(`${HTTP_URL}/api/scans`);
  assert.equal(scansRes.status, 401);

  // GET /api/auth/me rejected with 401
  const meRes = await fetch(`${HTTP_URL}/api/auth/me`);
  assert.equal(meRes.status, 401);

  // GET / root redirects unauthenticated visitors to /login
  const rootRes = await fetch(`${HTTP_URL}/`, { redirect: 'manual' });
  assert.equal(rootRes.status, 302);
  assert.ok(rootRes.headers.get('location').includes('/login'));
});

test('Nginx Gateway: Rate limiting on API routes (/api/) returns HTTP 429 upon bursting', async (t) => {
  const active = await isNginxRunning();
  if (!active) {
    t.skip('Nginx container is not active; skipping API rate limiting test');
    return;
  }

  // Rate limit for /api/ is 15r/s with burst=25.
  // Sending 50 concurrent requests will cleanly exceed the burst limit.
  const requests = Array.from({ length: 50 }, () =>
    fetch(`${HTTP_URL}/api/health`)
  );

  const responses = await Promise.all(requests);
  const statusCodes = responses.map(r => r.status);

  const has429 = statusCodes.includes(429);
  assert.ok(has429, `Rapid API requests must trigger rate limiting (HTTP 429). Received status codes: ${statusCodes.slice(0, 15).join(', ')}...`);
});
