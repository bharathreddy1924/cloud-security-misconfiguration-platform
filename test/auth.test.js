process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-suite-session-secret-must-be-32-chars-long';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const app = require('../server');
const {
  isGoogleOAuthConfigured,
  generateAuthUrl,
  exchangeCodeForTokens,
  fetchGoogleUserProfile,
  requireAuthApi,
  requireAuthPage
} = require('../src/auth');

let server;
let baseUrl;

test.before(async () => {
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

function getCookie(response) {
  const setCookie = response.headers.get('set-cookie');
  if (!setCookie) return '';
  return setCookie.split(';')[0];
}

// ---------------------------------------------------------------------------
// 1. Public vs Protected Routes
// ---------------------------------------------------------------------------

test('GET /api/health is publicly accessible and reports status and auth info', async () => {
  const res = await fetch(`${baseUrl}/api/health`);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.status, 'ok');
  assert.ok('database' in data);
  assert.ok('auth' in data);
  assert.equal(data.auth.provider, 'google');
});

test('GET /login is public and serves the sign-in page with Continue with Google', async () => {
  const res = await fetch(`${baseUrl}/login`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.ok(html.includes('Sign in to CloudSec'));
  assert.ok(html.includes('Continue with Google'));
  assert.ok(html.includes('/auth/google'));
});

test('GET / redirects unauthenticated browser users to /login', async () => {
  const res = await fetch(`${baseUrl}/`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/login');
});

test('GET /index.html redirects to / (which enforces authentication)', async () => {
  const res = await fetch(`${baseUrl}/index.html`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/');
});

test('GET /app.js redirects unauthenticated requests to /login', async () => {
  const res = await fetch(`${baseUrl}/app.js`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/login');
});

test('POST /api/scan returns 401 Unauthorized when unauthenticated', async () => {
  const res = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      resources: [{ id: 'b1', type: 's3', publicAccess: true }]
    })
  });
  assert.equal(res.status, 401);
  const data = await res.json();
  assert.equal(data.error, 'Unauthorized');
  assert.ok(data.message.includes('Authentication required'));
});

test('GET /api/scans returns 401 Unauthorized when unauthenticated', async () => {
  const res = await fetch(`${baseUrl}/api/scans`);
  assert.equal(res.status, 401);
  const data = await res.json();
  assert.equal(data.error, 'Unauthorized');
});

test('GET /api/auth/me returns 401 when no session exists', async () => {
  const res = await fetch(`${baseUrl}/api/auth/me`);
  assert.equal(res.status, 401);
  const data = await res.json();
  assert.equal(data.authenticated, false);
});

// ---------------------------------------------------------------------------
// 2. OAuth Initiation & CSRF State Protection
// ---------------------------------------------------------------------------

test('GET /auth/google redirects to Google consent endpoint when credentials configured', async () => {
  const savedId = process.env.GOOGLE_CLIENT_ID;
  const savedSecret = process.env.GOOGLE_CLIENT_SECRET;
  const savedCallback = process.env.GOOGLE_CALLBACK_URL;

  process.env.GOOGLE_CLIENT_ID = 'test-client-id-12345.apps.googleusercontent.com';
  process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret-abcde';
  process.env.GOOGLE_CALLBACK_URL = 'http://127.0.0.1:3000/auth/google/callback';

  try {
    const res = await fetch(`${baseUrl}/auth/google`, { redirect: 'manual' });
    assert.equal(res.status, 302);
    const location = res.headers.get('location');
    assert.ok(location);
    const targetUrl = new URL(location);
    assert.equal(targetUrl.origin, 'https://accounts.google.com');
    assert.equal(targetUrl.pathname, '/o/oauth2/v2/auth');
    assert.equal(targetUrl.searchParams.get('client_id'), 'test-client-id-12345.apps.googleusercontent.com');
    assert.equal(targetUrl.searchParams.get('redirect_uri'), 'http://127.0.0.1:3000/auth/google/callback');
    assert.equal(targetUrl.searchParams.get('response_type'), 'code');
    assert.equal(targetUrl.searchParams.get('scope'), 'openid email profile');
    assert.ok(targetUrl.searchParams.get('state'), 'CSRF state parameter must be present');
    assert.equal(targetUrl.searchParams.get('state').length, 64); // 32 bytes hex
  } finally {
    process.env.GOOGLE_CLIENT_ID = savedId;
    process.env.GOOGLE_CLIENT_SECRET = savedSecret;
    process.env.GOOGLE_CALLBACK_URL = savedCallback;
  }
});

test('GET /auth/google redirects to /login?error=unconfigured when credentials missing', async () => {
  const savedId = process.env.GOOGLE_CLIENT_ID;
  const savedSecret = process.env.GOOGLE_CLIENT_SECRET;

  process.env.GOOGLE_CLIENT_ID = '';
  process.env.GOOGLE_CLIENT_SECRET = '';

  try {
    const res = await fetch(`${baseUrl}/auth/google`, { redirect: 'manual' });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/login?error=unconfigured');
  } finally {
    process.env.GOOGLE_CLIENT_ID = savedId;
    process.env.GOOGLE_CLIENT_SECRET = savedSecret;
  }
});

test('GET /auth/google/callback returns 403 on missing or invalid state (CSRF protection)', async () => {
  // Request callback without state
  const res1 = await fetch(`${baseUrl}/auth/google/callback?code=mock_code`, { redirect: 'manual' });
  assert.equal(res1.status, 403);
  const text1 = await res1.text();
  assert.ok(text1.includes('CSRF protection'));

  // Request callback with random forged state
  const res2 = await fetch(`${baseUrl}/auth/google/callback?code=mock_code&state=forged_state_value`, { redirect: 'manual' });
  assert.equal(res2.status, 403);
  const text2 = await res2.text();
  assert.ok(text2.includes('CSRF protection'));
});

test('GET /auth/google/callback handles Google error response', async () => {
  const res = await fetch(`${baseUrl}/auth/google/callback?error=access_denied`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/login?error=access_denied');
});

// ---------------------------------------------------------------------------
// 3. End-to-End OAuth Verification Flow with Mock Token Exchange
// ---------------------------------------------------------------------------

test('Complete Google OAuth login flow succeeds and creates authenticated session', async () => {
  const savedId = process.env.GOOGLE_CLIENT_ID;
  const savedSecret = process.env.GOOGLE_CLIENT_SECRET;
  const originalFetch = globalThis.fetch;

  process.env.GOOGLE_CLIENT_ID = 'test-client-id-12345.apps.googleusercontent.com';
  process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret-abcde';

  // Mock Google OAuth endpoints
  globalThis.fetch = async (url, options = {}) => {
    const urlStr = String(url);
    if (urlStr === 'https://oauth2.googleapis.com/token') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          access_token: 'mock-google-access-token-xyz',
          id_token: 'mock-google-id-token-xyz',
          token_type: 'Bearer',
          expires_in: 3600
        }),
        text: async () => ''
      };
    }
    if (urlStr === 'https://www.googleapis.com/oauth2/v3/userinfo') {
      assert.equal(options.headers?.Authorization, 'Bearer mock-google-access-token-xyz');
      return {
        ok: true,
        status: 200,
        json: async () => ({
          sub: 'google-sub-998877',
          email: 'auditor@example.com',
          email_verified: true,
          name: 'Lead Cloud Auditor',
          picture: 'https://lh3.googleusercontent.com/test-avatar'
        }),
        text: async () => ''
      };
    }
    return originalFetch(url, options);
  };

  try {
    // Step 1: Initiate OAuth to obtain state and session cookie
    const initRes = await fetch(`${baseUrl}/auth/google`, { redirect: 'manual' });
    assert.equal(initRes.status, 302);
    const sessionCookie = getCookie(initRes);
    assert.ok(sessionCookie.includes('cloudsec.sid'), 'Session cookie should be issued');

    const redirectUrl = new URL(initRes.headers.get('location'));
    const state = redirectUrl.searchParams.get('state');
    assert.ok(state);

    // Step 2: Callback with matching state and authorization code
    const callbackRes = await fetch(`${baseUrl}/auth/google/callback?code=mock-auth-code&state=${state}`, {
      headers: { Cookie: sessionCookie },
      redirect: 'manual'
    });

    assert.equal(callbackRes.status, 302);
    assert.equal(callbackRes.headers.get('location'), '/');

    // Update session cookie if new cookie was issued, otherwise keep existing
    const updatedCookie = getCookie(callbackRes) || sessionCookie;

    // Step 3: Access /api/auth/me to verify user session identity
    const meRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Cookie: updatedCookie }
    });
    assert.equal(meRes.status, 200);
    const meData = await meRes.json();
    assert.equal(meData.authenticated, true);
    assert.equal(meData.user.email, 'auditor@example.com');
    assert.equal(meData.user.name, 'Lead Cloud Auditor');
    assert.equal(meData.user.googleId, 'google-sub-998877');
    assert.equal(meData.user.picture, 'https://lh3.googleusercontent.com/test-avatar');

    // Step 4: Access protected dashboard GET /
    const dashboardRes = await fetch(`${baseUrl}/`, {
      headers: { Cookie: updatedCookie },
      redirect: 'manual'
    });
    assert.equal(dashboardRes.status, 200);
    const dashboardHtml = await dashboardRes.text();
    assert.ok(dashboardHtml.includes('Find misconfigurations'));

    // Step 5: Perform protected security scan
    const scanRes = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': updatedCookie
      },
      body: JSON.stringify({
        resources: [
          { id: 'prod-bucket', type: 's3', publicAccess: true, encryptionEnabled: false },
          { id: 'admin-sg', type: 'security-group', ingress: [{ port: 22, cidr: '0.0.0.0/0' }] }
        ]
      })
    });
    assert.equal(scanRes.status, 200);
    const scanData = await scanRes.json();
    assert.equal(scanData.resourceCount, 2);
    assert.equal(scanData.summary.total, 3); // public S3, unencrypted S3, open SSH
    assert.equal(scanData.summary.critical, 2);
    assert.equal(scanData.summary.high, 1);

    // Step 6: Perform Logout
    const logoutRes = await fetch(`${baseUrl}/auth/logout`, {
      headers: { Cookie: updatedCookie },
      redirect: 'manual'
    });
    assert.equal(logoutRes.status, 302);
    assert.equal(logoutRes.headers.get('location'), '/login?status=logged_out');

    // Step 7: Verify session is destroyed after logout
    const postLogoutMe = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { Cookie: updatedCookie }
    });
    assert.equal(postLogoutMe.status, 401);

    const postLogoutScan = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': updatedCookie
      },
      body: JSON.stringify({ resources: [{ id: 'test', type: 's3', publicAccess: true }] })
    });
    assert.equal(postLogoutScan.status, 401);
  } finally {
    globalThis.fetch = originalFetch;
    process.env.GOOGLE_CLIENT_ID = savedId;
    process.env.GOOGLE_CLIENT_SECRET = savedSecret;
  }
});

// ---------------------------------------------------------------------------
// 4. Session Injection & Scan API Validation
// ---------------------------------------------------------------------------

test('POST /api/scan input validation with authenticated session', async () => {
  // Create session using test helper endpoint
  const sessionRes = await fetch(`${baseUrl}/auth/test-session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user: { id: 'u1', googleId: 'g1', email: 'test@cloudsec.local', name: 'Tester' }
    })
  });
  assert.equal(sessionRes.status, 200);
  const sessionCookie = getCookie(sessionRes);

  // Test missing or empty resources array
  const emptyRes = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': sessionCookie },
    body: JSON.stringify({ resources: [] })
  });
  assert.equal(emptyRes.status, 400);

  // Test non-array resources
  const badRes = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': sessionCookie },
    body: JSON.stringify({ resources: 'not-an-array' })
  });
  assert.equal(badRes.status, 400);

  // Test scan with sample inventory
  const sampleRes = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': sessionCookie },
    body: JSON.stringify({
      resources: [
        { id: 'b1', type: 's3', publicAccess: true, encryptionEnabled: false },
        { id: 'sg1', type: 'security-group', ingress: [{ port: 22, cidr: '0.0.0.0/0' }] },
        { id: 'iam1', type: 'iam-policy', action: '*', resource: '*' },
        { id: 'db1', type: 'database', publiclyAccessible: true },
        { id: 'ct1', type: 'cloudtrail', enabled: false },
        { id: 'vol1', type: 'ebs', encrypted: false }
      ]
    })
  });
  assert.equal(sampleRes.status, 200);
  const data = await sampleRes.json();
  assert.equal(data.resourceCount, 6);
  // Expect findings:
  // 1. S3_PUBLIC_ACCESS (Critical)
  // 2. S3_ENCRYPTION_DISABLED (High)
  // 3. OPEN_SSH (Critical)
  // 4. IAM_WILDCARD_POLICY (High)
  // 5. DATABASE_PUBLIC (Critical)
  // 6. CLOUDTRAIL_DISABLED (Medium)
  // 7. EBS_ENCRYPTION_DISABLED (Medium)
  assert.equal(data.findings.length, 7);
  assert.equal(data.summary.total, 7);
  assert.equal(data.summary.critical, 3);
  assert.equal(data.summary.high, 2);
  assert.equal(data.summary.medium, 2);
});

test('POST /api/scan with sample-inventory.json produces exactly 6 findings for authenticated Google user', async () => {
  const sessionRes = await fetch(`${baseUrl}/auth/test-session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user: { id: 'u-google-1', googleId: 'g-101', email: 'auditor@university.edu', name: 'Cloud Auditor' }
    })
  });
  assert.equal(sessionRes.status, 200);
  const sessionCookie = getCookie(sessionRes);

  const samplePayload = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'sample-inventory.json'), 'utf8'));
  const scanRes = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': sessionCookie
    },
    body: JSON.stringify(samplePayload)
  });
  assert.equal(scanRes.status, 200);
  const data = await scanRes.json();
  assert.equal(data.resourceCount, 6);
  assert.equal(data.summary.total, 6);
  assert.equal(data.summary.critical, 3);
  assert.equal(data.summary.high, 2);
  assert.equal(data.summary.medium, 1);
  assert.equal(data.summary.low, 0);
  assert.equal(data.findings.length, 6);
  assert.deepEqual(
    data.findings.map(f => f.ruleId).sort(),
    ['CLOUDTRAIL_DISABLED', 'DATABASE_PUBLIC', 'IAM_WILDCARD_POLICY', 'OPEN_SSH', 'S3_ENCRYPTION_DISABLED', 'S3_PUBLIC_ACCESS'].sort()
  );
});

test('GET /api/scans requires authentication and retrieves scan history when DB connected or 503 if disconnected', async () => {
  const sessionRes = await fetch(`${baseUrl}/auth/test-session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user: { id: 'u-google-1', googleId: 'g-101', email: 'auditor@university.edu', name: 'Cloud Auditor' }
    })
  });
  assert.equal(sessionRes.status, 200);
  const sessionCookie = getCookie(sessionRes);

  const res = await fetch(`${baseUrl}/api/scans`, {
    headers: { 'Cookie': sessionCookie }
  });

  if (mongoose.connection.readyState === 1) {
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data));
  } else {
    assert.equal(res.status, 503);
    const data = await res.json();
    assert.equal(data.error, 'Database is not connected.');
  }
});
