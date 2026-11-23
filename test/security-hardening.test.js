process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-suite-session-secret-must-be-32-chars-long';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../server');
const { validateSessionSecret } = require('../server');

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

// ---------------------------------------------------------------------------
// Security Hardening Test Suite
// ---------------------------------------------------------------------------

test('Security Hardening: X-Powered-By header is disabled on all HTTP responses', async () => {
  const healthRes = await fetch(`${baseUrl}/api/health`);
  assert.equal(healthRes.headers.get('x-powered-by'), null, 'X-Powered-By should not be present on API responses');

  const loginRes = await fetch(`${baseUrl}/login`);
  assert.equal(loginRes.headers.get('x-powered-by'), null, 'X-Powered-By should not be present on page responses');
});

test('Security Hardening: validateSessionSecret enforces strict secret requirements in production', () => {
  // Production: rejects undefined, null, empty
  assert.throws(() => {
    validateSessionSecret(undefined, 'production');
  }, /FATAL: A secure, non-default SESSION_SECRET must be configured in production/);

  assert.throws(() => {
    validateSessionSecret('', 'production');
  }, /FATAL: A secure, non-default SESSION_SECRET must be configured in production/);

  // Production: rejects known insecure defaults
  const insecureDefaults = [
    'cloudsec-dev-session-secret-change-in-production',
    'cloudsec-docker-session-secret-change-in-production',
    'secret',
    'keyboard cat',
    'changeme'
  ];
  for (const defaultSecret of insecureDefaults) {
    assert.throws(() => {
      validateSessionSecret(defaultSecret, 'production');
    }, /FATAL: A secure, non-default SESSION_SECRET must be configured in production/);
  }

  // Production: rejects secrets shorter than 16 characters
  assert.throws(() => {
    validateSessionSecret('short-secret', 'production');
  }, /FATAL: A secure, non-default SESSION_SECRET must be configured in production/);

  // Production: accepts strong secret (>= 16 chars)
  const strongSecret = 'super-secure-production-random-secret-key-12345';
  const validated = validateSessionSecret(strongSecret, 'production');
  assert.equal(validated, strongSecret);

  // Development/Test: allows fallback without throwing
  const devDefault = validateSessionSecret(undefined, 'development');
  assert.equal(devDefault, 'cloudsec-dev-session-secret-change-in-production');

  const testDefault = validateSessionSecret(undefined, 'test');
  assert.equal(testDefault, 'cloudsec-dev-session-secret-change-in-production');
});

test('Security Hardening: Unknown /api/* routes return structured JSON 404 responses', async () => {
  // GET on unmapped API endpoint
  const getRes = await fetch(`${baseUrl}/api/nonexistent-endpoint`);
  assert.equal(getRes.status, 404);
  assert.ok(getRes.headers.get('content-type').includes('application/json'));
  const getBody = await getRes.json();
  assert.equal(getBody.error, 'Not Found');
  assert.equal(getBody.message, 'API endpoint GET /api/nonexistent-endpoint does not exist.');

  // POST on unmapped API endpoint
  const postRes = await fetch(`${baseUrl}/api/v1/invalid-action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'test' })
  });
  assert.equal(postRes.status, 404);
  assert.ok(postRes.headers.get('content-type').includes('application/json'));
  const postBody = await postRes.json();
  assert.equal(postBody.error, 'Not Found');
  assert.equal(postBody.message, 'API endpoint POST /api/v1/invalid-action does not exist.');
});

test('Security Hardening: Session fixation prevention regenerates session ID on OAuth callback', async () => {
  const originalFetch = global.fetch;

  // Mock Google token and userinfo endpoints
  global.fetch = async (url, options) => {
    if (typeof url === 'string' && url.includes('oauth2.googleapis.com/token')) {
      return {
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          access_token: 'mock-access-token-security',
          token_type: 'Bearer',
          expires_in: 3600
        }),
        text: async () => ''
      };
    }
    if (typeof url === 'string' && url.includes('googleapis.com/oauth2/v3/userinfo')) {
      return {
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          sub: 'google-sub-fixed-id-1234',
          email: 'hardening@example.com',
          email_verified: true,
          name: 'Security Hardening Auditor',
          picture: 'https://lh3.googleusercontent.com/test-avatar'
        }),
        text: async () => ''
      };
    }
    return originalFetch(url, options);
  };

  try {
    // Step 1: Initiate OAuth to obtain initial unauthenticated session cookie
    const initRes = await fetch(`${baseUrl}/auth/google`, { redirect: 'manual' });
    const preAuthSetCookie = initRes.headers.get('set-cookie');
    assert.ok(preAuthSetCookie && preAuthSetCookie.includes('cloudsec.sid'), 'Initial session cookie should be issued');

    const preAuthSid = preAuthSetCookie.split(';')[0];
    const redirectUrl = new URL(initRes.headers.get('location'));
    const state = redirectUrl.searchParams.get('state');

    // Step 2: Callback with matching state
    const callbackRes = await fetch(`${baseUrl}/auth/google/callback?code=mock-code-123&state=${state}`, {
      headers: { Cookie: preAuthSid },
      redirect: 'manual'
    });

    assert.equal(callbackRes.status, 302);
    assert.equal(callbackRes.headers.get('location'), '/');

    // Step 3: Verify session fixation prevention - a NEW session cookie must be issued
    const postAuthSetCookie = callbackRes.headers.get('set-cookie');
    assert.ok(postAuthSetCookie && postAuthSetCookie.includes('cloudsec.sid'), 'Post-auth session cookie must be set upon regeneration');
    const postAuthSid = postAuthSetCookie.split(';')[0];

    assert.notEqual(preAuthSid, postAuthSid, 'Pre-authentication session ID must not equal post-authentication session ID (session fixation prevention)');
  } finally {
    global.fetch = originalFetch;
  }
});

