const test = require('node:test');
const assert = require('node:assert/strict');
const {
  isGoogleOAuthConfigured,
  generateAuthUrl,
  exchangeCodeForTokens,
  fetchGoogleUserProfile,
  requireAuthApi,
  requireAuthPage
} = require('../src/auth');

test('isGoogleOAuthConfigured validates environment credentials correctly', () => {
  const origId = process.env.GOOGLE_CLIENT_ID;
  const origSecret = process.env.GOOGLE_CLIENT_SECRET;

  process.env.GOOGLE_CLIENT_ID = '';
  process.env.GOOGLE_CLIENT_SECRET = '';
  assert.equal(isGoogleOAuthConfigured(), false);

  process.env.GOOGLE_CLIENT_ID = 'your-google-client-id.apps.googleusercontent.com';
  process.env.GOOGLE_CLIENT_SECRET = 'your-google-client-secret';
  assert.equal(isGoogleOAuthConfigured(), false);

  process.env.GOOGLE_CLIENT_ID = 'valid-12345.apps.googleusercontent.com';
  process.env.GOOGLE_CLIENT_SECRET = 'valid-secret-999';
  assert.equal(isGoogleOAuthConfigured(), true);

  process.env.GOOGLE_CLIENT_ID = origId;
  process.env.GOOGLE_CLIENT_SECRET = origSecret;
});

test('generateAuthUrl creates valid Google OAuth URL with CSRF state', () => {
  const origId = process.env.GOOGLE_CLIENT_ID;
  const origSecret = process.env.GOOGLE_CLIENT_SECRET;
  const origCallback = process.env.GOOGLE_CALLBACK_URL;

  process.env.GOOGLE_CLIENT_ID = 'client-xyz.apps.googleusercontent.com';
  process.env.GOOGLE_CLIENT_SECRET = 'secret-xyz';
  process.env.GOOGLE_CALLBACK_URL = 'http://localhost:3000/auth/google/callback';

  const mockReq = { session: {} };
  const authUrlStr = generateAuthUrl(mockReq);
  assert.ok(authUrlStr);

  const authUrl = new URL(authUrlStr);
  assert.equal(authUrl.origin, 'https://accounts.google.com');
  assert.equal(authUrl.pathname, '/o/oauth2/v2/auth');
  assert.equal(authUrl.searchParams.get('client_id'), 'client-xyz.apps.googleusercontent.com');
  assert.equal(authUrl.searchParams.get('redirect_uri'), 'http://localhost:3000/auth/google/callback');
  assert.equal(authUrl.searchParams.get('response_type'), 'code');
  assert.equal(authUrl.searchParams.get('scope'), 'openid email profile');
  assert.ok(mockReq.session.oauthState);
  assert.equal(authUrl.searchParams.get('state'), mockReq.session.oauthState);

  process.env.GOOGLE_CLIENT_ID = origId;
  process.env.GOOGLE_CLIENT_SECRET = origSecret;
  process.env.GOOGLE_CALLBACK_URL = origCallback;
});

test('exchangeCodeForTokens sends correct POST payload to Google token endpoint', async () => {
  const origId = process.env.GOOGLE_CLIENT_ID;
  const origSecret = process.env.GOOGLE_CLIENT_SECRET;

  process.env.GOOGLE_CLIENT_ID = 'test-id';
  process.env.GOOGLE_CLIENT_SECRET = 'test-secret';

  let capturedUrl = null;
  let capturedOptions = null;

  const mockFetch = async (url, options) => {
    capturedUrl = url;
    capturedOptions = options;
    return {
      ok: true,
      status: 200,
      json: async () => ({ access_token: 'tok-123', id_token: 'id-123' }),
      text: async () => ''
    };
  };

  const tokens = await exchangeCodeForTokens('auth-code-1', 'http://localhost:3000/callback', mockFetch);
  assert.equal(tokens.access_token, 'tok-123');
  assert.equal(capturedUrl, 'https://oauth2.googleapis.com/token');
  assert.equal(capturedOptions.method, 'POST');
  assert.equal(capturedOptions.headers['Content-Type'], 'application/x-www-form-urlencoded');

  const bodyParams = new URLSearchParams(capturedOptions.body);
  assert.equal(bodyParams.get('code'), 'auth-code-1');
  assert.equal(bodyParams.get('client_id'), 'test-id');
  assert.equal(bodyParams.get('client_secret'), 'test-secret');
  assert.equal(bodyParams.get('grant_type'), 'authorization_code');

  process.env.GOOGLE_CLIENT_ID = origId;
  process.env.GOOGLE_CLIENT_SECRET = origSecret;
});

test('fetchGoogleUserProfile requests userinfo with Bearer token', async () => {
  let capturedHeaders = null;
  const mockFetch = async (url, options) => {
    capturedHeaders = options.headers;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        sub: 'sub-456',
        email: 'user@example.com',
        email_verified: true,
        name: 'Alex Auditor'
      }),
      text: async () => ''
    };
  };

  const profile = await fetchGoogleUserProfile('access-token-789', mockFetch);
  assert.equal(profile.sub, 'sub-456');
  assert.equal(profile.email, 'user@example.com');
  assert.equal(capturedHeaders.Authorization, 'Bearer access-token-789');
});

test('requireAuthApi blocks unauthenticated requests and permits authenticated sessions', () => {
  let calledNext = false;
  let returnedStatus = null;
  let returnedJson = null;

  const next = () => { calledNext = true; };
  const res = {
    status(code) {
      returnedStatus = code;
      return {
        json(payload) {
          returnedJson = payload;
        }
      };
    }
  };

  // Unauthenticated call
  requireAuthApi({ session: {} }, res, next);
  assert.equal(calledNext, false);
  assert.equal(returnedStatus, 401);
  assert.equal(returnedJson.error, 'Unauthorized');

  // Authenticated call
  calledNext = false;
  returnedStatus = null;
  requireAuthApi({ session: { user: { id: 'u1', email: 'test@cloudsec.local' } } }, res, next);
  assert.equal(calledNext, true);
  assert.equal(returnedStatus, null);
});

test('requireAuthPage redirects unauthenticated requests and permits authenticated sessions', () => {
  let calledNext = false;
  let redirectedTo = null;

  const next = () => { calledNext = true; };
  const res = {
    redirect(path) {
      redirectedTo = path;
    }
  };

  // Unauthenticated call
  requireAuthPage({ session: {} }, res, next);
  assert.equal(calledNext, false);
  assert.equal(redirectedTo, '/login');

  // Authenticated call
  calledNext = false;
  redirectedTo = null;
  requireAuthPage({ session: { user: { id: 'u1' } } }, res, next);
  assert.equal(calledNext, true);
  assert.equal(redirectedTo, null);
});
