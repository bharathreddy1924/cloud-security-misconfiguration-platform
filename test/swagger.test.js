process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-suite-session-secret-must-be-32-chars-long';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../server');

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
// Swagger / OpenAPI Test Suite
// ---------------------------------------------------------------------------

test('GET /api-docs and /api-docs/ load Swagger UI documentation successfully', async () => {
  // Direct access with trailing slash
  const resWithSlash = await fetch(`${baseUrl}/api-docs/`);
  assert.equal(resWithSlash.status, 200);
  const contentType = resWithSlash.headers.get('content-type');
  assert.ok(contentType.includes('text/html'), 'Response should be HTML');
  const html = await resWithSlash.text();
  assert.ok(html.includes('swagger-ui'), 'HTML should contain swagger-ui assets');

  // Access without trailing slash (follows 301 redirect to /api-docs/)
  const resNoSlash = await fetch(`${baseUrl}/api-docs`);
  assert.equal(resNoSlash.status, 200);
  const textNoSlash = await resNoSlash.text();
  assert.ok(textNoSlash.includes('swagger-ui'), 'Redirected response should contain swagger-ui');
});

test('GET /api-docs.json serves valid OpenAPI 3.x JSON specification', async () => {
  const res = await fetch(`${baseUrl}/api-docs.json`);
  assert.equal(res.status, 200);
  const contentType = res.headers.get('content-type');
  assert.ok(contentType.includes('application/json'), 'Content-Type should be application/json');

  const spec = await res.json();
  assert.ok(spec.openapi && spec.openapi.startsWith('3.'), 'Should be OpenAPI 3.x');
  assert.equal(spec.info.title, 'Cloud Security Misconfiguration Detection Platform API');
  assert.ok(spec.info.version, 'Should have version');
  assert.ok(spec.paths, 'Should have paths object');
});

test('OpenAPI specification documents all production API endpoints', async () => {
  const res = await fetch(`${baseUrl}/api-docs.json`);
  const spec = await res.json();

  // 1. Health endpoint
  assert.ok(spec.paths['/api/health'], 'GET /api/health must be documented');
  assert.ok(spec.paths['/api/health'].get, 'GET /api/health operation must exist');

  // 2. Current user profile endpoint
  assert.ok(spec.paths['/api/auth/me'], 'GET /api/auth/me must be documented');
  assert.ok(spec.paths['/api/auth/me'].get, 'GET /api/auth/me operation must exist');

  // 3. Scan execution endpoint
  assert.ok(spec.paths['/api/scan'], 'POST /api/scan must be documented');
  assert.ok(spec.paths['/api/scan'].post, 'POST /api/scan operation must exist');

  // 4. Scan history endpoint
  assert.ok(spec.paths['/api/scans'], 'GET /api/scans must be documented');
  assert.ok(spec.paths['/api/scans'].get, 'GET /api/scans operation must exist');

  // 5. Google OAuth endpoints
  assert.ok(spec.paths['/auth/google'], 'GET /auth/google must be documented');
  assert.ok(spec.paths['/auth/google'].get, 'GET /auth/google operation must exist');
  assert.ok(spec.paths['/auth/google/callback'], 'GET /auth/google/callback must be documented');
  assert.ok(spec.paths['/auth/google/callback'].get, 'GET /auth/google/callback operation must exist');

  // 6. Logout endpoints (both GET and POST)
  assert.ok(spec.paths['/auth/logout'], '/auth/logout must be documented');
  assert.ok(spec.paths['/auth/logout'].get, 'GET /auth/logout must exist');
  assert.ok(spec.paths['/auth/logout'].post, 'POST /auth/logout must exist');
});

test('OpenAPI specification documents session cookie authentication (cloudsec.sid)', async () => {
  const res = await fetch(`${baseUrl}/api-docs.json`);
  const spec = await res.json();

  // Verify securityScheme definition
  assert.ok(spec.components?.securitySchemes?.CookieAuth, 'CookieAuth security scheme must be defined');
  const cookieAuth = spec.components.securitySchemes.CookieAuth;
  assert.equal(cookieAuth.type, 'apiKey');
  assert.equal(cookieAuth.in, 'cookie');
  assert.equal(cookieAuth.name, 'cloudsec.sid');

  // Verify protected endpoints require CookieAuth
  const scanPost = spec.paths['/api/scan']?.post;
  assert.ok(scanPost.security, 'POST /api/scan must specify security requirement');
  assert.ok(scanPost.security.some((s) => 'CookieAuth' in s), 'POST /api/scan requires CookieAuth');

  const scansGet = spec.paths['/api/scans']?.get;
  assert.ok(scansGet.security, 'GET /api/scans must specify security requirement');
  assert.ok(scansGet.security.some((s) => 'CookieAuth' in s), 'GET /api/scans requires CookieAuth');

  const authMeGet = spec.paths['/api/auth/me']?.get;
  assert.ok(authMeGet.security, 'GET /api/auth/me must specify security requirement');
  assert.ok(authMeGet.security.some((s) => 'CookieAuth' in s), 'GET /api/auth/me requires CookieAuth');
});

test('OpenAPI specification documents all 8 cloud security scanning rules', async () => {
  const res = await fetch(`${baseUrl}/api-docs.json`);
  const spec = await res.json();

  const expectedRules = [
    'S3_PUBLIC_ACCESS',
    'S3_ENCRYPTION_DISABLED',
    'OPEN_SSH',
    'OPEN_RDP',
    'IAM_WILDCARD_POLICY',
    'DATABASE_PUBLIC',
    'CLOUDTRAIL_DISABLED',
    'EBS_ENCRYPTION_DISABLED'
  ];

  // Check rule enum in ScanFinding schema
  const ruleEnum = spec.components?.schemas?.ScanFinding?.properties?.ruleId?.enum;
  assert.ok(Array.isArray(ruleEnum), 'ScanFinding.ruleId must define enum of rule IDs');
  for (const rule of expectedRules) {
    assert.ok(ruleEnum.includes(rule), `Enum must include rule ${rule}`);
  }

  // Check description of /api/scan documents rules
  const scanDesc = spec.paths['/api/scan']?.post?.description || '';
  for (const rule of expectedRules) {
    assert.ok(scanDesc.includes(rule), `/api/scan description must reference rule ${rule}`);
  }
});

test('Protected API endpoints remain protected despite public Swagger documentation', async () => {
  // Swagger UI and JSON are public
  const docsRes = await fetch(`${baseUrl}/api-docs/`);
  assert.equal(docsRes.status, 200);

  const jsonRes = await fetch(`${baseUrl}/api-docs.json`);
  assert.equal(jsonRes.status, 200);

  // But protected endpoints still require authentication
  const scanRes = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resources: [{ id: 'test', type: 's3', publicAccess: true }] })
  });
  assert.equal(scanRes.status, 401);
  const scanBody = await scanRes.json();
  assert.equal(scanBody.error, 'Unauthorized');

  const scansRes = await fetch(`${baseUrl}/api/scans`);
  assert.equal(scansRes.status, 401);

  const meRes = await fetch(`${baseUrl}/api/auth/me`);
  assert.equal(meRes.status, 401);
});

test('Test-only endpoint /auth/test-session is not exposed in OpenAPI documentation', async () => {
  const res = await fetch(`${baseUrl}/api-docs.json`);
  const spec = await res.json();

  assert.equal(spec.paths['/auth/test-session'], undefined, '/auth/test-session must NOT be in OpenAPI spec');
});
