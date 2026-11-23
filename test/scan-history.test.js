process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-suite-session-secret-must-be-32-chars-long';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const mongoose = require('mongoose');
const app = require('../server');

let server;
let baseUrl;

test.before(async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/cloudsec';
  if (mongoose.connection.readyState === 0) {
    try {
      await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 2000 });
    } catch (_) {
      // Offline fallback
    }
  }

  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
});

function getCookie(response) {
  const setCookie = response.headers.get('set-cookie');
  if (!setCookie) return '';
  return setCookie.split(';')[0];
}

async function createAuthenticatedSession(userData) {
  const sessionRes = await fetch(`${baseUrl}/auth/test-session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: userData })
  });
  assert.equal(sessionRes.status, 200);
  return getCookie(sessionRes);
}

// ---------------------------------------------------------------------------
// Scan History Test Suite
// ---------------------------------------------------------------------------

test('Scan History: GET /api/scans strictly requires authentication (401 Unauthorized)', async () => {
  const res = await fetch(`${baseUrl}/api/scans`);
  assert.equal(res.status, 401);
  const body = await res.json();
  assert.equal(body.error, 'Unauthorized');
  assert.ok(body.message.includes('Authentication required'));
});

test('Scan History: Empty scan history returns 200 with empty array for new user', async (t) => {
  if (mongoose.connection.readyState !== 1) {
    t.skip('MongoDB is not connected; skipping live history test');
    return;
  }

  const cookie = await createAuthenticatedSession({
    id: 'user-empty-history-id',
    googleId: 'google-empty-history-sub',
    email: 'new-auditor-no-history@university.edu',
    name: 'New Auditor'
  });

  const res = await fetch(`${baseUrl}/api/scans`, {
    headers: { Cookie: cookie }
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.ok(Array.isArray(data));
  assert.equal(data.length, 0, 'New user should have 0 scan history records');
});

test('Scan History: User-specific scan isolation ensures User A cannot view User B scans', async (t) => {
  if (mongoose.connection.readyState !== 1) {
    t.skip('MongoDB is not connected; skipping live history test');
    return;
  }

  const userA = {
    id: 'user-a-uuid-111',
    googleId: 'g-user-a',
    email: 'alice.auditor@firm-a.com',
    name: 'Alice Auditor'
  };
  const userB = {
    id: 'user-b-uuid-222',
    googleId: 'g-user-b',
    email: 'bob.security@firm-b.com',
    name: 'Bob Security'
  };

  const cookieA = await createAuthenticatedSession(userA);
  const cookieB = await createAuthenticatedSession(userB);

  // User A runs a scan
  const scanPayloadA = {
    resources: [
      { id: 'alice-bucket', type: 's3', publicAccess: true, encryptionEnabled: false }
    ]
  };
  const scanResA = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookieA },
    body: JSON.stringify(scanPayloadA)
  });
  assert.equal(scanResA.status, 200);
  const scanDataA = await scanResA.json();

  // User B runs a scan
  const scanPayloadB = {
    resources: [
      { id: 'bob-db', type: 'database', publiclyAccessible: true }
    ]
  };
  const scanResB = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookieB },
    body: JSON.stringify(scanPayloadB)
  });
  assert.equal(scanResB.status, 200);
  const scanDataB = await scanResB.json();

  // User A fetches history
  const historyResA = await fetch(`${baseUrl}/api/scans`, {
    headers: { Cookie: cookieA }
  });
  assert.equal(historyResA.status, 200);
  const historyA = await historyResA.json();

  // Verify User A only sees User A's scans
  const userAScanIds = historyA.map(s => String(s._id));
  assert.ok(userAScanIds.includes(String(scanDataA.scanId)), "User A's scan must be present in User A's history");
  assert.ok(!userAScanIds.includes(String(scanDataB.scanId)), "User B's scan must NEVER appear in User A's history");
  assert.ok(historyA.every(s => s.userEmail === userA.email || s.userId === userA.id), "All scans in User A's history must belong to User A");

  // User B fetches history
  const historyResB = await fetch(`${baseUrl}/api/scans`, {
    headers: { Cookie: cookieB }
  });
  assert.equal(historyResB.status, 200);
  const historyB = await historyResB.json();

  // Verify User B only sees User B's scans
  const userBScanIds = historyB.map(s => String(s._id));
  assert.ok(userBScanIds.includes(String(scanDataB.scanId)), "User B's scan must be present in User B's history");
  assert.ok(!userBScanIds.includes(String(scanDataA.scanId)), "User A's scan must NEVER appear in User B's history");
  assert.ok(historyB.every(s => s.userEmail === userB.email || s.userId === userB.id), "All scans in User B's history must belong to User B");
});

test('Scan History: Refreshing history after a successful scan includes the newly created record', async (t) => {
  if (mongoose.connection.readyState !== 1) {
    t.skip('MongoDB is not connected; skipping live history test');
    return;
  }

  const cookie = await createAuthenticatedSession({
    id: 'user-refresh-test-id',
    googleId: 'g-refresh-test',
    email: 'refresh.tester@cloudsec.local',
    name: 'Refresh Tester'
  });

  // Step 1: Initial history check
  const initialRes = await fetch(`${baseUrl}/api/scans`, {
    headers: { Cookie: cookie }
  });
  assert.equal(initialRes.status, 200);
  const initialHistory = await initialRes.json();
  const initialCount = initialHistory.length;

  // Step 2: Perform new scan
  const newScanRes = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify({
      resources: [
        { id: 'ssh-secgroup', type: 'security-group', ingress: [{ port: 22, cidr: '0.0.0.0/0' }] }
      ]
    })
  });
  assert.equal(newScanRes.status, 200);
  const newScanData = await newScanRes.json();

  // Step 3: Refresh history and verify new scan appears as newest (first) item
  const refreshedRes = await fetch(`${baseUrl}/api/scans`, {
    headers: { Cookie: cookie }
  });
  assert.equal(refreshedRes.status, 200);
  const refreshedHistory = await refreshedRes.json();

  assert.equal(refreshedHistory.length, initialCount + 1, 'History count should increase by 1 after scan');
  assert.equal(String(refreshedHistory[0]._id), String(newScanData.scanId), 'Newest scan must be first in the list');
  assert.equal(refreshedHistory[0].resourceCount, 1);
  assert.equal(refreshedHistory[0].summary.critical, 1);
  assert.equal(refreshedHistory[0].summary.total, 1);
});

test('Scan History: Database offline scenario returns 503 Service Unavailable', async () => {
  try {
    Object.defineProperty(mongoose.connection, 'readyState', { value: 0, configurable: true });

    const cookie = await createAuthenticatedSession({
      id: 'db-offline-test-user',
      googleId: 'g-offline-test',
      email: 'offline.test@cloudsec.local',
      name: 'Offline Tester'
    });

    const res = await fetch(`${baseUrl}/api/scans`, {
      headers: { Cookie: cookie }
    });

    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.error, 'Database is not connected.');
  } finally {
    delete mongoose.connection.readyState;
  }
});
