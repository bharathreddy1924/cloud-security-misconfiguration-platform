process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-suite-session-secret-must-be-32-chars-long';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const app = require('../server');
const { persistUser } = require('../src/auth');

let server;
let baseUrl;
let isMongoAvailable = false;

test.before(async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/cloudsec';
  try {
    await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 2000 });
    isMongoAvailable = mongoose.connection.readyState === 1;
  } catch (_) {
    isMongoAvailable = false;
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
  if (isMongoAvailable && mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
});

function getCookie(response) {
  const setCookie = response.headers.get('set-cookie');
  if (!setCookie) return '';
  return setCookie.split(';')[0];
}

test('MongoDB integration: user persistence, scan saving, and scan history retrieval', async (t) => {
  if (!isMongoAvailable) {
    t.skip('Local MongoDB instance is not connected; skipping live DB test');
    return;
  }

  // 1. Verify User model persistence
  const googleProfile = {
    sub: 'google-test-sub-persist-001',
    email: 'cloud.lead@university.edu',
    name: 'Cloud Security Lead',
    picture: 'https://lh3.googleusercontent.com/avatar001.jpg'
  };
  const persistedUser = await persistUser(googleProfile);
  assert.ok(persistedUser);
  assert.equal(persistedUser.email, 'cloud.lead@university.edu');
  assert.equal(persistedUser.googleId, 'google-test-sub-persist-001');

  // 2. Establish session for this Google user
  const sessionRes = await fetch(`${baseUrl}/auth/test-session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user: {
        id: persistedUser._id.toString(),
        googleId: persistedUser.googleId,
        email: persistedUser.email,
        name: persistedUser.name,
        picture: persistedUser.picture
      }
    })
  });
  assert.equal(sessionRes.status, 200);
  const cookie = getCookie(sessionRes);

  // 3. Execute sample inventory scan
  const sampleData = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'sample-inventory.json'), 'utf8'));
  const scanRes = await fetch(`${baseUrl}/api/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': cookie
    },
    body: JSON.stringify(sampleData)
  });
  assert.equal(scanRes.status, 200);
  const scanJson = await scanRes.json();

  assert.equal(scanJson.persistence, 'saved', 'Scan must be saved to MongoDB');
  assert.ok(scanJson.scanId, 'Scan response must include scanId');
  assert.equal(scanJson.resourceCount, 6);
  assert.equal(scanJson.summary.total, 6);
  assert.equal(scanJson.summary.critical, 3);
  assert.equal(scanJson.summary.high, 2);
  assert.equal(scanJson.summary.medium, 1);
  assert.equal(scanJson.summary.low, 0);

  // 4. Retrieve scan history via GET /api/scans
  const historyRes = await fetch(`${baseUrl}/api/scans`, {
    headers: { 'Cookie': cookie }
  });
  assert.equal(historyRes.status, 200);
  const historyList = await historyRes.json();
  assert.ok(Array.isArray(historyList));
  assert.ok(historyList.length >= 1);

  const matchedScan = historyList.find((s) => String(s._id) === String(scanJson.scanId));
  assert.ok(matchedScan, 'Saved scan must appear in /api/scans history');
  assert.equal(matchedScan.userEmail, 'cloud.lead@university.edu');
  assert.equal(matchedScan.resourceCount, 6);
  assert.equal(matchedScan.summary.total, 6);
  assert.equal(matchedScan.findings.length, 6);

  // 5. Query MongoDB directly to verify document integrity
  const Scan = app.Scan;
  const dbDoc = await Scan.findById(scanJson.scanId).lean();
  assert.ok(dbDoc);
  assert.equal(dbDoc.userEmail, 'cloud.lead@university.edu');
  assert.equal(dbDoc.resourceCount, 6);
  assert.equal(dbDoc.summary.total, 6);
  assert.equal(dbDoc.findings.length, 6);
});
