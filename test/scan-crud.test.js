process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-suite-session-secret-must-be-32-chars-long';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const mongoose = require('mongoose');
const app = require('../server');
const {
  Scan,
  buildScanOwnershipFilter,
  isValidScanId,
  validateScanMetadataPatch
} = require('../server');

let server;
let baseUrl;
let isMongoConnected = false;

test.before(async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/cloudsec';
  if (mongoose.connection.readyState === 0) {
    try {
      await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 2000 });
    } catch (_) {
      // MongoDB offline; unit/auth/validation/offline tests continue normally
    }
  }
  isMongoConnected = mongoose.connection.readyState === 1;

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
// 1. Pure Unit Tests (Always run without MongoDB)
// ---------------------------------------------------------------------------

test('Scan CRUD Unit: buildScanOwnershipFilter constructs strict user ownership filters', () => {
  assert.deepEqual(
    buildScanOwnershipFilter({ id: '  u-1  ', email: '  alice@cloudsec.local  ' }),
    { $or: [{ userEmail: 'alice@cloudsec.local' }, { userId: 'u-1' }] }
  );
  assert.deepEqual(
    buildScanOwnershipFilter({ email: 'alice@cloudsec.local' }),
    { userEmail: 'alice@cloudsec.local' }
  );
  assert.deepEqual(
    buildScanOwnershipFilter({ id: 'u-1' }),
    { userId: 'u-1' }
  );
  assert.equal(buildScanOwnershipFilter(null), null);
  assert.equal(buildScanOwnershipFilter(undefined), null);
  assert.equal(buildScanOwnershipFilter({}), null);
  assert.equal(buildScanOwnershipFilter({ email: '   ', id: '' }), null);
});

test('Scan CRUD Unit: isValidScanId accepts only canonical 24-hex ObjectId strings', () => {
  assert.equal(isValidScanId('507f1f77bcf86cd799439011'), true);
  assert.equal(isValidScanId('673DFA12B984FA001234ABCD'), true);
  assert.equal(isValidScanId('12charstring'), false, 'Must reject 12-char non-ObjectId strings');
  assert.equal(isValidScanId('invalid-id'), false);
  assert.equal(isValidScanId('507f1f77bcf86cd79943901z'), false);
  assert.equal(isValidScanId(''), false);
  assert.equal(isValidScanId(null), false);
});

test('Scan CRUD Unit: validateScanMetadataPatch enforces whitelist, limits, and server-controlled updatedAt', () => {
  const ok = validateScanMetadataPatch({
    name: '  Production Baseline  ',
    environment: ' production ',
    notes: '  Ticket SEC-142 tracked  '
  });
  assert.equal(ok.valid, true);
  assert.equal(ok.updates.name, 'Production Baseline');
  assert.equal(ok.updates.environment, 'production');
  assert.equal(ok.updates.notes, 'Ticket SEC-142 tracked');
  assert.ok(ok.updates.updatedAt instanceof Date);

  const cleared = validateScanMetadataPatch({ notes: '' });
  assert.equal(cleared.valid, true);
  assert.equal(cleared.updates.notes, '');

  const clientUpdatedAt = validateScanMetadataPatch({
    name: 'Valid',
    updatedAt: new Date().toISOString()
  });
  assert.equal(clientUpdatedAt.valid, false);
  assert.match(clientUpdatedAt.error, /updatedAt is server-controlled/);

  for (const field of ['findings', 'summary', 'userId', 'userEmail', 'resourceCount', 'createdAt', '_id', 'id']) {
    const res = validateScanMetadataPatch({ [field]: field === 'findings' ? [] : 'tampered' });
    assert.equal(res.valid, false, `Must reject protected field ${field}`);
    assert.match(res.error, new RegExp(`Cannot modify protected scan field: ${field}`));
  }

  const unknownField = validateScanMetadataPatch({ extraField: 'value' });
  assert.equal(unknownField.valid, false);
  assert.match(unknownField.error, /Unsupported field: extraField/);

  const emptyObj = validateScanMetadataPatch({});
  assert.equal(emptyObj.valid, false);

  const nonStringOperator = validateScanMetadataPatch({ name: { $ne: '' } });
  assert.equal(nonStringOperator.valid, false);
  assert.equal(nonStringOperator.error, 'name must be a string.');

  const tooLongName = validateScanMetadataPatch({ name: 'a'.repeat(121) });
  assert.equal(tooLongName.valid, false);
});

// ---------------------------------------------------------------------------
// 2. HTTP Guard, Auth, Validation, and Offline Tests (Always run without MongoDB)
// ---------------------------------------------------------------------------

test('Scan CRUD HTTP: unauthenticated GET, PATCH, and DELETE /api/scans/:id return 401', async () => {
  const targetId = '507f1f77bcf86cd799439011';

  const getRes = await fetch(`${baseUrl}/api/scans/${targetId}`);
  assert.equal(getRes.status, 401);

  const patchRes = await fetch(`${baseUrl}/api/scans/${targetId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Blocked' })
  });
  assert.equal(patchRes.status, 401);

  const deleteRes = await fetch(`${baseUrl}/api/scans/${targetId}`, {
    method: 'DELETE'
  });
  assert.equal(deleteRes.status, 401);
});

test('Scan CRUD HTTP: invalid scan ID returns 400 on GET, PATCH, and DELETE', async () => {
  const cookie = await createAuthenticatedSession({
    id: 'validation-user-1',
    googleId: 'g-validation-1',
    email: 'validator@cloudsec.local',
    name: 'Validator'
  });

  for (const badId of ['invalid-id', '12charstring']) {
    const getRes = await fetch(`${baseUrl}/api/scans/${badId}`, { headers: { Cookie: cookie } });
    assert.equal(getRes.status, 400);
    assert.equal((await getRes.json()).error, 'Invalid scan ID.');

    const patchRes = await fetch(`${baseUrl}/api/scans/${badId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ name: 'Test' })
    });
    assert.equal(patchRes.status, 400);
    assert.equal((await patchRes.json()).error, 'Invalid scan ID.');

    const deleteRes = await fetch(`${baseUrl}/api/scans/${badId}`, {
      method: 'DELETE',
      headers: { Cookie: cookie }
    });
    assert.equal(deleteRes.status, 400);
    assert.equal((await deleteRes.json()).error, 'Invalid scan ID.');
  }
});

test('Scan CRUD HTTP: PATCH rejects client-supplied updatedAt, findings, summary, userId, userEmail, and invalid bodies with 400', async () => {
  const cookie = await createAuthenticatedSession({
    id: 'patch-val-user',
    googleId: 'g-patch-val',
    email: 'patchval@cloudsec.local',
    name: 'Patch Validator'
  });
  const targetId = '507f1f77bcf86cd799439011';

  const updatedAtRes = await fetch(`${baseUrl}/api/scans/${targetId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify({ name: 'Updated', updatedAt: '2026-01-01T00:00:00.000Z' })
  });
  assert.equal(updatedAtRes.status, 400);
  const updatedAtBody = await updatedAtRes.json();
  assert.match(updatedAtBody.error, /updatedAt is server-controlled/);

  const forbiddenPayloads = [
    { findings: [] },
    { summary: { total: 0, critical: 0 } },
    { userId: 'attacker-id' },
    { userEmail: 'attacker@evil.com' },
    { createdAt: '2020-01-01T00:00:00.000Z' },
    { name: 'Ok', userId: 'attacker-id' },
    {},
    { name: { $gt: '' } },
    { environment: 'a'.repeat(51) }
  ];

  for (const payload of forbiddenPayloads) {
    const res = await fetch(`${baseUrl}/api/scans/${targetId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 400, `Expected 400 for payload: ${JSON.stringify(payload)}`);
  }
});

test('Scan CRUD HTTP: PUT /api/scans/:id is not implemented in Phase 1 (returns 404)', async () => {
  const cookie = await createAuthenticatedSession({
    id: 'put-check-user',
    googleId: 'g-put-check',
    email: 'putcheck@cloudsec.local',
    name: 'Put Checker'
  });

  const res = await fetch(`${baseUrl}/api/scans/507f1f77bcf86cd799439011`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify({ resources: [{ id: 'b1', type: 's3', publicAccess: true }] })
  });
  assert.equal(res.status, 404);
});

test('Scan CRUD HTTP: disconnected database returns 503 for GET, PATCH, and DELETE /api/scans/:id', async () => {
  try {
    Object.defineProperty(mongoose.connection, 'readyState', { value: 0, configurable: true });

    const cookie = await createAuthenticatedSession({
      id: 'offline-crud-user',
      googleId: 'g-offline-crud',
      email: 'offline.crud@cloudsec.local',
      name: 'Offline CRUD User'
    });
    const targetId = '507f1f77bcf86cd799439011';

    const getRes = await fetch(`${baseUrl}/api/scans/${targetId}`, { headers: { Cookie: cookie } });
    assert.equal(getRes.status, 503);
    assert.equal((await getRes.json()).error, 'Database is not connected.');

    const patchRes = await fetch(`${baseUrl}/api/scans/${targetId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ name: 'Should fail cleanly with 503' })
    });
    assert.equal(patchRes.status, 503);
    assert.equal((await patchRes.json()).error, 'Database is not connected.');

    const deleteRes = await fetch(`${baseUrl}/api/scans/${targetId}`, {
      method: 'DELETE',
      headers: { Cookie: cookie }
    });
    assert.equal(deleteRes.status, 503);
    assert.equal((await deleteRes.json()).error, 'Database is not connected.');
  } finally {
    delete mongoose.connection.readyState;
  }
});

test('Scan CRUD HTTP: enforces ownership filter in Mongoose queries and returns 404 when unowned (mocked DB)', async () => {
  const origFindOne = Scan.findOne;
  const origFindOneAndUpdate = Scan.findOneAndUpdate;
  const origFindOneAndDelete = Scan.findOneAndDelete;

  const targetId = '507f1f77bcf86cd799439011';
  let capturedFindFilter = null;
  let capturedUpdateFilter = null;
  let capturedDeleteFilter = null;

  try {
    Object.defineProperty(mongoose.connection, 'readyState', { value: 1, configurable: true });

    Scan.findOne = (filter) => {
      capturedFindFilter = filter;
      return { lean: async () => null };
    };
    Scan.findOneAndUpdate = (filter) => {
      capturedUpdateFilter = filter;
      return { lean: async () => null };
    };
    Scan.findOneAndDelete = (filter) => {
      capturedDeleteFilter = filter;
      return { lean: async () => null };
    };

    const cookie = await createAuthenticatedSession({
      id: 'owner-check-user',
      googleId: 'g-owner-check',
      email: 'owner@cloudsec.local',
      name: 'Owner User'
    });

    const getRes = await fetch(`${baseUrl}/api/scans/${targetId}`, { headers: { Cookie: cookie } });
    assert.equal(getRes.status, 404);
    assert.deepEqual(capturedFindFilter, {
      _id: targetId,
      $or: [{ userEmail: 'owner@cloudsec.local' }, { userId: 'owner-check-user' }]
    });

    const patchRes = await fetch(`${baseUrl}/api/scans/${targetId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ name: 'Attempt' })
    });
    assert.equal(patchRes.status, 404);
    assert.deepEqual(capturedUpdateFilter, {
      _id: targetId,
      $or: [{ userEmail: 'owner@cloudsec.local' }, { userId: 'owner-check-user' }]
    });

    const deleteRes = await fetch(`${baseUrl}/api/scans/${targetId}`, {
      method: 'DELETE',
      headers: { Cookie: cookie }
    });
    assert.equal(deleteRes.status, 404);
    assert.deepEqual(capturedDeleteFilter, {
      _id: targetId,
      $or: [{ userEmail: 'owner@cloudsec.local' }, { userId: 'owner-check-user' }]
    });
  } finally {
    delete mongoose.connection.readyState;
    Scan.findOne = origFindOne;
    Scan.findOneAndUpdate = origFindOneAndUpdate;
    Scan.findOneAndDelete = origFindOneAndDelete;
  }
});

// ---------------------------------------------------------------------------
// 3. Live MongoDB Integration Tests (Skip ONLY if MongoDB is disconnected)
// ---------------------------------------------------------------------------

test('Scan CRUD Live MongoDB: GET, PATCH metadata, and DELETE succeed for owner and preserve immutability', async (t) => {
  if (!isMongoConnected) {
    t.skip('MongoDB is disconnected; skipping live Scan CRUD integration test');
    return;
  }

  const suffix = Date.now();
  const owner = {
    id: `crud-owner-${suffix}`,
    googleId: `g-crud-owner-${suffix}`,
    email: `crud.owner.${suffix}@cloudsec.local`,
    name: 'CRUD Owner'
  };
  const cookie = await createAuthenticatedSession(owner);

  let createdScanId = null;
  try {
    // 1. Create scan via POST /api/scan
    const createRes = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({
        resources: [
          { id: 'bucket-1', type: 's3', publicAccess: true, encryptionEnabled: false }
        ]
      })
    });
    assert.equal(createRes.status, 200);
    const created = await createRes.json();
    createdScanId = created.scanId;
    assert.ok(createdScanId);

    // 2. Fetch single scan via GET /api/scans/:id
    const getRes = await fetch(`${baseUrl}/api/scans/${createdScanId}`, {
      headers: { Cookie: cookie }
    });
    assert.equal(getRes.status, 200);
    const fetched = await getRes.json();
    assert.equal(String(fetched._id), String(createdScanId));
    assert.equal(fetched.userEmail, owner.email);
    assert.equal(fetched.resourceCount, 1);
    assert.equal(fetched.summary.total, 2);
    assert.equal(fetched.name, '');
    assert.equal(fetched.updatedAt, null);

    // 3. Update metadata via PATCH /api/scans/:id
    const patchRes = await fetch(`${baseUrl}/api/scans/${createdScanId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({
        name: 'S3 Audit Baseline',
        environment: 'production',
        notes: 'Escalated to cloud ops'
      })
    });
    assert.equal(patchRes.status, 200);
    const updated = await patchRes.json();
    assert.equal(updated.name, 'S3 Audit Baseline');
    assert.equal(updated.environment, 'production');
    assert.equal(updated.notes, 'Escalated to cloud ops');
    assert.ok(updated.updatedAt, 'Server should set updatedAt on PATCH');
    // Verify immutable scan properties were preserved
    assert.equal(updated.summary.total, 2);
    assert.equal(updated.findings.length, 2);
    assert.equal(updated.userEmail, owner.email);
    assert.equal(updated.userId, owner.id);

    // 4. Delete scan via DELETE /api/scans/:id
    const deleteRes = await fetch(`${baseUrl}/api/scans/${createdScanId}`, {
      method: 'DELETE',
      headers: { Cookie: cookie }
    });
    assert.equal(deleteRes.status, 200);
    const deleteBody = await deleteRes.json();
    assert.deepEqual(deleteBody, { deleted: true, scanId: String(createdScanId) });

    // 5. Subsequent GET must return 404
    const afterDeleteRes = await fetch(`${baseUrl}/api/scans/${createdScanId}`, {
      headers: { Cookie: cookie }
    });
    assert.equal(afterDeleteRes.status, 404);
    createdScanId = null;
  } finally {
    if (createdScanId) {
      await Scan.deleteOne({ _id: createdScanId }).catch(() => {});
    }
  }
});

test('Scan CRUD Live MongoDB: cross-user ownership isolation blocks User B from reading, updating, or deleting User A scan', async (t) => {
  if (!isMongoConnected) {
    t.skip('MongoDB is disconnected; skipping live ownership isolation test');
    return;
  }

  const suffix = Date.now();
  const userA = {
    id: `iso-a-${suffix}`,
    googleId: `g-iso-a-${suffix}`,
    email: `iso.a.${suffix}@cloudsec.local`,
    name: 'User A'
  };
  const userB = {
    id: `iso-b-${suffix}`,
    googleId: `g-iso-b-${suffix}`,
    email: `iso.b.${suffix}@cloudsec.local`,
    name: 'User B'
  };

  const cookieA = await createAuthenticatedSession(userA);
  const cookieB = await createAuthenticatedSession(userB);

  let scanIdA = null;
  try {
    const createRes = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieA },
      body: JSON.stringify({
        resources: [{ id: 'db-prod', type: 'database', publiclyAccessible: true }]
      })
    });
    assert.equal(createRes.status, 200);
    scanIdA = (await createRes.json()).scanId;

    // User B tries GET, PATCH, and DELETE on User A's scan
    const getB = await fetch(`${baseUrl}/api/scans/${scanIdA}`, { headers: { Cookie: cookieB } });
    assert.equal(getB.status, 404);

    const patchB = await fetch(`${baseUrl}/api/scans/${scanIdA}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: cookieB },
      body: JSON.stringify({ name: 'Hijacked' })
    });
    assert.equal(patchB.status, 404);

    const deleteB = await fetch(`${baseUrl}/api/scans/${scanIdA}`, {
      method: 'DELETE',
      headers: { Cookie: cookieB }
    });
    assert.equal(deleteB.status, 404);

    // Verify User A's record is untouched in MongoDB
    const getA = await fetch(`${baseUrl}/api/scans/${scanIdA}`, { headers: { Cookie: cookieA } });
    assert.equal(getA.status, 200);
    const docA = await getA.json();
    assert.equal(docA.name, '');
    assert.equal(docA.userEmail, userA.email);
  } finally {
    if (scanIdA) {
      await Scan.deleteOne({ _id: scanIdA }).catch(() => {});
    }
  }
});

test('Scan CRUD Live MongoDB: backward compatibility with legacy scan documents lacking metadata fields', async (t) => {
  if (!isMongoConnected) {
    t.skip('MongoDB is disconnected; skipping live legacy document test');
    return;
  }

  const suffix = Date.now();
  const owner = {
    id: `legacy-owner-${suffix}`,
    googleId: `g-legacy-${suffix}`,
    email: `legacy.${suffix}@cloudsec.local`,
    name: 'Legacy Owner'
  };
  const cookie = await createAuthenticatedSession(owner);

  // Insert directly into MongoDB collection without name/environment/notes/updatedAt
  const insertRes = await Scan.collection.insertOne({
    createdAt: new Date(),
    resourceCount: 1,
    findings: [],
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    userEmail: owner.email,
    userId: owner.id
  });
  const legacyId = String(insertRes.insertedId);

  try {
    const getRes = await fetch(`${baseUrl}/api/scans/${legacyId}`, { headers: { Cookie: cookie } });
    assert.equal(getRes.status, 200);
    const legacyDoc = await getRes.json();
    assert.equal(String(legacyDoc._id), legacyId);

    const patchRes = await fetch(`${baseUrl}/api/scans/${legacyId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ name: 'Labeled Legacy Scan' })
    });
    assert.equal(patchRes.status, 200);
    const updated = await patchRes.json();
    assert.equal(updated.name, 'Labeled Legacy Scan');
    assert.ok(updated.updatedAt);

    const deleteRes = await fetch(`${baseUrl}/api/scans/${legacyId}`, {
      method: 'DELETE',
      headers: { Cookie: cookie }
    });
    assert.equal(deleteRes.status, 200);
  } finally {
    await Scan.collection.deleteOne({ _id: insertRes.insertedId }).catch(() => {});
  }
});
