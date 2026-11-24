process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-suite-session-secret-must-be-32-chars-long';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const session = require('express-session');
const { MongoStore } = require('connect-mongo');
const app = require('../server');
const { createSessionStore, sessionStore } = require('../server');

const REPO_ROOT = path.resolve(__dirname, '..');
const TEST_PROD_SECRET = 'test-production-session-secret-must-be-32-chars';
const MOCK_MONGO_URI = 'mongodb://mock-mongo-host:27017/cloudsec';

/**
 * Finds the index of a layer in Express's router stack.
 */
function findLayerIndex(expressApp, predicate) {
  return expressApp._router.stack.findIndex(predicate);
}

/**
 * Runs a Node snippet in an isolated subprocess with explicit env overrides.
 */
function runServerProbe(envOverrides, script) {
  return spawnSync(process.execPath, ['-e', script], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      ...envOverrides
    },
    encoding: 'utf8',
    timeout: 10000
  });
}

test('Session Store: connect-mongo exposes MongoStore.create API', () => {
  assert.equal(typeof MongoStore, 'function');
  assert.equal(typeof MongoStore.create, 'function');
});

test('Session Store: createSessionStore retains MemoryStore (returns undefined) in development and test', () => {
  let factoryCalled = false;
  const mockFactory = {
    create() {
      factoryCalled = true;
      return {};
    }
  };

  assert.equal(createSessionStore('development', MOCK_MONGO_URI, mockFactory), undefined);
  assert.equal(createSessionStore('development', '', mockFactory), undefined);
  assert.equal(createSessionStore('test', MOCK_MONGO_URI, mockFactory), undefined);
  assert.equal(createSessionStore('test', undefined, mockFactory), undefined);
  assert.equal(createSessionStore(undefined, MOCK_MONGO_URI, mockFactory), undefined);
  assert.equal(factoryCalled, false, 'MongoStore.create must not be called outside production');
});

test('Session Store: createSessionStore fails fast in production when MONGODB_URI is missing', () => {
  let factoryCalled = false;
  const mockFactory = {
    create() {
      factoryCalled = true;
      return {};
    }
  };

  for (const invalidUri of [undefined, null, '', '   ']) {
    assert.throws(
      () => createSessionStore('production', invalidUri, mockFactory),
      /FATAL: MONGODB_URI must be configured in production for MongoDB session storage\./
    );
  }
  assert.equal(factoryCalled, false, 'MongoStore.create must not be called when MONGODB_URI is missing');
});

test('Session Store: createSessionStore configures MongoStore with expected options in production (mocked)', () => {
  let capturedOptions = null;
  class MockMongoStore extends session.Store {
    constructor(opts) {
      super();
      this.options = opts;
      this.collectionP = Promise.resolve();
    }
  }
  const mockFactory = {
    create(opts) {
      capturedOptions = opts;
      return new MockMongoStore(opts);
    }
  };

  const store = createSessionStore('production', `  ${MOCK_MONGO_URI}  `, mockFactory);
  assert.ok(store instanceof MockMongoStore, 'Production session store should be returned from MongoStore factory');
  assert.deepEqual(capturedOptions, {
    mongoUrl: MOCK_MONGO_URI,
    collectionName: 'sessions',
    ttl: 86400
  });
});

test('Session Store: Express app retains MemoryStore in test mode and mounts session before auth routes', () => {
  assert.equal(sessionStore, undefined, 'sessionStore export should be undefined in test mode');

  const sessionLayerIdx = findLayerIndex(app, (layer) => layer.name === 'session');
  assert.notEqual(sessionLayerIdx, -1, 'express-session middleware should be registered');

  const authPaths = ['/api/auth/me', '/login', '/auth/google', '/auth/google/callback', '/auth/logout'];
  for (const authPath of authPaths) {
    const routeIdx = findLayerIndex(app, (layer) => layer.route && layer.route.path === authPath);
    assert.notEqual(routeIdx, -1, `Route ${authPath} should be registered`);
    assert.ok(
      sessionLayerIdx < routeIdx,
      `Session middleware (index ${sessionLayerIdx}) must precede ${authPath} (index ${routeIdx})`
    );
  }

  // Invoke the mounted session middleware to inspect req.sessionStore and preserved cookie defaults
  const sessionMiddleware = app._router.stack[sessionLayerIdx].handle;
  const mockReq = {
    url: '/api/health',
    originalUrl: '/api/health',
    headers: {},
    connection: {}
  };
  const mockRes = {
    getHeader: () => undefined,
    setHeader: () => {},
    writeHead: () => {},
    end: () => {},
    on: () => {},
    once: () => {},
    emit: () => {}
  };

  let nextCalled = false;
  sessionMiddleware(mockReq, mockRes, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.ok(mockReq.sessionStore instanceof session.MemoryStore, 'Active middleware store should be MemoryStore in test mode');
  assert.equal(mockReq.session.cookie.httpOnly, true);
  assert.equal(mockReq.session.cookie.sameSite, 'lax');
  assert.equal(mockReq.session.cookie.originalMaxAge, 24 * 60 * 60 * 1000);
});

test('Session Store: server.js fails fast in production if MONGODB_URI is missing', () => {
  const result = runServerProbe(
    {
      NODE_ENV: 'production',
      SESSION_SECRET: TEST_PROD_SECRET,
      MONGODB_URI: ''
    },
    "require('./server');"
  );

  assert.notEqual(result.status, 0, 'Process must exit non-zero when MONGODB_URI is missing in production');
  assert.match(result.stderr, /FATAL: MONGODB_URI must be configured in production for MongoDB session storage\./);
});

test('Session Store: server.js uses mocked MongoStore in production and MemoryStore in development', () => {
  const prodResult = runServerProbe(
    {
      NODE_ENV: 'production',
      SESSION_SECRET: TEST_PROD_SECRET,
      MONGODB_URI: MOCK_MONGO_URI
    },
    `
      const assert = require('node:assert/strict');
      const session = require('express-session');
      const connectMongoPath = require.resolve('connect-mongo');
      let capturedOptions = null;

      class MockMongoStore extends session.Store {
        constructor(opts) {
          super();
          this.options = opts;
          this.collectionP = Promise.resolve();
        }
        static create(opts) {
          capturedOptions = opts;
          return new MockMongoStore(opts);
        }
      }

      require.cache[connectMongoPath] = {
        id: connectMongoPath,
        filename: connectMongoPath,
        loaded: true,
        exports: { MongoStore: MockMongoStore }
      };

      const app = require('./server');
      assert.deepEqual(capturedOptions, {
        mongoUrl: '${MOCK_MONGO_URI}',
        collectionName: 'sessions',
        ttl: 86400
      });
      assert.ok(app.sessionStore instanceof MockMongoStore);

      const sessionIdx = app._router.stack.findIndex((l) => l.name === 'session');
      const oauthIdx = app._router.stack.findIndex((l) => l.route && l.route.path === '/auth/google');
      assert.ok(sessionIdx !== -1 && oauthIdx !== -1 && sessionIdx < oauthIdx);

      const req = { url: '/api/health', originalUrl: '/api/health', headers: {}, connection: {} };
      const res = { getHeader: () => {}, setHeader: () => {}, writeHead: () => {}, end: () => {}, on: () => {}, once: () => {}, emit: () => {} };
      app._router.stack[sessionIdx].handle(req, res, () => {});
      assert.ok(req.sessionStore instanceof MockMongoStore);
      assert.equal(req.session.cookie.httpOnly, true);
      assert.equal(req.session.cookie.sameSite, 'lax');
      assert.equal(req.session.cookie.originalMaxAge, 24 * 60 * 60 * 1000);
    `
  );
  assert.equal(prodResult.status, 0, `Production probe failed: ${prodResult.stderr}`);

  const devResult = runServerProbe(
    {
      NODE_ENV: 'development',
      MONGODB_URI: MOCK_MONGO_URI
    },
    `
      const assert = require('node:assert/strict');
      const session = require('express-session');
      const connectMongoPath = require.resolve('connect-mongo');
      let createCalled = false;

      class MockMongoStore extends session.Store {
        static create() {
          createCalled = true;
          return new MockMongoStore();
        }
      }

      require.cache[connectMongoPath] = {
        id: connectMongoPath,
        filename: connectMongoPath,
        loaded: true,
        exports: { MongoStore: MockMongoStore }
      };

      const app = require('./server');
      assert.equal(createCalled, false);
      assert.equal(app.sessionStore, undefined);

      const sessionLayer = app._router.stack.find((l) => l.name === 'session');
      const req = { url: '/api/health', originalUrl: '/api/health', headers: {}, connection: {} };
      const res = { getHeader: () => {}, setHeader: () => {}, writeHead: () => {}, end: () => {}, on: () => {}, once: () => {}, emit: () => {} };
      sessionLayer.handle(req, res, () => {});
      assert.ok(req.sessionStore instanceof session.MemoryStore);
    `
  );
  assert.equal(devResult.status, 0, `Development probe failed: ${devResult.stderr}`);
});
