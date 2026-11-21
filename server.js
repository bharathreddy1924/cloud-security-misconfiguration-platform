require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const { scanResources } = require('./src/scanner');
const {
  User,
  isGoogleOAuthConfigured,
  generateAuthUrl,
  exchangeCodeForTokens,
  fetchGoogleUserProfile,
  persistUser,
  requireAuthApi,
  requireAuthPage
} = require('./src/auth');

const app = express();

// Body parser
app.use(express.json({ limit: '1mb' }));

// Session management
const SESSION_SECRET = process.env.SESSION_SECRET || 'cloudsec-dev-session-secret-change-in-production';
if (!process.env.SESSION_SECRET && process.env.NODE_ENV === 'production') {
  console.warn('⚠️ WARNING: SESSION_SECRET is not configured. Set SESSION_SECRET in .env for production.');
}

app.use(session({
  name: 'cloudsec.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// MongoDB Scan Schema (with optional user attribution)
const Scan = mongoose.models.Scan || mongoose.model('Scan', new mongoose.Schema({
  createdAt: { type: Date, default: Date.now },
  resourceCount: Number,
  findings: Array,
  summary: Object,
  userEmail: { type: String, default: null },
  userId: { type: String, default: null }
}, { versionKey: false }));

// ==========================================
// Public Endpoints
// ==========================================

// Health check endpoint (used by Docker and monitoring)
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    auth: {
      provider: 'google',
      configured: isGoogleOAuthConfigured()
    }
  });
});

// Current authenticated user profile
app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.user) {
    return res.json({
      authenticated: true,
      user: req.session.user
    });
  }
  return res.status(401).json({
    authenticated: false,
    error: 'Not authenticated'
  });
});

// Login page
app.get('/login', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Google OAuth 2.0 authorization trigger
app.get('/auth/google', (req, res) => {
  if (!isGoogleOAuthConfigured()) {
    return res.redirect('/login?error=unconfigured');
  }
  const authUrl = generateAuthUrl(req);
  if (!authUrl) {
    return res.redirect('/login?error=unconfigured');
  }
  res.redirect(authUrl);
});

// Google OAuth 2.0 callback handler
app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state, error: oauthError } = req.query;

    if (oauthError) {
      return res.redirect(`/login?error=${encodeURIComponent(oauthError)}`);
    }

    const expectedState = req.session && req.session.oauthState;
    if (!state || !expectedState || state !== expectedState) {
      if (req.session) delete req.session.oauthState;
      return res.status(403).send('OAuth state verification failed (CSRF protection). Please return to login and try again.');
    }

    // Invalidate state immediately upon single use
    delete req.session.oauthState;

    if (!code) {
      return res.redirect('/login?error=missing_code');
    }

    const redirectUri = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback';
    const tokens = await exchangeCodeForTokens(code, redirectUri);
    const profile = await fetchGoogleUserProfile(tokens.access_token);

    if (profile.email_verified === false || profile.email_verified === 'false') {
      return res.redirect('/login?error=unverified_email');
    }

    // Persist user in MongoDB if database is connected
    const dbUser = await persistUser(profile);

    // Establish user session
    req.session.user = {
      id: dbUser ? dbUser._id.toString() : profile.sub,
      googleId: profile.sub,
      email: profile.email,
      name: profile.name || profile.email.split('@')[0],
      picture: profile.picture || ''
    };

    req.session.save((err) => {
      if (err) {
        console.error('Session persistence failed:', err);
        return res.redirect('/login?error=session_error');
      }
      res.redirect('/');
    });
  } catch (err) {
    console.error('Google OAuth callback failed:', err.message);
    res.redirect('/login?error=auth_failed');
  }
});

// Logout handler (supports GET and POST)
function handleLogout(req, res) {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) console.error('Error destroying session:', err);
      res.clearCookie('cloudsec.sid');
      if (req.headers.accept && req.headers.accept.includes('application/json')) {
        return res.json({ success: true, message: 'Signed out successfully' });
      }
      return res.redirect('/login?status=logged_out');
    });
  } else {
    res.clearCookie('cloudsec.sid');
    res.redirect('/login?status=logged_out');
  }
}
app.get('/auth/logout', handleLogout);
app.post('/auth/logout', handleLogout);

// Test session helper (only active when running tests)
if (process.env.NODE_ENV === 'test') {
  app.post('/auth/test-session', (req, res) => {
    req.session.user = req.body && req.body.user ? req.body.user : {
      id: 'test-user-id',
      googleId: 'test-google-id-12345',
      email: 'tester@cloudsec.local',
      name: 'Security Test Auditor'
    };
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ status: 'ok', user: req.session.user });
    });
  });
}

// ==========================================
// Protected Web Dashboard & Client Assets
// ==========================================

// Root route serves the dashboard for authenticated users
app.get('/', requireAuthPage, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Redirect direct index.html access through auth check
app.get('/index.html', (_req, res) => {
  res.redirect('/');
});

// Protect client application code
app.get('/app.js', requireAuthPage, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.js'));
});

// Serve public static assets (e.g. styles.css, public icons)
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ==========================================
// Protected Scanner API Endpoints
// ==========================================

// Run security scan against provided inventory
app.post('/api/scan', requireAuthApi, async (req, res) => {
  try {
    const resources = req.body && req.body.resources;
    if (!Array.isArray(resources) || resources.length === 0) {
      return res.status(400).json({ error: 'Provide a non-empty resources array.' });
    }
    if (resources.length > 500) {
      return res.status(400).json({ error: 'A maximum of 500 resources is allowed per scan.' });
    }

    const findings = scanResources(resources);
    const summary = {
      total: findings.length,
      critical: findings.filter(x => x.severity === 'CRITICAL').length,
      high: findings.filter(x => x.severity === 'HIGH').length,
      medium: findings.filter(x => x.severity === 'MEDIUM').length,
      low: findings.filter(x => x.severity === 'LOW').length
    };

    let saved = null;
    if (mongoose.connection.readyState === 1) {
      saved = await Scan.create({
        resourceCount: resources.length,
        findings,
        summary,
        userEmail: req.session?.user?.email || null,
        userId: req.session?.user?.id || null
      });
    }

    return res.status(200).json({
      scanId: saved ? saved._id : null,
      resourceCount: resources.length,
      summary,
      findings,
      persistence: saved ? 'saved' : 'not-connected'
    });
  } catch (error) {
    return res.status(500).json({ error: 'Scan failed.', detail: error.message });
  }
});

// Retrieve recent scan history
app.get('/api/scans', requireAuthApi, async (_req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Database is not connected.' });
  }
  const scans = await Scan.find().sort({ createdAt: -1 }).limit(20).lean();
  res.json(scans);
});

// ==========================================
// Server Initialization
// ==========================================

const port = Number(process.env.PORT || 3000);

async function start() {
  const uri = process.env.MONGODB_URI;
  if (uri) {
    try {
      await mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 });
      console.log('Connected to MongoDB');
    } catch (err) {
      console.error('MongoDB connection unavailable; scan and user persistence will run in memory:', err.message);
    }
  } else {
    console.log('MONGODB_URI not set; scan API and users will run without persistence.');
  }

  app.listen(port, '0.0.0.0', () => console.log(`CloudSec platform listening on ${port}`));
}

if (require.main === module) start();

module.exports = app;
module.exports.app = app;
module.exports.Scan = Scan;
module.exports.User = User;
