require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
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

// Security hardening: Disable Express fingerprinting header
app.disable('x-powered-by');

// Body parser
app.use(express.json({ limit: '1mb' }));

// Reverse proxy trust configuration
// Only trusts reverse proxy headers if explicitly configured via TRUST_PROXY
const trustProxyEnv = process.env.TRUST_PROXY;
if (trustProxyEnv === '1' || trustProxyEnv === 'true') {
  // Trust exactly one reverse proxy hop (Nginx)
  app.set('trust proxy', 1);
} else if (trustProxyEnv && !isNaN(Number(trustProxyEnv))) {
  const hops = parseInt(trustProxyEnv, 10);
  if (hops > 0 && hops <= 5) {
    app.set('trust proxy', hops);
  }
} else if (trustProxyEnv === 'loopback' || trustProxyEnv === 'linklocal' || trustProxyEnv === 'uniquelocal') {
  app.set('trust proxy', trustProxyEnv);
}

// Session management & secret validation
const INSECURE_DEFAULT_SECRETS = [
  'cloudsec-dev-session-secret-change-in-production',
  'cloudsec-docker-session-secret-change-in-production',
  'secret',
  'keyboard cat',
  'changeme'
];

function validateSessionSecret(secret, env = process.env.NODE_ENV) {
  if (env === 'production') {
    if (!secret || typeof secret !== 'string' || INSECURE_DEFAULT_SECRETS.includes(secret.trim()) || secret.trim().length < 16) {
      throw new Error('FATAL: A secure, non-default SESSION_SECRET must be configured in production (minimum 16 characters).');
    }
  }
  return secret || 'cloudsec-dev-session-secret-change-in-production';
}

const SESSION_SECRET = validateSessionSecret(process.env.SESSION_SECRET);

// Dynamic secure cookie configuration:
// - true: always set Secure flag (requires HTTPS)
// - auto: dynamically set Secure flag if connection is HTTPS (via req.secure and trust proxy)
// - false: never set Secure flag (standard HTTP development)
let cookieSecure = false;
if (process.env.COOKIE_SECURE === 'true') {
  cookieSecure = true;
} else if (process.env.COOKIE_SECURE === 'auto') {
  cookieSecure = 'auto';
}

app.use(session({
  name: 'cloudsec.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: cookieSecure,
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
// Swagger / OpenAPI Specification
// ==========================================

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Cloud Security Misconfiguration Detection Platform API',
      version: '1.0.0',
      description: 'Defensive cloud security configuration scanner API for detecting common AWS-style misconfigurations. Includes automated rule evaluation across 8 security checks, Google OAuth 2.0 authentication, session management, and MongoDB scan history persistence.',
      contact: {
        name: 'Cloud Security Platform Team'
      }
    },
    servers: [
      {
        url: '/',
        description: 'Current environment server'
      }
    ],
    components: {
      securitySchemes: {
        CookieAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'cloudsec.sid',
          description: 'Session cookie issued upon successful Google OAuth 2.0 authentication. Sent automatically by web browsers or passed in the Cookie header.'
        }
      },
      schemas: {
        HealthResponse: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'ok' },
            database: { type: 'string', enum: ['connected', 'disconnected'], example: 'connected' },
            auth: {
              type: 'object',
              properties: {
                provider: { type: 'string', example: 'google' },
                configured: { type: 'boolean', example: true }
              }
            }
          }
        },
        UserProfile: {
          type: 'object',
          properties: {
            id: { type: 'string', example: '673dfa12b984fa001234abcd' },
            googleId: { type: 'string', example: '108234912384912834912' },
            email: { type: 'string', example: 'auditor@university.edu' },
            name: { type: 'string', example: 'Cloud Security Auditor' },
            picture: { type: 'string', example: 'https://lh3.googleusercontent.com/a/default-avatar' }
          }
        },
        AuthMeResponse: {
          type: 'object',
          properties: {
            authenticated: { type: 'boolean', example: true },
            user: { $ref: '#/components/schemas/UserProfile' }
          }
        },
        ResourceItem: {
          type: 'object',
          required: ['id', 'type'],
          properties: {
            id: { type: 'string', description: 'Unique resource identifier', example: 'bucket-customer-uploads' },
            type: {
              type: 'string',
              description: 'Resource type',
              enum: ['s3', 'security-group', 'iam-policy', 'database', 'cloudtrail', 'ebs'],
              example: 's3'
            },
            publicAccess: { type: 'boolean', description: 'Whether S3 bucket allows public access' },
            blockPublicAccess: { type: 'boolean', description: 'S3 Block Public Access setting' },
            encryptionEnabled: { type: 'boolean', description: 'Whether S3 default encryption is enabled' },
            ingress: {
              type: 'array',
              description: 'Security group inbound rules',
              items: {
                type: 'object',
                properties: {
                  port: { type: 'integer', example: 22 },
                  cidr: { type: 'string', example: '0.0.0.0/0' }
                }
              }
            },
            action: { type: 'string', description: 'IAM action statement', example: '*' },
            resource: { type: 'string', description: 'IAM resource ARN or wildcard', example: '*' },
            publiclyAccessible: { type: 'boolean', description: 'Whether RDS/database is publicly accessible' },
            enabled: { type: 'boolean', description: 'Whether CloudTrail logging is enabled' },
            encrypted: { type: 'boolean', description: 'Whether EBS volume is encrypted' }
          }
        },
        ScanRequest: {
          type: 'object',
          required: ['resources'],
          properties: {
            resources: {
              type: 'array',
              description: 'Array of cloud infrastructure resources to inspect (1 to 500 items).',
              items: { $ref: '#/components/schemas/ResourceItem' },
              minItems: 1,
              maxItems: 500
            }
          }
        },
        ScanFinding: {
          type: 'object',
          properties: {
            ruleId: {
              type: 'string',
              description: 'Identifies which of the 8 misconfiguration rules triggered',
              enum: [
                'S3_PUBLIC_ACCESS',
                'S3_ENCRYPTION_DISABLED',
                'OPEN_SSH',
                'OPEN_RDP',
                'IAM_WILDCARD_POLICY',
                'DATABASE_PUBLIC',
                'CLOUDTRAIL_DISABLED',
                'EBS_ENCRYPTION_DISABLED'
              ],
              example: 'S3_PUBLIC_ACCESS'
            },
            resourceId: { type: 'string', example: 'bucket-customer-uploads' },
            resourceType: { type: 'string', example: 's3' },
            title: { type: 'string', example: 'S3 bucket allows public access' },
            severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], example: 'CRITICAL' },
            description: { type: 'string', example: 'Public bucket access can expose stored data to unauthorised users.' },
            remediation: { type: 'string', example: 'Enable all S3 Block Public Access settings and review bucket policies and ACLs.' }
          }
        },
        ScanSummary: {
          type: 'object',
          properties: {
            total: { type: 'integer', example: 6 },
            critical: { type: 'integer', example: 3 },
            high: { type: 'integer', example: 2 },
            medium: { type: 'integer', example: 1 },
            low: { type: 'integer', example: 0 }
          }
        },
        ScanResponse: {
          type: 'object',
          properties: {
            scanId: { type: 'string', nullable: true, example: '673dfa12b984fa001234abcd' },
            resourceCount: { type: 'integer', example: 6 },
            summary: { $ref: '#/components/schemas/ScanSummary' },
            findings: {
              type: 'array',
              items: { $ref: '#/components/schemas/ScanFinding' }
            },
            persistence: { type: 'string', enum: ['saved', 'not-connected'], example: 'saved' }
          }
        },
        ScanRecord: {
          type: 'object',
          properties: {
            _id: { type: 'string', example: '673dfa12b984fa001234abcd' },
            createdAt: { type: 'string', format: 'date-time', example: '2026-11-21T10:00:00.000Z' },
            resourceCount: { type: 'integer', example: 6 },
            findings: {
              type: 'array',
              items: { $ref: '#/components/schemas/ScanFinding' }
            },
            summary: { $ref: '#/components/schemas/ScanSummary' },
            userEmail: { type: 'string', nullable: true, example: 'auditor@university.edu' },
            userId: { type: 'string', nullable: true, example: '673dfa12b984fa001234abcd' }
          }
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            error: { type: 'string', example: 'Unauthorized' },
            message: { type: 'string', example: 'Authentication required. Please sign in with Google to access this resource.' }
          }
        }
      }
    }
  },
  apis: [path.join(__dirname, 'server.js').replace(/\\/g, '/')]
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// OpenAPI Specification JSON endpoint (public)
app.get('/api-docs.json', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(swaggerSpec);
});

// Swagger UI mount (public, accessible without login)
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customSiteTitle: 'CloudSec API Documentation',
  swaggerOptions: {
    persistAuthorization: true
  }
}));

// ==========================================
// Public Endpoints
// ==========================================

/**
 * @openapi
 * /api/health:
 *   get:
 *     summary: System health and dependency status
 *     description: Returns operational health status of the application, MongoDB database connection state, and Google OAuth configuration status. Accessible publicly without authentication.
 *     tags:
 *       - System
 *     responses:
 *       200:
 *         description: System status report
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthResponse'
 *             example:
 *               status: ok
 *               database: connected
 *               auth:
 *                 provider: google
 *                 configured: true
 */
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

/**
 * @openapi
 * /api/auth/me:
 *   get:
 *     summary: Get current authenticated user profile
 *     description: Returns user identity details (ID, Google ID, email, name, avatar) for the active session. If no valid session exists, returns 401 Unauthorized.
 *     tags:
 *       - Authentication
 *     security:
 *       - CookieAuth: []
 *     responses:
 *       200:
 *         description: Authenticated user profile
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthMeResponse'
 *             example:
 *               authenticated: true
 *               user:
 *                 id: "673dfa12b984fa001234abcd"
 *                 googleId: "108234912384912834912"
 *                 email: "auditor@university.edu"
 *                 name: "Cloud Security Auditor"
 *                 picture: "https://lh3.googleusercontent.com/a/default-avatar"
 *       401:
 *         description: Not authenticated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 authenticated:
 *                   type: boolean
 *                   example: false
 *                 error:
 *                   type: string
 *                   example: Not authenticated
 */
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

/**
 * @openapi
 * /auth/google:
 *   get:
 *     summary: Initiate Google OAuth 2.0 authorization
 *     description: Generates a cryptographically secure random state parameter for CSRF mitigation, stores it in the user session, and redirects the client browser to Google's OAuth 2.0 authorization endpoint (`https://accounts.google.com/o/oauth2/v2/auth`).
 *     tags:
 *       - Authentication
 *     responses:
 *       302:
 *         description: Redirect to Google OAuth consent screen, or login page if OAuth is unconfigured.
 *         headers:
 *           Location:
 *             description: Target Google OAuth authorization URL or error redirect
 *             schema:
 *               type: string
 */
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

/**
 * @openapi
 * /auth/google/callback:
 *   get:
 *     summary: Google OAuth 2.0 callback handler
 *     description: Handles redirect from Google OAuth consent. Validates CSRF state parameter against the session, exchanges authorization code for Google access tokens, retrieves user profile, creates/updates user in MongoDB, and establishes an authenticated session.
 *     tags:
 *       - Authentication
 *     parameters:
 *       - in: query
 *         name: code
 *         schema:
 *           type: string
 *         required: false
 *         description: Authorization code returned by Google OAuth.
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *         required: false
 *         description: CSRF mitigation state parameter generated during initiation.
 *       - in: query
 *         name: error
 *         schema:
 *           type: string
 *         required: false
 *         description: OAuth error code if user cancelled or Google rejected authentication.
 *     responses:
 *       302:
 *         description: Redirect to dashboard (`/`) upon successful login, or `/login?error=...` on failure.
 *         headers:
 *           Location:
 *             schema:
 *               type: string
 *       403:
 *         description: OAuth state verification failed (CSRF protection).
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: OAuth state verification failed (CSRF protection). Please return to login and try again.
 */
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

    // Prepare authenticated user payload
    const authenticatedUser = {
      id: dbUser ? dbUser._id.toString() : profile.sub,
      googleId: profile.sub,
      email: profile.email,
      name: profile.name || profile.email.split('@')[0],
      picture: profile.picture || ''
    };

    // Prevent session fixation by regenerating session identifier upon authentication
    if (req.session && typeof req.session.regenerate === 'function') {
      req.session.regenerate((regenErr) => {
        if (regenErr) {
          console.error('Session regeneration failed:', regenErr);
          return res.redirect('/login?error=session_error');
        }
        req.session.user = authenticatedUser;
        req.session.save((saveErr) => {
          if (saveErr) {
            console.error('Session persistence failed:', saveErr);
            return res.redirect('/login?error=session_error');
          }
          res.redirect('/');
        });
      });
    } else {
      if (req.session) {
        req.session.user = authenticatedUser;
      }
      res.redirect('/');
    }
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

/**
 * @openapi
 * /auth/logout:
 *   get:
 *     summary: Sign out current user (GET)
 *     description: Terminates the server-side session, clears the session cookie, and redirects to /login?status=logged_out (or returns JSON if Accept header includes application/json).
 *     tags:
 *       - Authentication
 *     responses:
 *       200:
 *         description: JSON confirmation of logout (when requested via Accept application/json)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Signed out successfully
 *       302:
 *         description: Redirect to login page
 *         headers:
 *           Location:
 *             schema:
 *               type: string
 *               example: /login?status=logged_out
 *   post:
 *     summary: Sign out current user (POST)
 *     description: Terminates the server-side session, clears the session cookie, and returns JSON or redirects to /login?status=logged_out.
 *     tags:
 *       - Authentication
 *     responses:
 *       200:
 *         description: JSON confirmation of logout
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Signed out successfully
 *       302:
 *         description: Redirect to login page
 *         headers:
 *           Location:
 *             schema:
 *               type: string
 *               example: /login?status=logged_out
 */
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

/**
 * @openapi
 * /api/scan:
 *   post:
 *     summary: Scan cloud resources for security misconfigurations
 *     description: |
 *       Scans an array of cloud infrastructure resource definitions (1 to 500 items) against 8 defensive security rules:
 *       1. **S3_PUBLIC_ACCESS** (CRITICAL): Detects S3 buckets with public access enabled.
 *       2. **S3_ENCRYPTION_DISABLED** (HIGH): Detects unencrypted S3 buckets.
 *       3. **OPEN_SSH** (CRITICAL): Detects Security Groups with port 22 open to `0.0.0.0/0` or `::/0`.
 *       4. **OPEN_RDP** (CRITICAL): Detects Security Groups with port 3389 open to `0.0.0.0/0` or `::/0`.
 *       5. **IAM_WILDCARD_POLICY** (HIGH): Detects IAM policies granting `*` on Action or Resource.
 *       6. **DATABASE_PUBLIC** (CRITICAL): Detects database instances with public internet accessibility.
 *       7. **CLOUDTRAIL_DISABLED** (MEDIUM): Detects disabled CloudTrail audit logging.
 *       8. **EBS_ENCRYPTION_DISABLED** (MEDIUM): Detects unencrypted EBS block storage volumes.
 *       
 *       Automatically saves results and severity breakdown to MongoDB when connected, attributed to the authenticated user.
 *       Requires an active authenticated session (`cloudsec.sid`).
 *     tags:
 *       - Scanner
 *     security:
 *       - CookieAuth: []
 *     requestBody:
 *       required: true
 *       description: Inventory containing list of cloud resources to scan (1 to 500 items).
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ScanRequest'
 *           example:
 *             resources:
 *               - id: "bucket-customer-uploads"
 *                 type: "s3"
 *                 publicAccess: true
 *                 encryptionEnabled: false
 *               - id: "sg-admin-access"
 *                 type: "security-group"
 *                 ingress:
 *                   - port: 22
 *                     cidr: "0.0.0.0/0"
 *               - id: "iam-developer-policy"
 *                 type: "iam-policy"
 *                 action: "*"
 *                 resource: "*"
 *               - id: "prod-reporting-db"
 *                 type: "database"
 *                 publiclyAccessible: true
 *               - id: "audit-trail-main"
 *                 type: "cloudtrail"
 *                 enabled: false
 *               - id: "encrypted-volume-01"
 *                 type: "ebs"
 *                 encrypted: true
 *     responses:
 *       200:
 *         description: Scan completed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ScanResponse'
 *             example:
 *               scanId: "673dfa12b984fa001234abcd"
 *               resourceCount: 6
 *               summary:
 *                 total: 6
 *                 critical: 3
 *                 high: 2
 *                 medium: 1
 *                 low: 0
 *               findings:
 *                 - ruleId: "S3_PUBLIC_ACCESS"
 *                   resourceId: "bucket-customer-uploads"
 *                   resourceType: "s3"
 *                   title: "S3 bucket allows public access"
 *                   severity: "CRITICAL"
 *                   description: "Public bucket access can expose stored data to unauthorised users."
 *                   remediation: "Enable all S3 Block Public Access settings and review bucket policies and ACLs."
 *                 - ruleId: "S3_ENCRYPTION_DISABLED"
 *                   resourceId: "bucket-customer-uploads"
 *                   resourceType: "s3"
 *                   title: "S3 default encryption is disabled"
 *                   severity: "HIGH"
 *                   description: "Objects may be stored without server-side encryption at rest."
 *                   remediation: "Enable default server-side encryption using SSE-S3 or an approved KMS key."
 *               persistence: "saved"
 *       400:
 *         description: Invalid scan request payload
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Provide a non-empty resources array."
 *       401:
 *         description: Unauthorized - Active session cookie required
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               error: "Unauthorized"
 *               message: "Authentication required. Please sign in with Google to access this resource."
 *       500:
 *         description: Internal scan execution failure
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Scan failed."
 *                 detail:
 *                   type: string
 */
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
    console.error('Scan execution error:', error.message);
    const detail = process.env.NODE_ENV === 'production'
      ? 'An error occurred during resource scan processing.'
      : error.message;
    return res.status(500).json({ error: 'Scan failed.', detail });
  }
});

/**
 * @openapi
 * /api/scans:
 *   get:
 *     summary: Retrieve recent scan history
 *     description: Fetches up to 20 most recent cloud security misconfiguration scans stored in MongoDB, ordered newest first. Requires active authenticated session.
 *     tags:
 *       - Scanner
 *     security:
 *       - CookieAuth: []
 *     responses:
 *       200:
 *         description: List of historical scan records
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/ScanRecord'
 *       401:
 *         description: Unauthorized - Session cookie missing or invalid
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       503:
 *         description: Database not connected
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Database is not connected."
 */
app.get('/api/scans', requireAuthApi, async (req, res) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'Database is not connected.' });
  }
  const user = req.session && req.session.user;
  const filter = {};
  if (user) {
    if (user.email && user.id) {
      filter.$or = [{ userEmail: user.email }, { userId: user.id }];
    } else if (user.email) {
      filter.userEmail = user.email;
    } else if (user.id) {
      filter.userId = user.id;
    }
  }
  const scans = await Scan.find(filter).sort({ createdAt: -1 }).limit(20).lean();
  res.json(scans);
});

// Structured JSON 404 handler for unknown API routes
app.all('/api/*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `API endpoint ${req.method} ${req.path} does not exist.`
  });
});

// Centralized error handling middleware
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }
  console.error('Unhandled application error:', err);
  const isProd = process.env.NODE_ENV === 'production';
  if (req.path && req.path.startsWith('/api/')) {
    return res.status(err.status || err.statusCode || 500).json({
      error: err.name || 'Internal Server Error',
      message: isProd ? 'An unexpected error occurred while processing the request.' : (err.message || 'Unknown error')
    });
  }
  res.status(err.status || err.statusCode || 500).send('Internal Server Error');
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
module.exports.swaggerSpec = swaggerSpec;
module.exports.validateSessionSecret = validateSessionSecret;
