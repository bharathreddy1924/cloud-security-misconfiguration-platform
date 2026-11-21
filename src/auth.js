const crypto = require('crypto');
const mongoose = require('mongoose');

// MongoDB User Schema for persisting Google authenticated users
const userSchema = new mongoose.Schema({
  googleId: { type: String, required: true, unique: true, index: true },
  email: { type: String, required: true, lowercase: true, trim: true },
  name: { type: String, trim: true },
  picture: { type: String, default: '' },
  lastLogin: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const User = mongoose.models.User || mongoose.model('User', userSchema);

/**
 * Checks whether Google OAuth 2.0 credentials have been configured in environment variables.
 */
function isGoogleOAuthConfigured() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return false;
  if (clientId.includes('your-google-client-id') || clientSecret.includes('your-google-client-secret')) {
    return false;
  }
  return clientId.trim().length > 0 && clientSecret.trim().length > 0;
}

/**
 * Generates the Google OAuth 2.0 authorization URL with CSRF state protection.
 */
function generateAuthUrl(req) {
  if (!isGoogleOAuthConfigured()) {
    return null;
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback';

  // Generate cryptographically secure random state parameter for CSRF mitigation
  const state = crypto.randomBytes(32).toString('hex');
  if (req.session) {
    req.session.oauthState = state;
  }

  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('access_type', 'online');
  authUrl.searchParams.set('prompt', 'select_account');

  return authUrl.toString();
}

/**
 * Exchanges authorization code with Google OAuth token endpoint.
 */
async function exchangeCodeForTokens(code, redirectUri, fetchFn = globalThis.fetch) {
  const params = new URLSearchParams({
    code,
    client_id: process.env.GOOGLE_CLIENT_ID || '',
    client_secret: process.env.GOOGLE_CLIENT_SECRET || '',
    redirect_uri: redirectUri,
    grant_type: 'authorization_code'
  });

  const response = await fetchFn('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Google token exchange failed (HTTP ${response.status}): ${errorBody}`);
  }

  const tokenData = await response.json();
  if (!tokenData.access_token) {
    throw new Error('Google token response did not contain an access_token.');
  }

  return tokenData;
}

/**
 * Retrieves verified Google user profile using the access token.
 */
async function fetchGoogleUserProfile(accessToken, fetchFn = globalThis.fetch) {
  const response = await fetchFn('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to retrieve Google userinfo (HTTP ${response.status}): ${errorBody}`);
  }

  const profile = await response.json();
  if (!profile.sub || !profile.email) {
    throw new Error('Google user profile is missing required sub or email fields.');
  }

  return profile;
}

/**
 * Persists or updates the authenticated user in MongoDB if the database connection is active.
 */
async function persistUser(profile) {
  if (mongoose.connection.readyState === 1) {
    try {
      const user = await User.findOneAndUpdate(
        { googleId: profile.sub },
        {
          $set: {
            email: profile.email,
            name: profile.name || profile.email.split('@')[0],
            picture: profile.picture || '',
            lastLogin: new Date()
          },
          $setOnInsert: {
            createdAt: new Date()
          }
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
      return user;
    } catch (err) {
      console.error('MongoDB user persistence error:', err.message);
      return null;
    }
  }
  return null;
}

/**
 * Middleware: Require active session for API endpoints.
 * Returns 401 JSON response for unauthenticated calls.
 */
function requireAuthApi(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({
    error: 'Unauthorized',
    message: 'Authentication required. Please sign in with Google to access this resource.'
  });
}

/**
 * Middleware: Require active session for HTML pages.
 * Redirects unauthenticated browser requests to /login.
 */
function requireAuthPage(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.redirect('/login');
}

module.exports = {
  User,
  isGoogleOAuthConfigured,
  generateAuthUrl,
  exchangeCodeForTokens,
  fetchGoogleUserProfile,
  persistUser,
  requireAuthApi,
  requireAuthPage
};
