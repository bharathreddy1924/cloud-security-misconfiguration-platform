# Cloud Security Misconfiguration Detection Platform

**Capstone team shown in the supplied roster**
- Gangana Bharath Simha Reddy — BT23GCS494
- Garre Lakhmi Narayana — BT23GCS253
- Charugundla Hemendra Venkata Lalith — BT23GCS254

## 1. Project overview

A defensive, rule-based cloud security platform that assesses cloud resource configuration inventory and reports security misconfigurations with severity levels, contextual descriptions, and actionable remediation guidance.

The platform includes **Google OAuth 2.0 authentication**, server-side session management, route protection, and MongoDB persistence. Unauthenticated users are directed to a professional sign-in portal, while authenticated auditors gain access to the posture assessment dashboard and scan history.

The detection engine implements eight transparent security rules:
- **S3_PUBLIC_ACCESS (CRITICAL):** Unrestricted public bucket access.
- **S3_ENCRYPTION_DISABLED (HIGH):** Missing default server-side encryption at rest.
- **OPEN_SSH (CRITICAL):** Security group port 22 open to the public internet (`0.0.0.0/0` or `::/0`).
- **OPEN_RDP (CRITICAL):** Security group port 3389 open to the public internet.
- **IAM_WILDCARD_POLICY (HIGH):** Over-privileged wildcard policies (`*` in Action or Resource).
- **DATABASE_PUBLIC (CRITICAL):** Publicly accessible relational or document database instances.
- **CLOUDTRAIL_DISABLED (MEDIUM):** Inactive management and audit event logging.
- **EBS_ENCRYPTION_DISABLED (MEDIUM):** Unencrypted elastic block storage volumes.

**Scope note:** this capstone build scans a supplied JSON inventory. It does not connect to an AWS account, fetch live cloud resources, or automatically change cloud settings. This keeps the demonstration safe and avoids requiring cloud credentials.

---

## 2. Architecture & Authentication Flow

```text
Browser User / Auditor
      │
      ├─► [GET /] (Unauthenticated) ──► 302 Redirect to /login
      │
      ├─► [GET /login] ──► Professional Sign-In Page ("Continue with Google")
      │
      ├─► [GET /auth/google] ──► Generates 32-byte CSRF State ──► Redirect to Google OAuth 2.0
      │                                                                   │
      │◄──────────────── Consent Screen / Account Selection ──────────────┘
      │
      ├─► [GET /auth/google/callback?code=...&state=...]
      │        │
      │        ├─► 1. Verify CSRF state against session (timing-safe)
      │        ├─► 2. Invalidate state token (single-use defense)
      │        ├─► 3. POST authorization code to https://oauth2.googleapis.com/token
      │        ├─► 4. Fetch verified identity from https://www.googleapis.com/oauth2/v3/userinfo
      │        ├─► 5. Persist/update user profile in MongoDB (User collection)
      │        ├─► 6. Issue secure httpOnly session cookie (cloudsec.sid)
      │        └─► 7. Redirect to / (Dashboard)
      │
      ├─► [GET /] (Authenticated) ──► Serve Dashboard with User Profile & Avatar
      │
      ├─► [POST /api/scan] ──► Validates Session Cookie ──► Rule Engine (src/scanner.js)
      │                                                           │
      │                                                           ▼
      │                                                Findings + Severity Summary
      │                                                           │
      ├─► MongoDB (Scan History attributed to authenticated user) ◄┘
      │
      └─► [GET /auth/logout] ──► Destroy Session + Clear Cookie ──► Redirect to /login
```

---

## 3. Google Cloud Console Setup Guide

To enable live Google Sign-In with real Google accounts, configure an OAuth 2.0 Client ID in the Google Cloud Console:

### Step 1: Access Google Cloud Console
1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Select an existing project or create a new project named **CloudSec-Platform**.

### Step 2: Configure the OAuth Consent Screen
1. In the left navigation, go to **APIs & Services &rarr; OAuth consent screen**.
2. Select **External** (or **Internal** if using a Google Workspace organization) and click **Create**.
3. Fill in the required application details:
   - **App name:** `CloudSec Platform`
   - **User support email:** Select your Google account email.
   - **Developer contact information:** Enter your email address.
4. Click **Save and Continue**.
5. On the **Scopes** page, click **Add or Remove Scopes** and select:
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`
   - `openid`
6. Click **Save and Continue**.
7. Under **Test users**, add your Google email address so your account can sign in while the app is in testing mode.
8. Click **Save and Continue** to finish.

### Step 3: Create OAuth 2.0 Credentials
1. In the left navigation, click **Credentials**.
2. Click **+ CREATE CREDENTIALS &rarr; OAuth client ID**.
3. Set **Application type** to **Web application**.
4. Set **Name** to `CloudSec Web Client`.
5. Under **Authorized JavaScript origins**, click **+ ADD URI** and add:
   - `http://localhost:3001` (primary: Docker Compose application port)
   - `http://localhost:3000` (for standalone local `npm start` without Docker)
6. Under **Authorized redirect URIs**, click **+ ADD URI** and add:
   - `http://localhost:3001/auth/google/callback` (primary: Docker Compose callback URL)
   - `http://localhost:3000/auth/google/callback` (for standalone local `npm start` without Docker)
7. Click **CREATE**.

### Step 4: Configure Local `.env`
Copy `.env.example` to `.env` (or update `.env`) with your generated credentials:

```bash
cp .env.example .env
```

Edit `.env`:
```env
GOOGLE_CLIENT_ID=your-actual-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-actual-client-secret
SESSION_SECRET=a-secure-random-string-at-least-32-characters-long
```

> **Security Note:** Never commit `.env` or credentials to version control. The repository `.gitignore` automatically excludes `.env`.

---

## 4. Environment Variables Reference

| Variable | Description | Default / Example |
|---|---|---|
| `PORT` | HTTP port the Express server listens on (container port: 3000; host port in Docker Compose: 3001) | `3000` |
| `NODE_ENV` | Application environment (`development`, `production`, `test`) | `development` |
| `MONGODB_URI` | MongoDB connection URI for persistent scan history and user profiles | `mongodb://localhost:27017/cloudsec` |
| `SESSION_SECRET` | Secret key used to sign the session ID cookie | 32+ character random string |
| `COOKIE_SECURE` | Enforces `Secure` attribute on cookies (set `true` in HTTPS production) | `false` |
| `GOOGLE_CLIENT_ID` | OAuth 2.0 Client ID obtained from Google Cloud Console | `xxxx.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET`| OAuth 2.0 Client Secret obtained from Google Cloud Console | `GOCSPX-xxxx` |
| `GOOGLE_CALLBACK_URL` | OAuth redirect URI (must match Google Console setting: port 3001 for Docker, 3000 for local node) | `http://localhost:3001/auth/google/callback` |

---

## 5. Run Locally (without Docker)

### Prerequisites
- Node.js 20+ and npm
- MongoDB (optional, scan engine and sessions run gracefully in-memory without persistent history if offline)

### Commands
```bash
# 1. Install dependencies
npm install

# 2. Run all automated unit and integration tests
npm test

# 3. Start the application
npm start
```

Open `http://localhost:3000` in your browser.
1. The application detects you are unauthenticated and redirects to `/login`.
2. Click **Continue with Google** to authenticate with your Google account.
3. Upon approval, Google redirects back to `/auth/google/callback`, validates the state token, establishes your server-side session, and loads the posture dashboard.
4. Your Google profile name, email, and avatar are displayed in the top bar.
5. Click **Run sample scan** to evaluate the configuration inventory.
6. Click **Sign out** at any time to destroy the session and return to the login screen.

---

## 6. Run with Docker Compose

Docker Compose runs both the CloudSec platform and MongoDB:

```bash
# Start containers in background with build
docker-compose up --build -d

# Verify container status and healthchecks
docker-compose ps

# View application logs
docker-compose logs -f app

# Stop containers
docker-compose down

# Stop containers and remove persisted MongoDB volume
docker-compose down -v
```

> **Port Mapping Note:** Docker Compose publishes the application to host port **3001** (mapped to container port 3000). Access the Dockerized application at:
> **http://localhost:3001**
> (Ensure `GOOGLE_CALLBACK_URL=http://localhost:3001/auth/google/callback` when using Docker).

---

## 7. API Reference

### Public Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | Service health status, database state, and OAuth configuration flag. |
| `/login` | `GET` | Serves the professional sign-in page with Continue with Google. |
| `/auth/google` | `GET` | Generates CSRF state and redirects user to Google OAuth consent page. |
| `/auth/google/callback` | `GET` | Receives authorization code, validates state token, exchanges code for tokens, verifies profile, and creates session. |
| `/auth/logout` | `GET`, `POST` | Destroys server-side session, clears session cookie, and redirects to `/login?status=logged_out`. |

### Protected Endpoints (Session Required)

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Serves the security posture dashboard (redirects to `/login` if unauthenticated). |
| `/api/auth/me` | `GET` | Returns authenticated user identity (`id`, `googleId`, `email`, `name`, `picture`). Returns `401 Unauthorized` if not logged in. |
| `/api/scan` | `POST` | Audits a cloud resource inventory against all 8 security rules. Links scan record to user if MongoDB is active. |
| `/api/scans` | `GET` | Returns the latest 20 stored scan results from MongoDB. |

#### Sample Scan Request
`POST /api/scan`
`Content-Type: application/json`
`Cookie: cloudsec.sid=...`

```json
{
  "resources": [
    { "id": "bucket-customer-uploads", "type": "s3", "publicAccess": true, "encryptionEnabled": false },
    { "id": "sg-admin-access", "type": "security-group", "ingress": [{ "port": 22, "cidr": "0.0.0.0/0" }] },
    { "id": "iam-developer-policy", "type": "iam-policy", "action": "*", "resource": "*" },
    { "id": "prod-reporting-db", "type": "database", "publiclyAccessible": true },
    { "id": "audit-trail-main", "type": "cloudtrail", "enabled": false },
    { "id": "encrypted-volume-01", "type": "ebs", "encrypted": true }
  ]
}
```

---

## 8. Security Rules

| Rule ID | Severity | Detection Logic | Recommended Remediation |
|---|---|---|---|
| `S3_PUBLIC_ACCESS` | CRITICAL | `publicAccess === true` or `blockPublicAccess === false` | Enable all S3 Block Public Access settings and review bucket policies and ACLs. |
| `S3_ENCRYPTION_DISABLED` | HIGH | `encryptionEnabled === false` | Enable default server-side encryption using SSE-S3 or an approved KMS key. |
| `OPEN_SSH` | CRITICAL | Ingress port 22 open to `0.0.0.0/0` or `::/0` | Restrict SSH to a trusted VPN, bastion host, or approved source CIDR. |
| `OPEN_RDP` | CRITICAL | Ingress port 3389 open to `0.0.0.0/0` or `::/0` | Restrict RDP to a trusted VPN or approved source CIDR. |
| `IAM_WILDCARD_POLICY` | HIGH | `action === '*'` or `resource === '*'` | Apply least privilege: specify only required actions and resource ARNs. |
| `DATABASE_PUBLIC` | CRITICAL | `publiclyAccessible === true` | Disable public accessibility and place the database in private subnets. |
| `CLOUDTRAIL_DISABLED` | MEDIUM | `enabled === false` | Enable CloudTrail in all required regions and protect log integrity. |
| `EBS_ENCRYPTION_DISABLED` | MEDIUM | `encrypted === false` | Enable encryption by default and encrypt existing volumes during migration. |

---

## 9. Automated Testing

The test suite uses the Node.js built-in test runner (`node --test`) and includes 28 automated tests across 4 test suites:

```bash
npm test
```

### Test Coverage Breakdown
- **Scanner Rules (`test/scanner.test.js`):**
  - Public S3 bucket and disabled encryption detection.
  - Internet-exposed SSH and RDP detection.
  - Wildcard IAM policies and publicly accessible databases detection.
  - Zero false positives on compliant cloud resources.
  - Graceful handling of malformed inventory entries without crashing.
- **Authentication Units (`test/auth-unit.test.js`):**
  - Environment variable validation for Google OAuth credentials.
  - Cryptographic CSRF state generation and URL parameter construction.
  - Token exchange payload formatting.
  - UserInfo retrieval with Bearer authorization header.
  - API authentication middleware (`requireAuthApi`) behavior.
  - Page redirection middleware (`requireAuthPage`) behavior.
- **End-to-End Auth & API Protection (`test/auth.test.js`):**
  - Public accessibility of health check and login page.
  - Dashboard redirection for unauthenticated visitors.
  - Rejection of unauthenticated scan and scan-history API requests (401 Unauthorized).
  - CSRF state mismatch rejection on OAuth callback (403 Forbidden).
  - Google error response handling.
  - End-to-end OAuth flow with mock token exchange and user profile creation.
  - Authenticated session verification via `/api/auth/me`.
  - Authenticated scan execution and finding verification.
  - Sample inventory assessment producing exactly 6 findings for an authenticated Google user.
  - Scan history API authentication guard and database status handling.
  - Session destruction and cookie clearance upon logout.
- **MongoDB History & Persistence Integration (`test/mongodb-history.test.js`):**
  - Verified User model upsert upon Google sign-in.
  - Verified persistence of scan assessments to the MongoDB `scans` collection.
  - Verified scan history query via `GET /api/scans` for authenticated Google users.
  - Verified user attribution (`userEmail` and `userId`) recorded on persisted scan documents.

---

## 10. Jenkins CI Pipeline

1. Ensure the Jenkins agent has Git, Node.js 20+, and Docker CLI/daemon access.
2. Push this project to GitHub.
3. In Jenkins, create **New Item &rarr; Pipeline**.
4. Under Pipeline, select **Pipeline script from SCM**, choose **Git**, enter repository URL, and set Script Path to `Jenkinsfile`.
5. Run **Build Now** and verify all stages pass:
   - `Checkout`
   - `Install Dependencies`
   - `Unit Tests` (runs `npm test` verifying all 28 tests)
   - `Build Docker Image`

---

## 11. Capstone Demonstration Sequence

1. **GitHub Evidence:** Show repository files (`server.js`, `src/auth.js`, `src/scanner.js`, `test/`, `Dockerfile`, `docker-compose.yml`, `Jenkinsfile`).
2. **Automated Testing:** Run `npm test` to demonstrate all 28 tests passing.
3. **Application Launch:** Run `docker-compose up --build -d` (or `npm start`).
4. **Access Control Demo:** Navigate to `http://localhost:3001` (or `3000` for standalone local node). Demonstrate automatic redirect to `/login`.
5. **Sign-In Interface:** Present the professional dark-themed login interface with the official "Continue with Google" action.
6. **OAuth Authentication:** Complete Google Sign-In. Show redirection to the dashboard and the user's name, email, and Google avatar rendered in the top bar.
7. **Security Scan Execution:** Click **Run sample scan** to audit the 6 cloud resources and review the 6 detected findings across Critical, High, and Medium severities.
8. **Audit Trail:** Show MongoDB scan history persistence linked to the authenticated user.
9. **Sign Out:** Click **Sign out** to destroy the session and demonstrate that protected routes immediately block access until re-authentication.
10. **CI Pipeline:** Present the successful Jenkins pipeline execution.
