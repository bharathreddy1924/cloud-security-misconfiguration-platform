# Cloud Security Misconfiguration Detection Platform — Postman API Guide

This guide documents the API collection for demonstrating and evaluating the **Cloud Security Misconfiguration Detection Platform**. It explains how to import, configure, authenticate, and execute automated tests across all platform endpoints.

---

## 1. Architecture & Port Mapping

The platform runs as a multi-tier architecture consisting of:
- **Nginx Reverse Proxy**: Entry point for external traffic with TLS termination and security headers.
  - **HTTP Entrypoint**: `http://localhost:3001` (recommended default in Postman)
  - **HTTPS Entrypoint**: `https://localhost:3443` (TLS self-signed dev certificate)
- **Node.js Express Application**: Core API and scanner engine running on internal container port `3000`.
- **MongoDB Database**: Persistent storage for scan history, severity analytics, and user attribution.

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `baseUrl` | `http://localhost:3001` | External application URL routed through the Nginx reverse proxy. For direct local standalone execution without Docker, set to `http://localhost:3000`. |
| `sessionCookie` | `(empty by default)` | Optional environment variable for storing the `cloudsec.sid` cookie value if manual header injection is preferred over Postman's native Cookie Jar. |
| `activeUserId` | `(auto-populated)` | Populated automatically by the test script of `GET /api/auth/me`. |
| `lastScanId` | `(auto-populated)` | Populated automatically by the test script of `POST /api/scan`. |

---

## 2. API Endpoints Overview

The collection contains **13 structured requests** organized into 3 logical folders matching the platform's backend implementation:

```
Cloud Security Misconfiguration Detection Platform/
├── 1. System/
│   └── System Health Status (GET /api/health)
├── 2. Authentication/
│   ├── Get Current User Profile - Authenticated (GET /api/auth/me)
│   ├── Get Current User Profile - Unauthenticated (GET /api/auth/me)
│   ├── Initiate Google OAuth 2.0 (GET /auth/google)
│   ├── OAuth Callback - CSRF State Protection Check (GET /auth/google/callback)
│   ├── Sign Out Current User - GET (GET /auth/logout)
│   └── Sign Out Current User - POST (POST /auth/logout)
└── 3. Scanner/
    ├── Scan Cloud Infrastructure - 8 Misconfiguration Rules (POST /api/scan)
    ├── Scan Cloud Infrastructure - Compliant Resources (POST /api/scan)
    ├── Scan Cloud Infrastructure - Unauthenticated (POST /api/scan)
    ├── Scan Cloud Infrastructure - Empty Array Validation (POST /api/scan)
    ├── Retrieve Recent Scan History - Authenticated (GET /api/scans)
    └── Retrieve Recent Scan History - Unauthenticated (GET /api/scans)
```

### Endpoint Summary Matrix

| Category | Method | Endpoint | Auth Required | Description | Expected HTTP Codes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **System** | `GET` | `/api/health` | No | System health, MongoDB status, and OAuth configuration. | `200 OK` |
| **Authentication** | `GET` | `/api/auth/me` | Yes (`cloudsec.sid`) | Returns current authenticated user profile (`id`, `email`, `name`). | `200 OK`, `401 Unauthorized` |
| **Authentication** | `GET` | `/auth/google` | No | Generates CSRF state and redirects to Google OAuth consent screen. | `302 Found` |
| **Authentication** | `GET` | `/auth/google/callback` | No (OAuth flow) | Exchanges Google code for tokens; validates CSRF state. | `302 Found`, `403 Forbidden` |
| **Authentication** | `GET` | `/auth/logout` | Optional | Terminates session, clears cookie, returns JSON confirmation. | `200 OK`, `302 Found` |
| **Authentication** | `POST` | `/auth/logout` | Optional | Terminates session, clears cookie, returns JSON confirmation. | `200 OK`, `302 Found` |
| **Scanner** | `POST` | `/api/scan` | Yes (`cloudsec.sid`) | Evaluates 1–500 cloud resources against 8 detection rules. | `200 OK`, `400 Bad Request`, `401 Unauthorized` |
| **Scanner** | `GET` | `/api/scans` | Yes (`cloudsec.sid`) | Retrieves up to 20 recent scans from MongoDB for the active user. | `200 OK`, `401 Unauthorized`, `503 Unavailable` |

---

## 3. Authentication & Session Management

The platform uses **Express Session** with `HttpOnly`, `SameSite=lax` cookies named `cloudsec.sid`. Authentication is tied to Google OAuth 2.0 with session regeneration upon sign-in to eliminate session fixation vulnerabilities.

### How to Authenticate for Protected Endpoints

Because the platform authenticates via Google OAuth 2.0, you have three reliable options to test protected endpoints:

#### Method 1: Postman Desktop Native Cookie Jar (Recommended)
1. Open your browser and navigate to `http://localhost:3001/login`.
2. Click **Continue with Google** and complete sign-in.
3. In the Postman Desktop App:
   - Click the **Cookies** link located under the **Send** button on any request.
   - Select or add domain `localhost`.
   - Postman's native cookie manager automatically shares/captures the `cloudsec.sid` cookie, and subsequent requests to `{{baseUrl}}` will include it automatically.

#### Method 2: Manual Cookie Header via Postman Environment
1. In your browser (Chrome/Edge/Firefox), open DevTools (`F12`) after logging into `http://localhost:3001`.
2. Go to **Application** (or **Storage**) → **Cookies** → `http://localhost:3001`.
3. Copy the value of the `cloudsec.sid` cookie (e.g., `s%3A_abc123...`).
4. In Postman, edit the active environment (`Cloud Security Platform - Local (Port 3001)`).
5. Paste the cookie value into the `sessionCookie` variable and save.
6. The collection's **Collection Pre-request Script** automatically attaches `Cookie: cloudsec.sid={{sessionCookie}}` to all outgoing requests.

#### Method 3: Development/Test Mode Endpoint (`POST /auth/test-session`)
When the application is started in test mode (`NODE_ENV=test`):
- A helper endpoint `POST /auth/test-session` is active.
- Sending a `POST` request to `{{baseUrl}}/auth/test-session` immediately issues an authenticated `cloudsec.sid` session cookie with dummy auditor credentials, without requiring interaction with Google's servers.

---

## 4. Automated Misconfiguration Detection Rules

The backend scanner evaluates submitted cloud infrastructure against **8 security checks**:

| Rule ID | Target Resource | Severity | Condition Triggered | Remediation |
| :--- | :--- | :--- | :--- | :--- |
| `S3_PUBLIC_ACCESS` | `s3` | **CRITICAL** | `publicAccess === true` or `blockPublicAccess === false` | Enable all S3 Block Public Access settings and review bucket policies. |
| `S3_ENCRYPTION_DISABLED` | `s3` | **HIGH** | `encryptionEnabled === false` | Enable default server-side encryption (SSE-S3 or AWS KMS). |
| `OPEN_SSH` | `security-group` | **CRITICAL** | Port 22 ingress CIDR is `0.0.0.0/0` or `::/0` | Restrict SSH access to trusted VPN, bastion host, or approved CIDR. |
| `OPEN_RDP` | `security-group` | **CRITICAL** | Port 3389 ingress CIDR is `0.0.0.0/0` or `::/0` | Restrict RDP access to a trusted corporate VPN or bastion host. |
| `IAM_WILDCARD_POLICY` | `iam-policy` | **HIGH** | `action === "*"` or `resource === "*"` | Apply least-privilege: specify only needed actions and resource ARNs. |
| `DATABASE_PUBLIC` | `database` | **CRITICAL** | `publiclyAccessible === true` | Disable public accessibility and place database in private subnets. |
| `CLOUDTRAIL_DISABLED` | `cloudtrail` | **MEDIUM** | `enabled === false` | Enable CloudTrail across all regions and protect log integrity. |
| `EBS_ENCRYPTION_DISABLED` | `ebs` | **MEDIUM** | `encrypted === false` | Enable EBS encryption by default and encrypt existing volumes. |

---

## 5. Sample Payloads

### Complete 8-Rule Vulnerability Test Payload
Included in `POST /api/scan (8 Misconfiguration Rules)`. Triggers all 8 detection rules across 6 vulnerable resources, and includes 1 compliant resource (`bucket-secure-audit-logs`):

```json
{
  "resources": [
    {
      "id": "bucket-customer-uploads",
      "type": "s3",
      "publicAccess": true,
      "blockPublicAccess": false,
      "encryptionEnabled": false
    },
    {
      "id": "sg-external-admin-access",
      "type": "security-group",
      "ingress": [
        { "port": 22, "cidr": "0.0.0.0/0" },
        { "port": 3389, "cidr": "0.0.0.0/0" }
      ]
    },
    {
      "id": "iam-admin-fullaccess-policy",
      "type": "iam-policy",
      "action": "*",
      "resource": "*"
    },
    {
      "id": "prod-customer-aurora-db",
      "type": "database",
      "publiclyAccessible": true
    },
    {
      "id": "global-audit-trail",
      "type": "cloudtrail",
      "enabled": false
    },
    {
      "id": "vol-finance-records-01",
      "type": "ebs",
      "encrypted": false
    },
    {
      "id": "bucket-secure-audit-logs",
      "type": "s3",
      "publicAccess": false,
      "blockPublicAccess": true,
      "encryptionEnabled": true
    }
  ]
}
```

### Compliant / Hardened Payload
Included in `POST /api/scan (Compliant Resources)`. Demonstrates that secure infrastructure yields **0 findings**:

```json
{
  "resources": [
    {
      "id": "bucket-hardened-assets",
      "type": "s3",
      "publicAccess": false,
      "blockPublicAccess": true,
      "encryptionEnabled": true
    },
    {
      "id": "sg-secure-web-tier",
      "type": "security-group",
      "ingress": [
        { "port": 443, "cidr": "10.0.0.0/16" }
      ]
    },
    {
      "id": "iam-readonly-billing-policy",
      "type": "iam-policy",
      "action": "aws-portal:ViewBilling",
      "resource": "arn:aws:billing:::billing-report"
    },
    {
      "id": "rds-internal-inventory-db",
      "type": "database",
      "publiclyAccessible": false
    },
    {
      "id": "cloudtrail-security-events",
      "type": "cloudtrail",
      "enabled": true
    },
    {
      "id": "ebs-encrypted-root-vol",
      "type": "ebs",
      "encrypted": true
    }
  ]
}
```

---

## 6. How to Import and Run in Postman

### Step 1: Import Files into Postman
1. Launch **Postman** (Desktop application recommended).
2. Click the **Import** button in the top-left corner.
3. Select or drag-and-drop both files located in the `postman/` directory:
   - `postman/Cloud-Security-Platform.postman_collection.json`
   - `postman/Cloud-Security-Platform.postman_environment.json`
4. Confirm the import. You will see:
   - Collection: **Cloud Security Misconfiguration Detection Platform**
   - Environment: **Cloud Security Platform - Local (Port 3001)**

### Step 2: Select the Environment
In the upper-right corner of Postman, click the Environment dropdown and select **Cloud Security Platform - Local (Port 3001)**.

### Step 3: Execute Requests
You can run requests individually or use the automated test runner:
1. **System Health Check**: Send `1. System` → `System Health Status`. Verifies database and OAuth status.
2. **Authentication Verification**:
   - Run `Get Current User Profile - Unauthenticated` to confirm that HTTP 401 is enforced.
   - Sign in via browser or populate `sessionCookie`, then run `Get Current User Profile - Authenticated` to verify HTTP 200 with user metadata.
3. **Scanner Demonstrations**:
   - Run `Scan Cloud Infrastructure - 8 Misconfiguration Rules` to demonstrate detection across all 8 rules.
   - Run `Scan Cloud Infrastructure - Compliant Resources` to demonstrate zero false positives on compliant configurations.
   - Run `Scan Cloud Infrastructure - Empty Array Validation` to demonstrate HTTP 400 input validation.
   - Run `Retrieve Recent Scan History - Authenticated` to view the saved scans in MongoDB.
4. **Sign Out**:
   - Run `Sign Out Current User - POST` to demonstrate session termination and cookie invalidation.

---

## 7. Running with Newman CLI (Automated Test Execution)

To run the entire collection headlessly from PowerShell or a terminal:

```bash
# Install Newman if not already present
npm install -g newman

# Run the collection using the local environment
newman run postman/Cloud-Security-Platform.postman_collection.json \
  -e postman/Cloud-Security-Platform.postman_environment.json \
  --reporters cli
```

---

## 8. Summary of Automated Postman Test Assertions

Each request includes executable Postman test scripts that validate:
- HTTP Status Codes (`200 OK`, `302 Found`, `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`).
- Response Body Schemas (presence of `summary`, `findings`, `resourceCount`, `persistence`, `user`).
- Exact Rule Identifiers (`S3_PUBLIC_ACCESS`, `OPEN_SSH`, etc.).
- Security Headers (`Set-Cookie` with `HttpOnly`, `Location` for OAuth redirects).
- Automatic Environment Variable propagation (`activeUserId`, `lastScanId`).
