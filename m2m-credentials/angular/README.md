# PingOne M2M Client Credentials + PingOne Protect — Angular 18

Angular 18 + Node/Express port of the Go `p1-m2m-client-credentials-go` sample.

## What it does

Walks through the OAuth 2.0 `client_credentials` grant (no user, no browser redirect) and then calls PingOne Protect for two contrasting risk evaluations:

1. **Build token request** — assembles Basic-auth header and `grant_type=client_credentials` form body
2. **Call token endpoint** — `POST {authPath}/{envID}/as/token`; receives access token
3. **Decode access token** — base64url-decodes the JWT header and payload without signature check
4. **Fetch JWKS** — `GET {authPath}/{envID}/as/jwks`; retrieves public keys (collapsed by default)
5. **Verify access token signature** — RS256 verification using Node `crypto.createVerify`
6. **Validate access token claims** — checks `iss`, `client_id`, `exp`, `iat`

**User A — trusted (real IP, type=EXTERNAL)**

7a. **PingOne Protect risk evaluation** — submits real IP + `type=EXTERNAL`; expects LOW/MEDIUM
8a. **Call PingOne Management API** — `GET /v1/environments/{envID}/users`; proceeds because risk is not HIGH

**User B — suspicious (Tor IP, type=ANONYMOUS)**

7b. **PingOne Protect risk evaluation** — submits `185.220.101.1` (Tor exit node) + `type=ANONYMOUS`; expects HIGH
8b. **Call PingOne Management API** — **blocked** because Anonymous Network Detection returns HIGH

## PingOne configuration required

- **Worker application** with:
  - Token Endpoint Auth Method: `CLIENT_SECRET_BASIC`
  - Grant Type: `CLIENT_CREDENTIALS`
  - Role: **Identity Data Admin** (read users)
  - Role: **PingOne Protect** (create risk evaluations)
- **Protect risk policy set** with Anonymous Network Detection enabled, HIGH threshold ≤ 75
  - Copy the policy set ID into `PINGONE_RISK_POLICY_SET_ID`

## Run instructions

### 1. Backend (Express)

```bash
cd server
cp .env.example .env
# fill in your values in .env
npm install
npm start
# Listens on http://localhost:3000
```

### 2. Frontend (Angular dev server)

```bash
cd client
npm install
npm start
# Opens http://localhost:4200 — proxies /api to :3000
```

Click **Run Flow** to execute the full workflow.

## Environment variables

| Variable | Purpose |
|---|---|
| `PINGONE_ENV_ID` | PingOne environment UUID |
| `PINGONE_CLIENT_ID` | Worker application client ID |
| `PINGONE_CLIENT_SECRET` | Worker application client secret |
| `PINGONE_AUTH_PATH` | Regional auth base URL (e.g. `https://auth.pingone.com`) |
| `PINGONE_API_PATH` | Regional API base URL (e.g. `https://api.pingone.com`) |
| `PINGONE_RISK_POLICY_SET_ID` | UUID of the Protect risk policy set |
