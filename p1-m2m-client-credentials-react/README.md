# PingOne M2M Client Credentials + Protect — React

React (Vite) + Node/Express port of the Go `p1-m2m-client-credentials-go` sample.

## What it does

Demonstrates the OAuth 2.0 **client_credentials** grant with JWT verification and two PingOne Protect risk evaluations:

1. **Build token request** — assembles the `client_credentials` grant parameters (no HTTP call yet)
2. **Token endpoint response** — `POST {authPath}/{envID}/as/token` with HTTP Basic auth
3. **Decode access token** — base64url-decode the JWT header and payload
4. **Fetch JWKS** — `GET {authPath}/{envID}/as/jwks` (collapsed by default)
5. **Verify access token signature** — RS256 verification using Node `crypto`
6. **Validate access token claims** — `iss`, `client_id`, `exp`, `iat`

Then two parallel risk + gate paths:

- **User A — trusted** (real client IP, `type=EXTERNAL`)
  - **7a.** PingOne Protect risk evaluation
  - **8a.** Call PingOne Management API (proceeds if LOW/MEDIUM, blocked if HIGH)
- **User B — suspicious** (Tor exit node `185.220.101.1`, `type=ANONYMOUS`)
  - **7b.** PingOne Protect risk evaluation
  - **8b.** Call PingOne Management API (expected: BLOCKED — HIGH risk)

## PingOne configuration required

- **Worker application** with Token Endpoint Auth Method = `Client Secret Basic`
- Worker app must have **Identity Data** (read users) and **PingOne Protect** (risk evaluation) roles
- A **Protect risk policy set** with **Anonymous Network Detection** enabled and HIGH threshold ≤ 80
- The risk policy set's ID goes in `PINGONE_RISK_POLICY_SET_ID`

## Run instructions

```bash
# 1. Start the backend
cd server
cp .env.example .env
# Fill in all values in .env
npm install
npm start          # Express on http://localhost:3000

# 2. In a second terminal — start the frontend dev server
cd client
npm install
npm run dev        # Vite on http://localhost:5173
```

Open [http://localhost:5173](http://localhost:5173) and click **Run Flow**.

For production, build the client first (`npm run build` in `client/`) and the Express server will serve the static files from `client/dist/`.

## Environment variables

| Variable | Purpose |
|---|---|
| `PINGONE_ENV_ID` | PingOne environment ID |
| `PINGONE_CLIENT_ID` | Worker application client ID |
| `PINGONE_CLIENT_SECRET` | Worker application client secret |
| `PINGONE_AUTH_PATH` | Auth base URL, e.g. `https://auth.pingone.com` |
| `PINGONE_API_PATH` | Management API base URL, e.g. `https://api.pingone.com` |
| `PINGONE_RISK_POLICY_SET_ID` | Protect risk policy set ID (must have Anonymous Network Detection) |
