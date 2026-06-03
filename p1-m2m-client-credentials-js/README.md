# PingOne M2M Client Credentials + PingOne Protect — Node.js/Express

Node.js/Express port of the Go reference implementation. Demonstrates the OAuth 2.0 `client_credentials` grant followed by two PingOne Protect risk evaluations with different risk profiles, showing how a service can gate downstream API calls based on risk level.

## What it does

1. **Build token request** — assembles the `client_credentials` grant request (no HTTP call yet)
2. **Call token endpoint** — `POST {authPath}/{envID}/as/token` with Basic auth; receives an access token
3. **Decode access token** — base64url-decodes the JWT header and payload (no signature verify yet)
4. **Fetch JWKS** — `GET {authPath}/{envID}/as/jwks`; retrieves the public keys for signature verification
5. **Verify access token signature** — RS256 verification using Node's built-in `crypto` module; key matched by `kid`
6. **Validate access token claims** — checks `iss`, `client_id` (not `sub`), `exp > now`, `iat` not in future

Then two parallel paths:

**User A — trusted (real IP, `type=EXTERNAL`)**

7a. **PingOne Protect risk evaluation** — `POST {apiPath}/v1/environments/{envID}/riskEvaluations` with the real client IP and `type=EXTERNAL`
8a. **Call PingOne Management API** — `GET {apiPath}/v1/environments/{envID}/users` — proceeds if risk is LOW or MEDIUM

**User B — suspicious (Tor IP, `type=ANONYMOUS`)**

7b. **PingOne Protect risk evaluation** — same endpoint, Tor exit node IP `185.220.101.1` and `type=ANONYMOUS`; Anonymous Network Detection scores it HIGH
8b. **Call PingOne Management API** — **blocked** because risk level is HIGH

## PingOne configuration required

- **Worker application** with grant type `Client Credentials` and Token Endpoint Auth Method `Client Secret Basic`
- The Worker app must have the following roles assigned:
  - **Identity Data Read** — for `GET /environments/{envID}/users`
  - **PingOne Protect** — for creating risk evaluations
- A **Protect risk policy set** with:
  - Anonymous Network Detection predictor enabled
  - HIGH threshold set below 80 (e.g. 75) so that `185.220.101.1` triggers HIGH
  - Record its ID in `PINGONE_RISK_POLICY_SET_ID`

## Run instructions

```bash
cd p1-m2m-client-credentials-js
cp .env.example .env
# Edit .env with your PingOne credentials
npm install
npm start
```

Open http://localhost:3000 in your browser, then click **Run Flow**.

## Environment variables

| Variable | Purpose |
|---|---|
| `PINGONE_ENV_ID` | PingOne environment ID that owns the Worker application |
| `PINGONE_CLIENT_ID` | Worker application client ID |
| `PINGONE_CLIENT_SECRET` | Worker application client secret |
| `PINGONE_AUTH_PATH` | PingOne regional auth base URL (e.g. `https://auth.pingone.com`) |
| `PINGONE_API_PATH` | PingOne regional API base URL (e.g. `https://api.pingone.com`) |
| `PINGONE_RISK_POLICY_SET_ID` | ID of the Protect risk policy set with Anonymous Network Detection enabled |
