# p1-m2m-client-credentials-go

Go web app that walks through the OAuth 2.0 **client_credentials** grant against PingOne, with every
step rendered as a card so the details are visible rather than hidden inside library code.

## Why this exists

The `client_credentials` grant is the canonical M2M pattern: no user, no browser redirect, no PKCE.
A service authenticates with its own credentials and receives an access token it can use to call
downstream APIs. The details that trip people up:

- There is **no authorization code** and **no redirect URI** — the token endpoint is called directly
- The client authenticates with **HTTP Basic auth** (`client_id:client_secret`, base64-encoded)
- The access token is still a **signed JWT** — it should be decoded and its signature + claims verified
  before any resource server trusts it
- For PingOne Worker app tokens, **`client_id` holds the client identity** (not `sub`), and there is no `nonce`
- The token is used as a **Bearer token** on downstream API calls

This sample shows each of those explicitly.

## What the app demonstrates

1. **`/`** — start page.
2. **`/run`** — executes the entire flow server-side and renders cards for each step:
   1. Build token request (client credentials, grant type, scopes)
   2. Token endpoint response (single round-trip — no redirect)
   3. Decode access token (header + payload)
   4. Fetch JWKS
   5. Verify access token signature (RS256, key matched by `kid`)
   6. Validate access token claims (`iss`, `client_id`, `exp`, `iat`)
   7. PingOne Protect risk evaluation (`POST /v1/environments/{envID}/riskEvaluations`) — scores the request against the configured risk policy set
   8. Call PingOne Management API (`GET /v1/environments/{envID}/users`) with the access token — **only if the risk level is not HIGH**

## PingOne configuration

### Worker app

- **Type**: Worker
- **Grant types**: Client Credentials
- **Token Endpoint Auth Method**: **Client Secret Basic**

### Role assignment

For the management API call (step 8) to succeed, the Worker app must have a role assigned:

- Go to **Identities → Roles** → assign **Identity Data Read Only** (or higher) to the Worker app
  at the environment level.

For the risk evaluation (step 7) to succeed, the Worker app also needs Protect access:

- Assign a role that grants risk evaluation permissions (e.g. **Identity Data Admin** or a role
  scoped to PingOne Protect) at the environment level.

### PingOne Protect risk policy set

A risk policy set must exist in the environment. Copy its ID into `PINGONE_RISK_POLICY_SET_ID`.

- **Protect → Risk policies** → create or use an existing policy set.
- The demo posts a synthetic event (`user.id=m2m-demo-user`, `user.type=EXTERNAL`, the local
  request IP, and the request's User-Agent). To force the gating branch to fire, configure a
  predictor that flags this fake user or your local IP as HIGH.

### Environment settings

No users need to exist — the client_credentials grant is entirely serverless.

## Run

```bash
cp .env.example .env
# fill in your PingOne credentials
go run main.go
```

Open http://localhost:3000 and click **Run Flow**.

## Environment variables

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID |
| `PINGONE_CLIENT_ID` | Worker app client ID |
| `PINGONE_CLIENT_SECRET` | Worker app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
| `PINGONE_API_PATH` | Regional API host (`https://api.pingone.com` / `.ca` / `.eu` / `.asia`) |
| `PINGONE_RISK_POLICY_SET_ID` | PingOne Protect risk policy set ID — required, gates the management API call |
| `PINGONE_SCOPES` | Optional space-separated scopes (leave empty for default) |
