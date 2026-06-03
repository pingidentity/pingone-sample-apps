# p1-oidc-pkce-js

Node.js/Express web app that walks through the OIDC Authorization Code + PKCE flow against PingOne, with every
artifact rendered on the page so the details are visible code rather than mystery values.

The client is **confidential** — token exchange uses HTTP Basic auth (client ID + secret) AND the
PKCE `code_verifier`.

## Why this exists

PKCE has small details that trip people (and LLMs) up:

- `code_verifier` length and charset (43–128 from `[A-Za-z0-9-._~]`)
- `code_challenge = base64url-no-pad(SHA-256(verifier))` — base64**url** with no padding, not standard base64
- `code_challenge_method` must be exactly `S256` (uppercase)
- `state` and `nonce` serve different purposes (CSRF on the redirect vs replay on the ID token)
- ID token validation actually means signature + `iss`/`aud`/`exp`/`iat`/`nonce` checks

This sample shows each of those explicitly.

## What the app demonstrates

1. **`/`** — start page.
2. **`/prepare`** — server generates and displays the PKCE artifacts before redirecting:
   - `code_verifier` (43-char base64url of 32 random bytes)
   - SHA-256 digest (hex) and `code_challenge` (base64url-no-pad)
   - `state` and `nonce`
   - The fully assembled `/authorize` URL
3. **`/callback`** — after PingOne redirects back, the page renders cards for:
   1. Receive callback (`code` + `state`)
   2. Validate `state`
   3. Token exchange (HTTP Basic + `code_verifier`)
   4. Decode ID token (header + payload)
   5. Fetch JWKS
   6. Verify ID token signature (RS256, key matched by `kid`)
   7. Validate ID token claims (`iss`, `aud`, `exp`, `iat`, `nonce`)
   8. Call `/userinfo` with the access token
   9. Final tokens
4. **`/refresh`** — exchange the refresh token for a fresh access token.

## PingOne configuration

Only **one** application required. No worker app needed.

### OIDC web app

- **Type**: OIDC Web App
- **Grant types**: Authorization Code, Refresh Token (if you want to exercise step 4)
- **Response types**: Code
- **Redirect URIs**: `http://localhost:3000/callback`
- **PKCE Enforcement**: **REQUIRED** (the whole point of this sample)
- **Token Endpoint Auth Method**: **Client Secret Basic**

### Environment settings

- A user must exist that you can sign in as on the PingOne hosted login page.

## Run

```bash
cp .env.example .env
# fill in your PingOne credentials
npm install
npm start
```

Open http://localhost:3000 and click **Begin Login**.

## Environment variables

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID of the OIDC app |
| `PINGONE_CLIENT_ID` | OIDC app client ID |
| `PINGONE_CLIENT_SECRET` | OIDC app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
| `PINGONE_REDIRECT_URI` | Must match the redirect URI registered on the OIDC app |
| `PINGONE_SCOPES` | Space-separated, e.g. `openid profile email` |
