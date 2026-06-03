# PingOne DaVinci Sign-On Flow — Node.js / Express

Demonstrates driving a DaVinci sign-on flow to completion using the PingOne auth API. The app presents a login form, drives the three-step flow server-side, and displays the resulting access token.

## What it does

1. **Start flow** — `GET /as/authorize?response_mode=pi.flow` initialises a DaVinci flow session and returns session handles (`interactionId`, `interactionToken`, `connectionId`, `capabilityName`, `id`).
2. **Submit credentials** — `POST /davinci/connections/{connectionId}/capabilities/{capabilityName}` sends the user's username and password to the DaVinci capability that is waiting for input. A successful response contains an authorization code in `authorizeResponse.code`.
3. **Exchange token** — `POST /as/token` exchanges the authorization code for an access token using the standard OAuth 2.0 `authorization_code` grant.

A startup check probes the authorize endpoint before accepting traffic. If the app has no DaVinci flow policy assignment the server exits with a clear error rather than failing mid-login.

## PingOne configuration

You need a **Web App** (OIDC) in PingOne with:

- **Grant type**: Authorization Code
- **Token endpoint authentication**: `CLIENT_SECRET_BASIC`
- **Redirect URIs**: add the value you set for `PINGONE_REDIRECT_URI` (e.g. `http://localhost:3000/callback`)
- **DaVinci flow policy assignment**: assign a sign-on flow policy to the app. The DaVinci flow must use the **API** integration method so it returns JSON responses instead of HTML. Without this assignment the startup check will fail.

A test user must exist in the population that the DaVinci flow's PingOne SSO connector targets.

## How to run

```bash
cd p1-davinci-signon-js
cp .env.example .env
# fill in your values in .env
npm install
npm start
```

Then open [http://localhost:3000](http://localhost:3000) and sign in with your test user's credentials.

## Environment variables

| Variable | Purpose |
|---|---|
| `PINGONE_ENV_ID` | ID of the PingOne environment that contains the OIDC app |
| `PINGONE_CLIENT_ID` | Client ID of the Web App (OIDC) |
| `PINGONE_CLIENT_SECRET` | Client secret of the Web App (OIDC) |
| `PINGONE_AUTH_PATH` | Regional base URL for the PingOne auth service (no trailing slash). North America: `https://auth.pingone.com`; Europe: `https://auth.pingone.eu`; Canada: `https://auth.pingone.ca`; Asia-Pacific: `https://auth.pingone.asia` |
| `PINGONE_REDIRECT_URI` | Redirect URI registered on the app. Used in the authorize and token requests. A placeholder like `http://localhost:3000/callback` is sufficient — the browser is never redirected here. |
