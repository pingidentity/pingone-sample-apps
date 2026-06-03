# p1-davinci-signon-react

React (Vite) + Node/Express port of the PingOne DaVinci Sign-On sample.

## What it does

- **Step 1 — Start DaVinci Flow**: GET `/as/authorize?response_mode=pi.flow` — initialises a DaVinci flow session and returns JSON flow handles (interactionId, interactionToken, connectionId, capabilityName, id) instead of redirecting the browser.
- **Step 2 — Submit Sign-On**: POST `/davinci/connections/{connectionId}/capabilities/{capabilityName}` — submits the user's username and password to the waiting DaVinci node; a successful response contains an authorization code in `authorizeResponse.code`.
- **Step 3 — Exchange Authorization Code**: POST `/as/token` — standard OAuth 2.0 `authorization_code` exchange using HTTP Basic (`CLIENT_SECRET_BASIC`); returns an access token.

A startup probe confirms the OIDC app has a DaVinci flow policy assignment before accepting sign-on traffic.

## PingOne configuration

You need **one PingOne application**:

| Setting | Value |
|---------|-------|
| Application type | Web App |
| Grant type | Authorization Code |
| Token endpoint auth method | CLIENT_SECRET_BASIC |
| Redirect URI | `http://localhost:3000/callback` (must match `PINGONE_REDIRECT_URI`) |
| Flow policy assignment | A DaVinci flow that uses a PingOne SSO connector with the API integration method (JSON responses) |

The DaVinci flow must:
- Use the **API integration** method (not the widget) so PingOne returns JSON flow handles.
- Target a population containing your test user.
- Reach a terminal success node that emits `authorizeResponse.code`.

## How to run

```bash
# Terminal 1 — backend
cd server && npm install && npm start

# Terminal 2 — frontend
cd client && npm install && npm run dev
```

Then open [http://localhost:5173](http://localhost:5173).

## Environment variables

Copy `server/.env.example` to `server/.env` and fill in the values.

| Variable | Purpose |
|----------|---------|
| `PINGONE_ENV_ID` | PingOne environment ID |
| `PINGONE_CLIENT_ID` | OAuth 2.0 client ID of the Web App |
| `PINGONE_CLIENT_SECRET` | OAuth 2.0 client secret |
| `PINGONE_AUTH_PATH` | Regional auth base URL, e.g. `https://auth.pingone.com` (no trailing slash) |
| `PINGONE_REDIRECT_URI` | Redirect URI registered on the app, e.g. `http://localhost:3000/callback` |
