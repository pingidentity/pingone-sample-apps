# PingOne DaVinci Sign-On — Python / Flask

A single-file Flask app that demonstrates a server-driven DaVinci sign-on flow
using PingOne Auth.

## What it does

1. **Startup check** — probes the authorize endpoint to confirm a DaVinci flow
   policy is assigned to the OIDC app. Exits with a clear error if the endpoint
   redirects instead of returning JSON flow handles.

2. **Login form** — serves a username/password form at `GET /`.

3. **Step 1 — Start flow** (`GET /as/authorize?response_mode=pi.flow`) — the
   server calls the PingOne authorize endpoint. Instead of redirecting, PingOne
   returns a JSON envelope with session handles (`interactionId`,
   `interactionToken`, `connectionId`, `capabilityName`, `id`).

4. **Step 2 — Submit credentials**
   (`POST /davinci/connections/{connectionId}/capabilities/{capabilityName}`) —
   the server sends the user's credentials to the DaVinci capability node. On
   success the flow completes and the response includes an authorization code in
   `authorizeResponse.code`.

5. **Step 3 — Exchange token** (`POST /as/token`) — the authorization code is
   exchanged for an access token using the standard OAuth 2.0
   `authorization_code` grant with `CLIENT_SECRET_BASIC` authentication.

6. **Result** — the access token is displayed on a dashboard page, or an error
   page is shown if any step fails.

## PingOne configuration

### OIDC Web App

Create (or use an existing) **Web App** in your PingOne environment:

- **Grant type**: Authorization Code
- **Token endpoint authentication method**: `CLIENT_SECRET_BASIC`
- **Redirect URIs**: add the value you set for `PINGONE_REDIRECT_URI` (e.g.
  `http://localhost:3000/callback`)
- **Response mode**: the app sends `response_mode=pi.flow` — no special
  configuration is needed for this; it is determined by the request.

### DaVinci flow policy assignment

The OIDC app must have a **DaVinci flow policy** assigned that points at a
sign-on flow:

1. In PingOne, go to **Connections → Applications**, open your Web App, and
   select the **Flow Policy** tab.
2. Add a policy that references a DaVinci flow containing a **PingOne SSO
   connector** configured for sign-on (action: `userLookup` or equivalent).
3. The DaVinci flow must use **API integration** so PingOne returns JSON
   responses rather than HTML forms.

Without this assignment the authorize endpoint will 302-redirect instead of
returning JSON handles, and the startup check will exit with an explanatory
error.

### Test user

Create a test user in the population that the DaVinci flow's PingOne SSO
connector targets.

## How to run

```bash
cd p1-davinci-signon-python

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and fill in your values

# Start the app
python app.py
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Environment variables

| Variable | Purpose |
|---|---|
| `PINGONE_ENV_ID` | ID of the PingOne environment containing the OIDC app |
| `PINGONE_CLIENT_ID` | Client ID of the OIDC Web App |
| `PINGONE_CLIENT_SECRET` | Client secret of the OIDC Web App |
| `PINGONE_AUTH_PATH` | Regional PingOne auth base URL (e.g. `https://auth.pingone.com`) |
| `PINGONE_REDIRECT_URI` | Redirect URI registered on the OIDC app (e.g. `http://localhost:3000/callback`) |
