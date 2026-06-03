# PingOne DaVinci Sign-On — Angular 18 + Node/Express

Demonstrates a DaVinci-driven sign-on flow using PingOne Auth, ported from the canonical Go implementation. The user enters credentials in the Angular UI; the Node/Express backend drives the three-step flow server-side and returns structured step results for display.

## What it does

1. **Start DaVinci Flow** — `GET /as/authorize?response_mode=pi.flow` initialises a DaVinci flow session. Instead of redirecting the browser, PingOne returns JSON flow handles (`interactionId`, `interactionToken`, `connectionId`, `capabilityName`, `id`).
2. **Submit Sign-On** — `POST /davinci/connections/{connectionId}/capabilities/{capabilityName}` submits the user's credentials to the DaVinci capability node waiting for input. A successful response contains `authorizeResponse.code`.
3. **Exchange Authorization Code** — `POST /as/token` exchanges the authorization code for an access token using the standard OAuth 2.0 `authorization_code` grant (CLIENT_SECRET_BASIC).

---

## Project layout

```
p1-davinci-signon-angular/
├── logo.png
├── server/          Node/Express backend (port 3000)
│   ├── index.js
│   ├── package.json
│   └── .env.example
└── client/          Angular 18 frontend (port 4200, dev server)
    ├── angular.json
    ├── package.json
    ├── proxy.conf.json
    ├── tsconfig.json
    ├── tsconfig.app.json
    └── src/
        ├── index.html
        ├── main.ts
        └── app/
            └── app.component.ts
```

---

## PingOne configuration

### OIDC Web App

1. Create (or use an existing) **Web App** in PingOne with grant type **Authorization Code** and token authentication method **CLIENT_SECRET_BASIC**.
2. Add `http://localhost:3000/callback` to the app's **Redirect URIs**.
3. Assign a **DaVinci flow policy** to the app that points at a sign-on flow. Without this assignment the authorize endpoint redirects instead of returning JSON handles, and the server will exit at startup with a clear error.

### DaVinci flow

- The flow must use the **API integration** method (returns JSON responses rather than HTML).
- The flow must be set up to return a DaVinci flow JSON response (not an HTML page).
- A test user must exist in the population targeted by the flow's PingOne SSO connector.

---

## Environment variables

Copy `server/.env.example` to `server/.env` and fill in the values.

| Variable | Description |
|---|---|
| `PINGONE_ENV_ID` | Environment ID that owns the OIDC app |
| `PINGONE_CLIENT_ID` | Client ID of the Web App (OIDC, authorization_code) |
| `PINGONE_CLIENT_SECRET` | Client secret of the Web App |
| `PINGONE_AUTH_PATH` | PingOne auth base URL, e.g. `https://auth.pingone.com` (no trailing slash) |
| `PINGONE_REDIRECT_URI` | Must match the app registration, e.g. `http://localhost:3000/callback` |

Regional auth base URLs:
- NA: `https://auth.pingone.com`
- EU: `https://auth.pingone.eu`
- AP: `https://auth.pingone.asia`
- CA: `https://auth.pingone.ca`

---

## Running locally

### Terminal 1 — backend

```bash
cd server
npm install
cp .env.example .env   # then fill in your values
npm start
# → Startup check passed: DaVinci flow policy assignment is present.
# → DaVinci Sign-On demo backend on http://localhost:3000
```

### Terminal 2 — frontend

```bash
cd client
npm install
npm start
# → Angular live development server listening on http://localhost:4200
```

Open **http://localhost:4200** in a browser. Enter a valid username and password, then click **Sign On**.

The Angular dev server proxies `/api/*` requests to `http://localhost:3000` via `proxy.conf.json`, so no CORS setup is needed in development.

---

## API

`POST /api/run` accepts `{ username, password }` and returns:

```json
{
  "success": true,
  "steps": [
    {
      "title": "Start DaVinci Flow",
      "ok": true,
      "detail": "flow started id=xxx capability=yyy",
      "body": "{ ... }",
      "url": "GET https://auth.pingone.com/{envID}/as/authorize?...",
      "collapsed": false
    },
    {
      "title": "Submit Sign-On",
      "ok": true,
      "detail": "authorization code received",
      "body": "{ ... }",
      "url": "POST https://auth.pingone.com/{envID}/davinci/connections/.../capabilities/...",
      "collapsed": false
    },
    {
      "title": "Exchange Authorization Code",
      "ok": true,
      "detail": "access_token received",
      "body": "{ ... }",
      "url": "POST https://auth.pingone.com/{envID}/as/token",
      "collapsed": false
    }
  ]
}
```

If any step fails the workflow stops immediately, `success` is `false`, and the last entry in `steps` is the failing step.

---

## Production build

```bash
cd client
npm run build   # outputs to client/dist/p1-davinci-signon-angular/browser/
```

The Express server in `server/index.js` serves the built Angular app from that path, so you can then run `npm start` in `server/` and browse directly to **http://localhost:3000**.
