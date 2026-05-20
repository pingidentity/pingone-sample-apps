# p1-user-registration-react

React UI + Node/Express backend implementing PingOne self-service user registration + login.

The backend proxies PingOne because the client secret must not be exposed to the browser, and
PingOne's flow API does not support browser CORS.

## Layout

- `server/` — Node/Express backend (port 3000). Exposes `/api/register`, `/api/verify`, `/api/login`.
- `client/` — React app (Vite). Dev on port 5173, proxies `/api` to :3000.

## PingOne configuration

Only **one** application is required — no admin worker app is needed.

### OIDC web app

- **Type**: OIDC Web App
- **Grant types**: Authorization Code
- **Response types**: Code
- **Redirect URIs**: `http://localhost:3000/callback`
- **Token endpoint auth method**: Client Secret Basic

### Environment settings

- The sign-on policy must permit user self-registration and include an email verification step.
- At least one population must exist.

## Run (dev)

```bash
# Terminal 1
cd server
cp .env.example .env       # fill in your PingOne credentials
npm install && npm start   # http://localhost:3000

# Terminal 2
cd client
npm install && npm run dev # http://localhost:5173
```

## Environment variables (server/.env)

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID of the OIDC app |
| `PINGONE_CLIENT_ID` | OIDC app client ID |
| `PINGONE_CLIENT_SECRET` | OIDC app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
