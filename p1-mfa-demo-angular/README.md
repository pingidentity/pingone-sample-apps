# p1-mfa-demo-angular

Angular UI + Node/Express backend implementing PingOne registration + email-MFA login.

The backend proxies PingOne because the client secret and admin worker app credentials cannot be
exposed in the browser, and PingOne's flow API does not support browser CORS.

## Layout

- `server/` — Node/Express backend (port 3000). Same API as the React version.
- `client/` — Angular app. Dev on port 4200, proxies `/api` to :3000.

## PingOne configuration

You need **two** applications:

### 1. End-user OIDC web app

- **Type**: OIDC Web App
- **Grant types**: Authorization Code
- **Response types**: Code
- **Redirect URIs**: `http://localhost:3000/callback`
- **Token endpoint auth method**: Client Secret Basic

### 2. Admin worker app

- **Type**: Worker
- **Assigned role**: **Identity Data Admin** (or broader)

The worker app is required because PingOne's `/flows/{id}` endpoints need a bearer token on every
call during the MFA challenge.

### Environment settings

- Enable the **Email** MFA device type in the sign-on policy used by the OIDC app.
- Ensure at least one population exists for new users to register into.

## Run (dev)

```bash
# Terminal 1
cd server
cp .env.example .env       # fill in your PingOne credentials
npm install
npm start                  # http://localhost:3000

# Terminal 2
cd client
npm install
npm start                  # http://localhost:4200
```

## Environment variables (server/.env)

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID of the end-user OIDC app |
| `PINGONE_CLIENT_ID` | OIDC app client ID |
| `PINGONE_CLIENT_SECRET` | OIDC app client secret |
| `PINGONE_ADMIN_ENV_ID` | Worker app environment ID |
| `PINGONE_ADMIN_CLIENT_ID` | Worker app client ID |
| `PINGONE_ADMIN_CLIENT_SECRET` | Worker app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
