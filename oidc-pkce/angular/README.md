# p1-oidc-pkce-angular

Angular UI + Node/Express backend walking through the OIDC Authorization Code + PKCE flow against PingOne, with every artifact rendered on the page.

## Layout

- `server/` — Node/Express backend (port 3000). Handles OAuth flow, serves Angular build.
- `client/` — Angular app. Dev on port 4200, proxies `/api` to :3000.

## PingOne configuration

Only **one** application required. No worker app needed.

### OIDC web app

- **Type**: OIDC Web App
- **Grant types**: Authorization Code, Refresh Token (if you want to exercise the refresh step)
- **Response types**: Code
- **Redirect URIs**: `http://localhost:3000/callback`
- **PKCE Enforcement**: **REQUIRED**
- **Token Endpoint Auth Method**: **Client Secret Basic**

## Run

```bash
cd client && npm install && npm run build
cd ../server
cp .env.example .env   # fill in your PingOne credentials
npm install
npm start              # http://localhost:3000
```

Open http://localhost:3000 and click **Begin Login**.

## Environment variables (server/.env)

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID of the OIDC app |
| `PINGONE_CLIENT_ID` | OIDC app client ID |
| `PINGONE_CLIENT_SECRET` | OIDC app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
| `PINGONE_REDIRECT_URI` | Must be `http://localhost:3000/callback` |
| `PINGONE_SCOPES` | Space-separated, e.g. `openid profile email` |
