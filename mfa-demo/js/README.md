# p1-mfa-demo-js

Node.js/Express port of the PingOne registration + email-MFA login demo.

## What it does

- **Sign up**: registers a new user via PingOne's authorization flow (`response_mode=pi.flow`).
- **Email MFA on login**: after username/password succeeds, triggers an email OTP, collects the 6-digit code, and returns an OIDC access token on success.

## PingOne configuration

You need **two** applications in your PingOne tenant:

### 1. End-user OIDC web app

- **Type**: OIDC Web App
- **Grant types**: Authorization Code
- **Response types**: Code
- **Redirect URIs**: `http://localhost:3000/callback`
- **Token endpoint auth method**: Client Secret Basic

### 2. Admin worker app

- **Type**: Worker
- **Assigned role**: **Identity Data Admin** (or broader) on the environment hosting the OIDC app

The worker app is required because PingOne's `/flows/{id}` endpoints require a bearer token —
session cookies alone are insufficient for the MFA challenge step.

### Environment settings

- Enable the **Email** MFA device type and include it in the sign-on policy associated with the OIDC app.
- Ensure at least one population exists for new users to register into.

## Run

```bash
cp .env.example .env
# fill in both sets of credentials
npm install
npm start
```

Open http://localhost:3000. Requires Node 18+ (uses the global `fetch` and `getSetCookie`).

## Environment variables

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID of the end-user OIDC app |
| `PINGONE_CLIENT_ID` | OIDC app client ID |
| `PINGONE_CLIENT_SECRET` | OIDC app client secret |
| `PINGONE_ADMIN_ENV_ID` | Worker app environment ID |
| `PINGONE_ADMIN_CLIENT_ID` | Worker app client ID |
| `PINGONE_ADMIN_CLIENT_SECRET` | Worker app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
