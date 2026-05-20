# p1-mfa-demo-go

Go/`net/http` implementation of a PingOne registration + email-MFA login flow.

## What it does

- **Sign up**: collects username/email/password, registers the user via the PingOne authorization flow (`response_mode=pi.flow`).
- **Email MFA on login**: after username/password succeeds, triggers an email OTP challenge, prompts for the 6-digit code, and completes the login to return an OIDC access token.

## PingOne configuration

You need **two** applications in your PingOne tenant:

### 1. End-user OIDC web app (the one users log in to)

- **Type**: OIDC Web App
- **Grant types**: Authorization Code
- **Response types**: Code
- **Redirect URIs**: `http://localhost:3000/callback`
- **Token endpoint auth method**: Client Secret Basic
- **PKCE enforcement**: Optional (not required — the sample uses a confidential client)
- **Assigned population(s)**: at least one, so new users can be registered into it

### 2. Admin worker app (used to issue management-API bearer tokens on behalf of the flow)

- **Type**: Worker
- **Assigned role**: **Identity Data Admin** (or broader) on the environment that hosts app #1

The MFA flow requires a bearer token from the worker app because PingOne's `/flows/{id}` endpoints
are authenticated — cookies alone are insufficient.

### Environment settings

- The end-user environment must have an **Email** MFA device configured and enabled for the sign-on policy the OIDC app uses.
- Users must have a verified email address (automatically set during registration).

## Run

```bash
cp .env.example .env
# fill in both sets of credentials
go run main.go
```

Open http://localhost:3000.

## Environment variables

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID of the end-user OIDC app |
| `PINGONE_CLIENT_ID` | Client ID of the end-user OIDC app |
| `PINGONE_CLIENT_SECRET` | Client secret of the end-user OIDC app |
| `PINGONE_ADMIN_ENV_ID` | Environment ID where the worker app lives |
| `PINGONE_ADMIN_CLIENT_ID` | Worker app client ID |
| `PINGONE_ADMIN_CLIENT_SECRET` | Worker app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host, e.g. `https://auth.pingone.com` (NA), `.ca`, `.eu`, `.asia` |
