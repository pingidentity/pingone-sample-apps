# p1-user-registration-go

Go/`net/http` sample app that demonstrates self-service user registration + login against PingOne
using the authorization flow (`response_mode=pi.flow`).

## What it does

- **Sign up**: collects username/email/password, creates the user in PingOne, prompts for the email
  verification code, and completes registration once the code is confirmed.
- **Log in**: username/password authentication that exchanges the resulting authorization code
  for an OIDC access token and displays it on a simple dashboard page.

## PingOne configuration

Only **one** application is required. No admin worker app is needed — the registration flow does
not require a bearer token.

### OIDC web app

- **Type**: OIDC Web App
- **Grant types**: Authorization Code
- **Response types**: Code
- **Redirect URIs**: `http://localhost:3000/callback`
- **Token endpoint auth method**: Client Secret Basic

### Environment settings

- The sign-on policy associated with the OIDC app must permit user self-registration
  (and include an email verification step).
- At least one population must exist so new users can be registered into it.

## Run

```bash
cp .env.example .env
# fill in your PingOne credentials
go run main.go
```

Open http://localhost:3000.

## Environment variables

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID of the OIDC app |
| `PINGONE_CLIENT_ID` | OIDC app client ID |
| `PINGONE_CLIENT_SECRET` | OIDC app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
