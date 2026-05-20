# p1-user-registration-python

Python/Flask port of the PingOne self-service user-registration + login demo.

## What it does

- **Sign up**: collects username/email/password, creates the user in PingOne, prompts for the email verification code, and completes registration once confirmed.
- **Log in**: username/password authentication that exchanges the resulting authorization code for an OIDC access token.

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

## Run

```bash
cp .env.example .env
# fill in your PingOne credentials
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://localhost:3000.

## Environment variables

| Var | Purpose |
|-----|---------|
| `PINGONE_ENV_ID` | Environment ID of the OIDC app |
| `PINGONE_CLIENT_ID` | OIDC app client ID |
| `PINGONE_CLIENT_SECRET` | OIDC app client secret |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
