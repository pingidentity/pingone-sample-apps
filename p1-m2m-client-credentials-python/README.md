# PingOne M2M Client Credentials + PingOne Protect — Python / Flask

Demonstrates the OAuth 2.0 **client_credentials** grant for machine-to-machine (M2M) workloads, followed by two **PingOne Protect** risk evaluations that gate a downstream management API call.

## What it does

1. **Build token request** — constructs the `client_credentials` form body and Basic auth header (no HTTP call yet).
2. **Token endpoint response** — POSTs to `{authPath}/{envID}/as/token`; receives an access token.
3. **Decode access token** — base64url-decodes the JWT header and payload (no signature verify yet).
4. **Fetch JWKS** — GETs `{authPath}/{envID}/as/jwks` to retrieve the signing keys.
5. **Verify access token signature** — RS256 verification using the matching JWK (`kid`).
6. **Validate access token claims** — checks `iss`, `client_id`, `exp` > now, `iat` not in future.

Then two side-by-side risk paths:

**User A — trusted (real IP, type=EXTERNAL)**

7a. **PingOne Protect risk evaluation** — POSTs real client IP with `type=EXTERNAL`; expected LOW/MEDIUM.
8a. **Call PingOne Management API** — `GET /users`; proceeds because risk is not HIGH.

**User B — suspicious (Tor IP, type=ANONYMOUS)**

7b. **PingOne Protect risk evaluation** — POSTs Tor exit node IP (`185.220.101.1`) with `type=ANONYMOUS`; triggers Anonymous Network Detection, score 80 (above HIGH threshold 75).
8b. **Call PingOne Management API** — blocked because risk level is HIGH.

## PingOne configuration

- **Worker application** — grant type `Client Credentials`, Token Endpoint Auth Method `Client Secret Basic`.
- **Roles required** — Identity Data Admin (read users) and PingOne Protect (risk evaluation), both assigned at environment level.
- **Risk policy set** — must have Anonymous Network Detection enabled with a HIGH threshold below 80. Its ID goes in `PINGONE_RISK_POLICY_SET_ID`.

## Environment variables

| Variable | Purpose |
|---|---|
| `PINGONE_ENV_ID` | PingOne environment ID |
| `PINGONE_CLIENT_ID` | Worker app client ID |
| `PINGONE_CLIENT_SECRET` | Worker app client secret |
| `PINGONE_AUTH_PATH` | Auth base URL (e.g. `https://auth.pingone.com`) |
| `PINGONE_API_PATH` | API base URL (e.g. `https://api.pingone.com`) |
| `PINGONE_RISK_POLICY_SET_ID` | Protect risk policy set ID |

## Run instructions

```bash
cp .env.example .env
# fill in .env with your PingOne values

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open [http://localhost:3000](http://localhost:3000) and click **Run Flow**.
