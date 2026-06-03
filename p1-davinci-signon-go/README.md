# p1-davinci-signon-go

A Go web app demonstrating how to invoke a **DaVinci sign-on flow** from a backend, fronted by the standard **PingOne authorize endpoint**. Implements the [DaVinci Sign-On Flow with PingOne Auth](https://developer.pingidentity.com/pingone-api/workflow-library/pingone-davinci/davinci-sign-on-flow-with-pingone-auth.html) use case.

## What it does

1. **Start the flow** — calls `GET /{envID}/as/authorize` with `response_mode=pi.flow`. PingOne hands the request off to the DaVinci flow policy assigned to the OIDC app and returns a JSON envelope containing the first capability the client must drive (`interactionId`, `interactionToken`, `connectionId`, `capabilityName`, flow `id`).
2. **Submit credentials** — POSTs the user's username/password to the returned capability URL (`/{envID}/davinci/connections/{connectionId}/capabilities/{capabilityName}`) with `actionKey: "SIGNON"`. The flow validates them and returns an authorization code in `authorizeResponse.code`.
3. **Exchange code for tokens** — POSTs to `/{envID}/as/token` with `grant_type=authorization_code` and HTTP Basic auth (CLIENT_SECRET_BASIC), printing the resulting access token.

## PingOne configuration

This sample assumes the use-case-library setup is already in place. Briefly:

- **OIDC web application** (`type: WEB_APP`, `protocol: OPENID_CONNECT`)
  - Grant type: `AUTHORIZATION_CODE`
  - Response type: `CODE`
  - Token endpoint auth method: `CLIENT_SECRET_BASIC`
  - Redirect URI must match `PINGONE_REDIRECT_URI` (the sample uses `http://localhost:3000/callback`)
- **Flow policy assignment** — read your environment's flow policies (`GET /v1/environments/{envID}/flowPolicies`), pick the sign-on policy, then assign it to the web app via `POST /v1/environments/{envID}/applications/{appID}/flowPolicyAssignments` with `priority: 1`.
- **Test user** must exist in a population the flow policy can authenticate.

The DaVinci flow itself must be configured for the **API integration method** (returns JSON capabilities).

## Run

```
cp .env.example .env
# fill in PINGONE_ENV_ID, PINGONE_CLIENT_ID, PINGONE_CLIENT_SECRET
go run .
```

Open [http://localhost:3000](http://localhost:3000) and sign in with your test user.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `PINGONE_AUTH_PATH` | Regional auth endpoint (`https://auth.pingone.com`, `.ca`, `.eu`, `.asia`) |
| `PINGONE_ENV_ID` | Environment ID containing the OIDC app and DaVinci flow policy |
| `PINGONE_CLIENT_ID` | Web app client ID — the one with the flow policy assignment |
| `PINGONE_CLIENT_SECRET` | Web app client secret (for the Basic-auth token exchange) |
| `PINGONE_REDIRECT_URI` | Redirect URI registered on the web app; sent in both the authorize and token requests |
