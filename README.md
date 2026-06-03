# PingOne Sample Apps

A collection of working sample apps that demonstrate common PingOne integration patterns. Each workflow is implemented in Go, Node.js, Python, React, and Angular so you can use whichever stack fits your project.

## Layout

```
<workflow>/
├── go/        ← canonical Go implementation
├── js/        ← Node.js / Express
├── python/    ← Python / Flask
├── react/     ← React (Vite) + Node/Express backend
└── angular/   ← Angular 18 + Node/Express backend
```

## Samples

| Workflow | Folder | Description |
|----------|--------|-------------|
| OIDC Authorization Code + PKCE | [oidc-pkce/](oidc-pkce/) | End-user sign-in with PKCE, token exchange, JWT decode and JWKS verify |
| User Registration | [user-registration/](user-registration/) | Self-service registration flow against PingOne |
| MFA Demo | [mfa-demo/](mfa-demo/) | Sign-in with email/SMS/TOTP MFA challenge |
| M2M Client Credentials + Protect | [m2m-credentials/](m2m-credentials/) | Service-to-service OAuth + PingOne Protect risk evaluation |
| DaVinci Sign-On | [davinci-signon/](davinci-signon/) | Drive a DaVinci flow from a sample web app |
| Create & Assign Custom Admin Role | [custom-admin-role/](custom-admin-role/) | Management API: create a custom role and assign it to a group |

## Getting started

Each sample is self-contained. Pick a workflow folder, then a language port, copy `.env.example` to `.env`, fill in your PingOne credentials, and follow the README inside that port.

## PingOne resources

- [PingOne documentation](https://docs.pingidentity.com/pingone)
- [PingOne API reference](https://apidocs.pingidentity.com/pingone/platform/v1/api/)
