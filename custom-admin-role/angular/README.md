# PingOne Custom Admin Role Workflow — Angular + Node/Express

Demonstrates the full custom-admin-role lifecycle in PingOne:

1. Obtain an admin access token (client_credentials)
2. List platform roles to find **Application Owner** and **Organization Admin**
3. Select a trimmed permission set: `applications:read:application` + `applications:update:application`
4. Create a custom admin role scoped to `ENVIRONMENT` / `POPULATION`, with `canBeAssignedBy` set to the Organization Admin role
5. Create a population in the target environment
6. Create a group in the target environment
7. Assign the custom role to that group, scoped to the population
8. Create a user inside the population
9. Add the user to the group
10. Verify that the user now inherits the custom role via group membership

---

## Project layout

```
p1-create-assign-custom-admin-role-angular/
├── server/          Node/Express backend (port 3000)
│   ├── index.js
│   ├── package.json
│   └── .env.example
└── client/          Angular 18 frontend (port 4200, dev server)
    ├── angular.json
    ├── package.json
    ├── proxy.conf.json
    ├── tsconfig.json
    ├── tsconfig.app.json
    └── src/
        ├── index.html
        ├── main.ts
        └── app/
            └── app.component.ts
```

---

## Environment variables

Copy `server/.env.example` to `server/.env` and fill in the values.

| Variable | Description |
|---|---|
| `PINGONE_ADMIN_ENV_ID` | Environment ID that owns the worker app (admin env) |
| `PINGONE_ADMIN_CLIENT_ID` | Client ID of the worker app (needs **Organization Admin** role) |
| `PINGONE_ADMIN_CLIENT_SECRET` | Client secret of the worker app |
| `PINGONE_TARGET_ENV_ID` | Environment ID where resources (role, population, group, user) will be created |
| `PINGONE_AUTH_PATH` | PingOne auth base URL, e.g. `https://auth.pingone.com` |
| `PINGONE_API_PATH` | PingOne API base URL, e.g. `https://api.pingone.com/v1` |

---

## PingOne configuration

- The worker app identified by `PINGONE_ADMIN_CLIENT_ID` / `PINGONE_ADMIN_CLIENT_SECRET` must be granted the **Organization Admin** role in the admin environment so it can create custom roles and delegate them.
- `PINGONE_TARGET_ENV_ID` is the sandbox environment where the demo objects are created. It can be the same as the admin env or a separate one.

---

## Running locally

### 1. Start the backend

```bash
cd server
npm install
cp .env.example .env   # then fill in your values
npm start
# → Custom Admin Role workflow backend on http://localhost:3000
```

### 2. Start the Angular dev server

In a second terminal:

```bash
cd client
npm install
npm start
# → Angular live development server listening on http://localhost:4200
```

Open **http://localhost:4200** in a browser, then click **Run Workflow**.

The Angular dev server proxies `/api/*` requests to `http://localhost:3000` via `proxy.conf.json`.

---

## Production build

```bash
cd client
npm run build          # outputs to client/dist/p1-create-assign-custom-admin-role-angular/browser/
```

The Express server in `server/index.js` serves the built Angular app from that path, so you can then run `npm start` in `server/` and browse directly to **http://localhost:3000**.

---

## API

`POST /api/run` — runs the full workflow synchronously and returns:

```json
{
  "success": true,
  "steps": [
    {
      "title": "Obtain admin access token",
      "ok": true,
      "detail": "client_credentials grant succeeded.",
      "body": "",
      "url": "",
      "collapsed": false
    }
  ]
}
```

If any step fails the workflow stops immediately, `success` is `false`, and the last entry in `steps` is the failing step.
