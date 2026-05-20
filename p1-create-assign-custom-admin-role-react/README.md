# PingOne Custom Admin Role Workflow — React + Node/Express

A React + Node/Express port of the Go app in `p1-create-assign-custom-admin-role-go`. The backend runs the full PingOne workflow and streams results to a React frontend as structured JSON.

## What It Does

1. Obtains an admin token via `client_credentials`
2. Lists platform roles (`GET /roles`) to find **Application Owner** and **Organization Admin** IDs
3. Selects two permissions: `applications:read:application` + `applications:update:application`
4. Creates a custom admin role in the target environment scoped with `canBeAssignedBy: [{ id: orgAdminID }]`
5. Creates a population in the target environment
6. Creates a group in the target environment
7. Assigns the custom role to the group, scoped to the population
8. Creates a user placed into that population
9. Adds the user to the group
10. Verifies the user's role assignments include the newly created custom role (inherited via group membership)

## Prerequisites

- Node 18 or later (uses global `fetch`)
- A PingOne **admin environment** with a Worker App holding the **Organization Admin** role
- A separate **target environment** where resources will be created

## Environment Variables

Copy `server/.env.example` to `server/.env` and fill in the values:

| Variable | Description |
|---|---|
| `PINGONE_ADMIN_ENV_ID` | Environment ID of the admin/worker environment |
| `PINGONE_ADMIN_CLIENT_ID` | Client ID of the Worker Application |
| `PINGONE_ADMIN_CLIENT_SECRET` | Client Secret of the Worker Application |
| `PINGONE_TARGET_ENV_ID` | Environment ID where the workflow creates resources |
| `PINGONE_AUTH_PATH` | Auth base URL, e.g. `https://auth.pingone.com` (change to `.ca`, `.eu`, or `.asia` as needed) |
| `PINGONE_API_PATH` | Management API base URL, e.g. `https://api.pingone.com/v1` |

## Running Locally

### 1. Start the backend

```bash
cd server
cp .env.example .env   # fill in your values
npm install
npm start
```

The Express server listens on **http://localhost:3000**.

### 2. Start the frontend

```bash
cd client
npm install
npm run dev
```

Vite serves the React app at **http://localhost:5173**. All `/api` requests are proxied to `:3000`.

Open http://localhost:5173, click **Run Workflow**, and watch the results appear step by step.

## PingOne Configuration Notes

### Organization Admin is required

The Worker Application used here must hold the **Organization Admin** role at the admin environment level. This role is what authorises the app to create custom admin roles in target environments and assign them.

### `canBeAssignedBy` explained

When creating a custom admin role via `POST /environments/{id}/roles`, the `canBeAssignedBy` field lists the platform role IDs whose holders are permitted to assign your custom role to principals. By including the **Organization Admin** role ID here, any identity (such as your Worker App) that holds Organization Admin is authorised to delegate your custom role. Without this field, or if the wrong role is listed, attempts to assign the custom role will be rejected with a 403.

### Propagation delay on role verification

Step 10 (verify user role assignments) reads the role assignments directly from the user object. Because PingOne role assignments via group membership may take a few seconds to propagate, this step can occasionally show the custom role as absent immediately after the group membership is created. If the workflow reports a failure on the final verification step, wait a moment and re-run.
