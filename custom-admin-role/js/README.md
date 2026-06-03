# p1-create-assign-custom-admin-role-js

Node.js/Express port of the PingOne custom admin role workflow. Runs a management-API sequence end-to-end via a browser UI on port 3000.

## What it does

1. Creates a custom admin role (trimmed-down Application Owner — read/update apps, no create).
2. Creates a population and a group in the target environment.
3. Assigns the custom role to the group, scoped to the population.
4. Registers a new user into the population and adds them to the group.
5. Verifies via `GET /users/{userID}/roleAssignments` that the user inherited the custom role.

Each step is shown as a card on the results page with the HTTP method + URL, a status badge, and a collapsible response body.

## Run

```bash
cp .env.example .env
# fill in your credentials and environment IDs
npm install
npm start
```

Open http://localhost:3000 and click **Run Workflow**.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `PINGONE_ADMIN_ENV_ID` | Environment ID where the worker app lives |
| `PINGONE_ADMIN_CLIENT_ID` | Worker app client ID |
| `PINGONE_ADMIN_CLIENT_SECRET` | Worker app client secret |
| `PINGONE_TARGET_ENV_ID` | Environment the workflow operates in (can equal the admin env) |
| `PINGONE_AUTH_PATH` | Regional auth host (default `https://auth.pingone.com`) |
| `PINGONE_API_PATH` | Regional management API host (default `https://api.pingone.com/v1`) |

Regional variants: replace `.com` with `.ca`, `.eu`, or `.asia` as appropriate.

## PingOne configuration

### Admin worker app

- **Type**: Worker
- **Assigned role**: **Organization Admin** at the organization level

Organization Admin is required for two reasons:

1. It has the broad permissions needed to create roles, groups, populations, and users across environments.
2. Custom admin roles have a `canBeAssignedBy` property that gates which roles can delegate them. This app sets `canBeAssignedBy` to the Organization Admin role ID when creating the custom role. Without it, PingOne rejects the group role-assignment with `"Must have role at the same or broader scope"` — even when the worker app is Organization Admin.

Lesser roles (Environment Admin, Identity Data Admin) are not sufficient.

### Target environment

Any environment in your tenant. Can be the same as the admin worker's environment or a separate test environment.
