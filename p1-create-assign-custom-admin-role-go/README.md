# p1-create-assign-custom-admin-role-go

Go web app that runs a PingOne management-API workflow end-to-end:

1. Create a custom admin role (trimmed-down Application Owner — read/update apps, no create).
2. Create a group and a population.
3. Assign the custom role to the group, scoped to the population.
4. Register a new user into the population and add them to the group.
5. Verify via `GET /users/{userID}/roleAssignments` that the user inherited the custom role.

## PingOne configuration

You need **one** admin worker app, plus an environment you want the workflow to operate in.

### Admin worker app

- **Type**: Worker
- **Assigned role**: **Organization Admin** (at the organization level)

Organization Admin is required for two reasons:

1. It has the broad permissions needed to create roles, groups, populations, and users across environments.
2. Custom admin roles have a `canBeAssignedBy` property that gates which roles can delegate them. The app adds Organization Admin to `canBeAssignedBy` when creating the custom role, so only holders of Organization Admin (i.e., this worker app) can assign it to the group. Without that property, PingOne rejects the group role-assignment call with `"Must have role at the same or broader scope"` — even when the worker app is Organization Admin.

Lesser roles (Environment Admin, Identity Data Admin) are **not** sufficient.

### Target environment

- Any environment in your tenant. Can be the same as the admin worker's environment, or a separate test environment.

## Run

```bash
cp .env.example .env
# fill in admin worker app credentials + target env ID
go run main.go
```

Open http://localhost:3000 and click **Run Workflow**. Each step logs to the page as it executes.

## Environment variables

| Var | Purpose |
|-----|---------|
| `PINGONE_ADMIN_ENV_ID` | Environment ID where the worker app lives |
| `PINGONE_ADMIN_CLIENT_ID` | Worker app client ID |
| `PINGONE_ADMIN_CLIENT_SECRET` | Worker app client secret |
| `PINGONE_TARGET_ENV_ID` | Environment the workflow operates in (can equal the admin env) |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
| `PINGONE_API_PATH` | Regional API host (`https://api.pingone.com/v1` / `.ca` / `.eu` / `.asia`) |

## Workflow steps

1. **Obtain admin token** — client_credentials grant against the worker app.
2. **List platform roles** — fetches `/roles` to discover role IDs.
3. **Find Application Owner** — used for display/comparison purposes.
4. **Find Organization Admin** — its ID is injected into `canBeAssignedBy`.
5. **Select permissions** — hardcoded `applications:read:application` + `applications:update:application`.
6. **Create custom admin role** — `POST /environments/{env}/roles` with `applicableTo: [ENVIRONMENT, POPULATION]` and `canBeAssignedBy: [{id: <Organization Admin role id>}]`.
7. **Create population**.
8. **Create group**.
9. **Assign custom role to group, scoped to population** — the role assignment carries `scope.type=POPULATION`, so group members in that population inherit the role.
10. **Register a new user into the population.**
11. **Add user to the group.**
12. **Verify** — `GET /users/{userID}/roleAssignments` confirms the user received the custom role via group membership.
