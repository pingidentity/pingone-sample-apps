# p1-create-assign-custom-admin-role-python

Python/Flask web app that runs a PingOne management-API workflow end-to-end:

1. Create a custom admin role (trimmed-down Application Owner — read/update apps, no create).
2. Create a group and a population.
3. Assign the custom role to the group, scoped to the population.
4. Register a new user into the population and add them to the group.
5. Verify via `GET /users/{userID}/roleAssignments` that the user inherited the custom role.

## How to run

```bash
cp .env.example .env
# fill in admin worker app credentials + target env ID

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://localhost:3000 and click **Run Workflow**.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `PINGONE_ADMIN_ENV_ID` | Environment ID where the worker app lives |
| `PINGONE_ADMIN_CLIENT_ID` | Worker app client ID |
| `PINGONE_ADMIN_CLIENT_SECRET` | Worker app client secret |
| `PINGONE_TARGET_ENV_ID` | Environment the workflow operates in (can equal the admin env) |
| `PINGONE_AUTH_PATH` | Regional auth host (`https://auth.pingone.com` / `.ca` / `.eu` / `.asia`) |
| `PINGONE_API_PATH` | Regional API host (`https://api.pingone.com/v1` / `.ca` / `.eu` / `.asia`) |

## PingOne configuration

### Admin worker app

- **Type**: Worker
- **Assigned role**: **Organization Admin** (at the organization level)

Organization Admin is required for two reasons:

1. It has the broad permissions needed to create roles, groups, populations, and users across environments.
2. Custom admin roles have a `canBeAssignedBy` property that gates which roles can delegate them. This app sets `canBeAssignedBy` to the Organization Admin role ID when creating the custom role, so only holders of Organization Admin (i.e., this worker app) can assign it to a group. Without that property, PingOne rejects the group role-assignment call with `"Must have role at the same or broader scope"` — even when the worker app is Organization Admin.

Lesser roles (Environment Admin, Identity Data Admin) are **not** sufficient.

### Target environment

Any environment in your tenant. Can be the same as the admin worker's environment, or a separate test environment.
