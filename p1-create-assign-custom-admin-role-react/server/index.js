/**
 * PingOne Custom Admin Role Workflow — React backend (Express)
 *
 * This Express server implements the PingOne custom admin role workflow and
 * exposes it as a single JSON endpoint (POST /api/run) consumed by the React
 * frontend. All PingOne API calls happen here on the server; the client never
 * holds credentials or tokens.
 *
 * Workflow overview:
 *  1. Obtain an admin bearer token via client_credentials (Organization Admin
 *     worker app). All management API calls require this token.
 *  2. GET /roles — list platform (built-in) roles. Extracts IDs for
 *     "Application Owner" and "Organization Admin".
 *  3. Select permission IDs using the service:action:resource format (e.g.
 *     "applications:read:application"). We take read + update only.
 *  4. POST /environments/{envID}/roles — create the custom admin role.
 *     canBeAssignedBy must reference at least one platform role ID, otherwise
 *     the role is unassignable even by an Organization Admin.
 *  5. Create a population (scope boundary) and a group (role vehicle).
 *  6. POST /groups/{groupID}/roleAssignments — assign the role to the group
 *     scoped to the population (scope.type = "POPULATION").
 *  7. Create a user in the population and add them to the group.
 *  8. GET /users/{userID}/roleAssignments — verify the custom role ID appears
 *     in the user's effective assignments.
 *
 * See server/.env.example for required environment variables.
 */
require('dotenv').config();
const express = require('express');

// adminEnvID — environment containing the worker app (often "Administrators").
const adminEnvID        = process.env.PINGONE_ADMIN_ENV_ID;
// adminClientID / adminClientSecret — worker app credentials used with the
// client_credentials grant to obtain a management API bearer token.
const adminClientID     = process.env.PINGONE_ADMIN_CLIENT_ID;
const adminClientSecret = process.env.PINGONE_ADMIN_CLIENT_SECRET;
// targetEnvID — where the custom role, population, group, and user are created.
const targetEnvID       = process.env.PINGONE_TARGET_ENV_ID;
// authPath / apiPath — regional base URLs (strip trailing slash for safe concatenation).
const authPath          = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');
const apiPath           = (process.env.PINGONE_API_PATH  || '').replace(/\/$/, '');

if (!adminEnvID || !adminClientID || !adminClientSecret || !targetEnvID || !authPath || !apiPath) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// PingOne API helpers
// ---------------------------------------------------------------------------

/**
 * Obtain a short-lived bearer token via the OAuth 2.0 client_credentials grant.
 *
 * client_credentials is the correct grant for server-to-server calls where no
 * end-user is involved. The resulting token inherits the platform roles assigned
 * to the worker app (Organization Admin in this case).
 *
 * Authentication uses HTTP Basic: credentials are base64-encoded as
 * "clientID:clientSecret" in the Authorization header (CLIENT_SECRET_BASIC).
 */
async function getAdminToken() {
  const body = new URLSearchParams({ grant_type: 'client_credentials' });
  const credentials = Buffer.from(`${adminClientID}:${adminClientSecret}`).toString('base64');
  const resp = await fetch(`${authPath}/${adminEnvID}/as/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
    },
    body,
  });
  const json = await resp.json();
  if (!json.access_token) throw new Error(`No access_token: ${JSON.stringify(json)}`);
  return json.access_token;
}

/**
 * Issue a JSON request to the PingOne management API.
 * Uses Node 18+ global fetch — no extra dependencies needed.
 *
 * Returns { fullURL, status, raw (string), parsed (object|null) }.
 *   fullURL — complete request URL for display in step cards.
 *   status  — HTTP status code.
 *   raw     — raw response body string; always populated.
 *   parsed  — JSON.parse(raw) on success, or null if body is not JSON.
 */
async function apiCall(method, path, token, payload = null) {
  const fullURL = apiPath + path;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
  };
  let body;
  if (payload !== null) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(payload);
  }
  const resp = await fetch(fullURL, { method, headers, body });
  const raw = await resp.text();
  let parsed = null;
  try { parsed = JSON.parse(raw); } catch {}
  return { fullURL, status: resp.status, raw, parsed };
}

/**
 * Return indented JSON for display in step cards.
 * Falls back to the raw string if the body is not valid JSON.
 */
function pretty(raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

/**
 * Search _embedded.roles for a case-insensitive name match.
 * Returns { id, name } or { id: '', name: '' } if not found.
 *
 * PingOne wraps list responses in a HAL _embedded envelope. For most tenants
 * the default page size covers all platform roles in one request so pagination
 * is not needed.
 */
function findRoleID(parsed, name) {
  const roles = parsed?._embedded?.roles ?? [];
  for (const role of roles) {
    if (typeof role.name === 'string' && role.name.toLowerCase() === name.toLowerCase()) {
      return { id: role.id ?? '', name: role.name };
    }
  }
  return { id: '', name: '' };
}

/**
 * Return true if roleID appears anywhere in the raw response string.
 * A plain string-contains check is sufficient because the roleAssignments
 * response embeds the role object in every assignment entry.
 */
function responseMentionsRole(raw, roleID) {
  return raw.includes(roleID);
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/**
 * runWorkflow executes the full custom admin role lifecycle and returns
 * { success, steps[] }. Each step object matches the StepResult shape
 * expected by the React frontend. On failure the function returns
 * immediately so the UI highlights exactly which step failed and why.
 */
async function runWorkflow() {
  const steps = [];

  // Step 0: obtain a bearer token via client_credentials.
  // The worker app must hold Organization Admin — without it, later calls to
  // create custom roles or assign them will return 403 Forbidden.
  let token;
  try {
    token = await getAdminToken();
  } catch (err) {
    steps.push({ title: 'Obtain admin access token', ok: false, detail: err.message, body: '', url: '', collapsed: false });
    return { success: false, steps };
  }
  steps.push({ title: 'Obtain admin access token', ok: true, detail: 'client_credentials grant succeeded.', body: '', url: '', collapsed: false });

  // Step 1: GET /roles — fetch all platform (built-in) roles.
  // Platform roles are global and read-only; they cannot be created or deleted.
  // We need two IDs: "Application Owner" (permission template) and
  // "Organization Admin" (for canBeAssignedBy on the custom role).
  // The response is often large so we collapse it in the UI by default.
  const rolesRes = await apiCall('GET', '/roles', token, null);
  const step1 = {
    title: 'List platform roles',
    url: `GET ${rolesRes.fullURL}`,
    body: pretty(rolesRes.raw),
    detail: `HTTP ${rolesRes.status}`,
    collapsed: true, // long response — collapse in UI
    ok: false,
  };
  if (rolesRes.status >= 400) {
    steps.push(step1);
    return { success: false, steps };
  }
  step1.ok = true;
  steps.push(step1);

  const rolesURL = `GET ${rolesRes.fullURL}`;

  // Locate Application Owner by name. Its permission IDs are the template for
  // the custom role's permission set.
  const { id: appOwnerID, name: appOwnerName } = findRoleID(rolesRes.parsed, 'Application Owner');
  if (!appOwnerID) {
    steps.push({ title: 'Find Application Owner platform role', ok: false, detail: "Could not find an 'Application Owner' role in this tenant.", body: '', url: rolesURL, collapsed: false });
    return { success: false, steps };
  }
  steps.push({
    title: 'Find Application Owner platform role',
    ok: true,
    detail: `Found "${appOwnerName}" (id=${appOwnerID}) — we'll borrow its application permissions and drop the create permission.`,
    body: '',
    url: rolesURL,
    collapsed: false,
  });

  // Locate Organization Admin by name. Its ID goes into canBeAssignedBy.
  // Without canBeAssignedBy, the custom role is created but no one can assign
  // it — not even an Organization Admin.
  const { id: orgAdminID } = findRoleID(rolesRes.parsed, 'Organization Admin');
  if (!orgAdminID) {
    steps.push({ title: 'Find Organization Admin platform role', ok: false, detail: "Could not find an 'Organization Admin' role — cannot grant delegation authority.", body: '', url: rolesURL, collapsed: false });
    return { success: false, steps };
  }
  steps.push({
    title: 'Find Organization Admin platform role',
    ok: true,
    detail: `Found (id=${orgAdminID}) — will add to canBeAssignedBy on the custom role.`,
    body: '',
    url: rolesURL,
    collapsed: false,
  });

  // Step 2: select the permissions for the custom role using the
  // service:action:resource format. We pick read + update and omit create.
  const selected = [
    { id: 'applications:read:application' },
    { id: 'applications:update:application' },
  ];
  steps.push({
    title: 'Select read/update application permissions',
    ok: true,
    detail: 'Using applications:read:application + applications:update:application (dropping create).',
    body: JSON.stringify(selected, null, 2),
    url: rolesURL,
    collapsed: false,
  });

  // Step 3: create the custom admin role.
  // POST /environments/{envID}/roles creates a custom role scoped to the
  // target environment. This is distinct from GET /roles (platform roles).
  //
  // canBeAssignedBy references the Organization Admin role ID, granting
  // Organization Admin holders the authority to delegate this custom role.
  const roleSuffix = Date.now();
  const customRolePayload = {
    name: `App Manager (Read/Update) ${roleSuffix}`,
    description: 'Trimmed-down Application Owner: can read and update applications but cannot create them.',
    applicableTo: ['ENVIRONMENT', 'POPULATION'],
    permissions: selected,
    canBeAssignedBy: [{ id: orgAdminID }],
  };
  const roleRes = await apiCall('POST', `/environments/${targetEnvID}/roles`, token, customRolePayload);
  const step3 = {
    title: 'Create custom admin role',
    url: `POST ${roleRes.fullURL}`,
    body: pretty(roleRes.raw),
    detail: `HTTP ${roleRes.status}`,
    collapsed: false,
    ok: false,
  };
  if (roleRes.status >= 400) {
    steps.push(step3);
    return { success: false, steps };
  }
  const customRoleID = roleRes.parsed?.id ?? '';
  if (!customRoleID) {
    step3.detail = 'Role created but response contained no id.';
    steps.push(step3);
    return { success: false, steps };
  }
  step3.ok = true;
  step3.detail = `HTTP ${roleRes.status} — custom role id=${customRoleID}`;
  steps.push(step3);

  // Step 4: create a population to act as the scope boundary.
  // Users inside this population will be managed under the custom role;
  // users in other populations are unaffected when scoped to POPULATION.
  const popPayload = {
    name: `App Management Scope ${roleSuffix}`,
    description: 'Population that scopes the trimmed-down App Manager role.',
  };
  const popRes = await apiCall('POST', `/environments/${targetEnvID}/populations`, token, popPayload);
  const step4 = {
    title: 'Create population',
    url: `POST ${popRes.fullURL}`,
    body: pretty(popRes.raw),
    detail: `HTTP ${popRes.status}`,
    collapsed: false,
    ok: false,
  };
  if (popRes.status >= 400) {
    steps.push(step4);
    return { success: false, steps };
  }
  const populationID = popRes.parsed?.id ?? '';
  if (!populationID) {
    step4.detail = 'Population created but response contained no id.';
    steps.push(step4);
    return { success: false, steps };
  }
  step4.ok = true;
  step4.detail = `HTTP ${popRes.status} — population id=${populationID}`;
  steps.push(step4);

  // Step 5: create a group to be the role-assignment vehicle.
  // Assigning the role to a group means membership changes automatically
  // grant or revoke the role without additional API calls.
  const groupPayload = {
    name: `App Managers ${roleSuffix}`,
    description: 'Group that receives the trimmed-down App Manager role.',
  };
  const groupRes = await apiCall('POST', `/environments/${targetEnvID}/groups`, token, groupPayload);
  const step5 = {
    title: 'Create group',
    url: `POST ${groupRes.fullURL}`,
    body: pretty(groupRes.raw),
    detail: `HTTP ${groupRes.status}`,
    collapsed: false,
    ok: false,
  };
  if (groupRes.status >= 400) {
    steps.push(step5);
    return { success: false, steps };
  }
  const groupID = groupRes.parsed?.id ?? '';
  if (!groupID) {
    step5.detail = 'Group created but response contained no id.';
    steps.push(step5);
    return { success: false, steps };
  }
  step5.ok = true;
  step5.detail = `HTTP ${groupRes.status} — group id=${groupID}`;
  steps.push(step5);

  // Step 6: assign the custom role to the group, scoped to the population.
  // PingOne has no standalone "assign group to population" endpoint; the scope
  // is expressed on the role assignment via scope.type = "POPULATION".
  // Members inherit the custom role within this population boundary only.
  const groupRolePayload = {
    role:  { id: customRoleID },
    scope: { id: populationID, type: 'POPULATION' },
  };
  const grRes = await apiCall('POST', `/environments/${targetEnvID}/groups/${groupID}/roleAssignments`, token, groupRolePayload);
  const step6 = {
    title: 'Assign custom role to group, scoped to population',
    url: `POST ${grRes.fullURL}`,
    body: pretty(grRes.raw),
    detail: `HTTP ${grRes.status}`,
    collapsed: false,
    ok: false,
  };
  if (grRes.status >= 400) {
    steps.push(step6);
    return { success: false, steps };
  }
  step6.ok = true;
  steps.push(step6);

  // Step 7: create a user inside the population.
  // The user must be in the same population as the role-assignment scope so
  // that group membership activates the scoped custom role.
  const userPayload = {
    username:   `app-manager-test-${roleSuffix}`,
    email:      `app-manager-test-${roleSuffix}@example.com`,
    population: { id: populationID }, // reference object, not a plain string
    name: { given: 'App', family: 'Manager' },
  };
  const userRes = await apiCall('POST', `/environments/${targetEnvID}/users`, token, userPayload);
  const step7 = {
    title: 'Register a new user into the population',
    url: `POST ${userRes.fullURL}`,
    body: pretty(userRes.raw),
    detail: `HTTP ${userRes.status}`,
    collapsed: false,
    ok: false,
  };
  if (userRes.status >= 400) {
    steps.push(step7);
    return { success: false, steps };
  }
  const userID = userRes.parsed?.id ?? '';
  if (!userID) {
    step7.detail = 'User created but response contained no id.';
    steps.push(step7);
    return { success: false, steps };
  }
  step7.ok = true;
  step7.detail = `HTTP ${userRes.status} — user id=${userID}`;
  steps.push(step7);

  // Step 8: add the user to the group so the role propagates to them.
  // PingOne returns 201 Created or 204 No Content on success — both are fine.
  const mogRes = await apiCall('POST', `/environments/${targetEnvID}/users/${userID}/memberOfGroups`, token, { id: groupID });
  const step8 = {
    title: 'Add user to the group',
    url: `POST ${mogRes.fullURL}`,
    body: pretty(mogRes.raw),
    detail: 'User added to group; role assignment now applies via group membership.',
    collapsed: false,
    ok: false,
  };
  if (mogRes.status >= 400) {
    step8.detail = `HTTP ${mogRes.status} — failed to add user to group.`;
    steps.push(step8);
    return { success: false, steps };
  }
  step8.ok = true;
  steps.push(step8);

  // Step 9: verify the user's effective role assignments.
  // GET /users/{id}/roleAssignments returns directly-assigned and group-inherited
  // roles. We do a plain string-contains check for the custom role ID. If absent,
  // propagation may still be in progress — the step is marked failed with a note.
  const verifyRes = await apiCall('GET', `/environments/${targetEnvID}/users/${userID}/roleAssignments`, token, null);
  const step9 = {
    title: 'Verify user role assignments',
    url: `GET ${verifyRes.fullURL}`,
    body: pretty(verifyRes.raw),
    detail: `HTTP ${verifyRes.status}`,
    collapsed: false,
    ok: false,
  };
  if (verifyRes.status >= 400) {
    steps.push(step9);
    return { success: false, steps };
  }
  if (!responseMentionsRole(verifyRes.raw, customRoleID)) {
    step9.ok = false;
    step9.detail = `HTTP ${verifyRes.status} — user does not yet appear to have the custom role; check the raw response below. Role assignments via groups may require a brief propagation delay.`;
    steps.push(step9);
    return { success: false, steps };
  }
  step9.ok = true;
  step9.detail = `HTTP ${verifyRes.status} — user's role assignments include the custom role (inherited via group).`;
  steps.push(step9);

  return { success: true, steps };
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

app.post('/api/run', async (req, res) => {
  try {
    const result = await runWorkflow();
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, steps: [{ title: 'Unexpected error', ok: false, detail: err.message, body: '', url: '', collapsed: false }] });
  }
});

app.listen(3000, () => {
  console.log('Custom Admin Role workflow backend on http://localhost:3000');
});
