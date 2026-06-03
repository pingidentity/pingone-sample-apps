/**
 * PingOne Custom Admin Role Workflow — Node.js / Express
 *
 * PingOne ships with a fixed set of platform (built-in) roles such as
 * "Organization Admin" and "Application Owner". These cannot be modified.
 * Custom admin roles let you create narrower, purpose-built roles —
 * for example, an application manager that can read and update apps but
 * cannot create new ones.
 *
 * This server drives the full workflow end-to-end:
 *
 *  1. Obtain an admin bearer token (client_credentials grant) from the
 *     PingOne token endpoint using a worker app that holds Organization Admin.
 *     All management API calls require this token.
 *
 *  2. GET /roles — list all platform roles. We need the numeric IDs of
 *     "Application Owner" (to understand available permission IDs) and
 *     "Organization Admin" (to populate canBeAssignedBy).
 *
 *  3. Select a subset of permissions using the service:action:resource
 *     format (e.g. "applications:read:application"). We take read + update
 *     and drop create, so holders of the custom role cannot add new apps.
 *
 *  4. POST /environments/{envID}/roles — create the custom admin role.
 *     The canBeAssignedBy field must reference at least one platform role
 *     whose holders are allowed to delegate the custom role. If omitted,
 *     even an Organization Admin cannot assign the role to anyone.
 *
 *  5. Create a population and a group. The population provides the scope
 *     boundary; the group is the role-assignment vehicle so that adding a
 *     user to the group automatically grants them the role.
 *
 *  6. POST /groups/{groupID}/roleAssignments — assign the custom role to
 *     the group, scoped to the population (scope.type = "POPULATION").
 *     PingOne has no "assign group to population" API; scoping is expressed
 *     on the role assignment itself.
 *
 *  7. Create a user inside the population and add them to the group.
 *     The user inherits the custom role through group membership.
 *
 *  8. GET /users/{userID}/roleAssignments — verify the custom role ID
 *     appears in the user's effective role assignments.
 *
 * Prerequisites: a worker app (client_credentials) with Organization Admin.
 * Set PINGONE_ADMIN_ENV_ID, PINGONE_ADMIN_CLIENT_ID, PINGONE_ADMIN_CLIENT_SECRET,
 * PINGONE_TARGET_ENV_ID, PINGONE_AUTH_PATH, and PINGONE_API_PATH in .env.
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');

const logoPNG = fs.readFileSync(path.join(__dirname, '..', 'assets', 'logo.png')).toString('base64');
const logoSrc = `data:image/png;base64,${logoPNG}`;

// adminEnvID — the environment that contains the worker app used to get the token.
// This is typically your "Administrators" environment.
const adminEnvID        = process.env.PINGONE_ADMIN_ENV_ID;
// adminClientID / adminClientSecret — credentials of the worker app that holds
// Organization Admin. Used with the client_credentials grant (no user login).
const adminClientID     = process.env.PINGONE_ADMIN_CLIENT_ID;
const adminClientSecret = process.env.PINGONE_ADMIN_CLIENT_SECRET;
// targetEnvID — where the custom role, population, group, and test user are created.
// May be the same as adminEnvID or a separate dev/staging environment.
const targetEnvID       = process.env.PINGONE_TARGET_ENV_ID;
// authPath / apiPath — regional base URLs. North America: auth.pingone.com /
// api.pingone.com/v1; Europe: auth.pingone.eu / api.pingone.eu/v1, etc.
const authPath          = (process.env.PINGONE_AUTH_PATH || 'https://auth.pingone.com').replace(/\/$/, '');
const apiPath           = (process.env.PINGONE_API_PATH  || 'https://api.pingone.com/v1').replace(/\/$/, '');

if (!adminEnvID || !adminClientID || !adminClientSecret || !targetEnvID || !authPath || !apiPath) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// --- HTML Templates ---

const indexHTML = `
<!DOCTYPE html>
<html>
<head>
<title>PingOne Custom Admin Role Workflow</title>
<style>
  body{font-family:sans-serif; margin:0; background:#f5f5f5;}
  button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;}
  button:hover{background:#c40034;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word;}
  .step{margin-top:18px;}
  .step h3{margin:0 0 6px 0;}
  .ok{color:#0a7a0a;}
  .err{color:#b00020;}
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Custom Admin Role Workflow</h2>
  <p>Creates a trimmed-down application admin role, assigns it to a group scoped to a population, registers a user into that population, and verifies the inherited role assignment.</p>
  <form action="/run" method="POST"><button type="submit">Run Workflow</button></form>
</div>
</body>
</html>`;

function resultsHTML(data) {
  const bannerClass = data.success ? 'ok' : 'err';
  const bannerMsg   = data.success ? 'All steps completed successfully.' : 'Workflow halted on error.';

  const stepsHTML = data.steps.map(step => {
    const statusClass = step.ok ? 'ok' : 'err';
    const statusText  = step.ok ? '(ok)' : '(failed)';
    const urlDiv      = step.url    ? `<div class="url">${escapeHTML(step.url)}</div>` : '';
    const detailPara  = step.detail ? `<p>${escapeHTML(step.detail)}</p>` : '';
    let bodyBlock = '';
    if (step.body) {
      const openAttr = step.collapsed ? '' : ' open';
      bodyBlock = `<details${openAttr}><summary>Response</summary><pre>${escapeHTML(step.body)}</pre></details>`;
    }
    return `
    <div class="step">
      <h3 class="${statusClass}">${escapeHTML(step.title)} ${statusText}</h3>
      ${urlDiv}
      ${detailPara}
      ${bodyBlock}
    </div>`;
  }).join('');

  return `
<!DOCTYPE html>
<html>
<head>
<title>Workflow Result</title>
<style>
  body{font-family:sans-serif; margin:0; background:#f5f5f5;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word; margin:0;}
  .step{margin-top:18px;}
  .step h3{margin:0 0 6px 0;}
  .ok{color:#0a7a0a;}
  .err{color:#b00020;}
  .banner{padding:10px; margin-top:10px; border-radius:4px;}
  .banner.ok{background:#e6f7e6;}
  .banner.err{background:#fde8ea;}
  .url{font-family:monospace; font-size:13px; color:#555; background:#f0f0f0; padding:4px 8px; border-radius:3px; display:inline-block; margin-bottom:6px; word-break:break-all;}
  details{margin-top:6px;}
  summary{cursor:pointer; font-size:13px; color:#444; user-select:none; padding:2px 0;}
  details pre{margin-top:4px;}
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Workflow Result</h2>
  <div class="banner ${bannerClass}">${bannerMsg}</div>
  ${stepsHTML}
  <p><a href="/">Back</a></p>
</div>
</body>
</html>`;
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// --- PingOne API helpers ---

/**
 * Obtain a short-lived bearer token using the OAuth 2.0 client_credentials
 * grant. This is the correct grant for server-to-server admin operations where
 * no end-user is present. The resulting token inherits the platform roles
 * (e.g. Organization Admin) assigned to the worker app in PingOne.
 *
 * Authentication is HTTP Basic: credentials are base64-encoded as
 * "clientID:clientSecret" in the Authorization header. This corresponds to the
 * CLIENT_SECRET_BASIC token endpoint authentication method in PingOne.
 */
async function getAdminToken() {
  const body        = new URLSearchParams({ grant_type: 'client_credentials' });
  const credentials = Buffer.from(`${adminClientID}:${adminClientSecret}`).toString('base64');

  const resp = await fetch(`${authPath}/${adminEnvID}/as/token`, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
    },
    body,
  });
  const json = await resp.json();
  if (!json.access_token) {
    throw new Error(`No access_token in response: ${JSON.stringify(json)}`);
  }
  return json.access_token;
}

/**
 * Issue a JSON request to the PingOne management API authenticated with the
 * admin bearer token. Uses Node 18+ global fetch — no extra dependencies needed.
 *
 * Returns { fullURL, status, rawText, parsed }.
 *   - fullURL:  the complete request URL, used in step cards for display.
 *   - status:   HTTP status code.
 *   - rawText:  raw response body string — always populated.
 *   - parsed:   JSON.parse(rawText) on success, or null if the body is not JSON.
 *               Always check status before trusting parsed content.
 */
async function apiCall(method, path, token, payload = null) {
  const fullURL = apiPath + path;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept':        'application/json',
  };
  const init = { method, headers };
  if (payload !== null) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(payload);
  }

  const resp    = await fetch(fullURL, init);
  const rawText = await resp.text();
  let parsed = null;
  try { parsed = JSON.parse(rawText); } catch (_) {}
  return { fullURL, status: resp.status, rawText, parsed };
}

/**
 * Return indented JSON for display in the results page.
 * Falls back to the raw string if the body is not valid JSON (e.g. a
 * plain-text error from the server) so the developer still sees the response.
 */
function pretty(rawText) {
  try {
    return JSON.stringify(JSON.parse(rawText), null, 2);
  } catch (_) {
    return rawText;
  }
}

// --- Workflow ---

/**
 * runWorkflow executes the full custom admin role lifecycle and returns
 * { success, steps[] }. Each step is a plain object matching the StepResult
 * shape. On failure the function returns immediately, leaving steps populated
 * up to and including the failed step so the UI can highlight the problem.
 */
async function runWorkflow() {
  const steps = [];

  // Step 0: obtain a bearer token via client_credentials.
  // The worker app must hold Organization Admin — without it, later calls
  // to create custom roles or assign them will return 403 Forbidden.
  let token;
  try {
    token = await getAdminToken();
  } catch (err) {
    steps.push({ title: 'Obtain admin access token', ok: false, detail: err.message });
    return { success: false, steps };
  }
  steps.push({ title: 'Obtain admin access token', ok: true, detail: 'client_credentials grant succeeded.' });

  // Step 1: GET /roles — fetch all platform (built-in) roles.
  // Platform roles are global and read-only; they can only be listed, not
  // created or deleted. We need two IDs from this response:
  //   - Application Owner — to understand which permission IDs to copy.
  //   - Organization Admin — to reference in canBeAssignedBy.
  // The response is often large, so we collapse it in the UI by default.
  let res = await apiCall('GET', '/roles', token);
  const rolesURLLabel = 'GET ' + res.fullURL;
  const step1 = { title: 'List platform roles', body: pretty(res.rawText), url: rolesURLLabel, collapsed: true };
  if (res.status >= 400) {
    step1.detail = `HTTP ${res.status}`;
    steps.push(step1);
    return { success: false, steps };
  }
  step1.ok     = true;
  step1.detail = `HTTP ${res.status}`;
  steps.push(step1);

  // Locate Application Owner by name. Its permission IDs serve as the template
  // for the custom role we are about to create.
  const [appOwnerID, appOwnerName] = findRoleID(res.parsed, 'Application Owner');
  if (!appOwnerID) {
    steps.push({ title: 'Find Application Owner platform role', ok: false, detail: "Could not find an 'Application Owner' role in this tenant.", url: rolesURLLabel });
    return { success: false, steps };
  }
  steps.push({ title: 'Find Application Owner platform role', ok: true, detail: `Found "${appOwnerName}" (id=${appOwnerID}) — we'll borrow its application permissions and drop the create permission.`, url: rolesURLLabel });

  // Locate Organization Admin by name. Its ID goes into canBeAssignedBy on the
  // custom role. Without canBeAssignedBy, the custom role is created but no
  // actor — not even an Organization Admin — can assign it to a user or group.
  const [orgAdminID] = findRoleID(res.parsed, 'Organization Admin');
  if (!orgAdminID) {
    steps.push({ title: 'Find Organization Admin platform role', ok: false, detail: "Could not find an 'Organization Admin' role — cannot grant delegation authority.", url: rolesURLLabel });
    return { success: false, steps };
  }
  steps.push({ title: 'Find Organization Admin platform role', ok: true, detail: `Found (id=${orgAdminID}) — will add to canBeAssignedBy on the custom role.`, url: rolesURLLabel });

  // Step 2: select the permissions to include in the custom role.
  // Permission IDs use the format service:action:resource.
  // We choose read + update and omit "applications:create:application" so that
  // holders of this role cannot add new applications — only view and edit them.
  const selected = [
    { id: 'applications:read:application' },
    { id: 'applications:update:application' },
  ];
  steps.push({
    title:  'Select read/update application permissions',
    ok:     true,
    detail: 'Using applications:read:application + applications:update:application (dropping create).',
    body:   JSON.stringify(selected, null, 2),
    url:    rolesURLLabel,
  });

  // Step 3: create the custom admin role.
  // Custom roles are scoped to an environment: POST /environments/{envID}/roles.
  // This is distinct from GET /roles which lists read-only platform roles.
  //
  // Key payload fields:
  //   applicableTo    — ["ENVIRONMENT", "POPULATION"] lets the role be assigned
  //                     at environment scope or narrowed to a single population.
  //   canBeAssignedBy — references the Organization Admin role ID. This unlocks
  //                     delegation: only actors holding one of these roles may
  //                     assign the custom role to other users or groups.
  const roleSuffix        = Math.floor(Date.now() / 1000);
  const customRolePayload = {
    name:            `App Manager (Read/Update) ${roleSuffix}`,
    description:     'Trimmed-down Application Owner: can read and update applications but cannot create them.',
    applicableTo:    ['ENVIRONMENT', 'POPULATION'],
    permissions:     selected,
    canBeAssignedBy: [{ id: orgAdminID }],
  };
  res = await apiCall('POST', `/environments/${targetEnvID}/roles`, token, customRolePayload);
  const step3 = { title: 'Create custom admin role', body: pretty(res.rawText), detail: `HTTP ${res.status}`, url: `POST ${res.fullURL}` };
  if (res.status >= 400) {
    steps.push(step3);
    return { success: false, steps };
  }
  const customRoleID = res.parsed && res.parsed.id;
  if (!customRoleID) {
    step3.detail = 'Role created but response contained no id.';
    steps.push(step3);
    return { success: false, steps };
  }
  step3.ok     = true;
  step3.detail = `HTTP ${res.status} — custom role id=${customRoleID}`;
  steps.push(step3);

  // Step 4: create a population to act as the role-assignment scope boundary.
  // Users in this population will be subject to the custom role; users in other
  // populations are unaffected when the role is assigned at POPULATION scope.
  const popPayload = {
    name:        `App Management Scope ${roleSuffix}`,
    description: 'Population that scopes the trimmed-down App Manager role.',
  };
  res = await apiCall('POST', `/environments/${targetEnvID}/populations`, token, popPayload);
  const step4 = { title: 'Create population', body: pretty(res.rawText), detail: `HTTP ${res.status}`, url: `POST ${res.fullURL}` };
  if (res.status >= 400) {
    steps.push(step4);
    return { success: false, steps };
  }
  const populationID = res.parsed && res.parsed.id;
  if (!populationID) {
    step4.detail = 'Population created but response contained no id.';
    steps.push(step4);
    return { success: false, steps };
  }
  step4.ok     = true;
  step4.detail = `HTTP ${res.status} — population id=${populationID}`;
  steps.push(step4);

  // Step 5: create a group to be the role-assignment vehicle.
  // Assigning a role to a group (rather than to individual users) means that
  // adding/removing members is the only operation needed to grant/revoke access.
  const groupPayload = {
    name:        `App Managers ${roleSuffix}`,
    description: 'Group that receives the trimmed-down App Manager role.',
  };
  res = await apiCall('POST', `/environments/${targetEnvID}/groups`, token, groupPayload);
  const step5 = { title: 'Create group', body: pretty(res.rawText), detail: `HTTP ${res.status}`, url: `POST ${res.fullURL}` };
  if (res.status >= 400) {
    steps.push(step5);
    return { success: false, steps };
  }
  const groupID = res.parsed && res.parsed.id;
  if (!groupID) {
    step5.detail = 'Group created but response contained no id.';
    steps.push(step5);
    return { success: false, steps };
  }
  step5.ok     = true;
  step5.detail = `HTTP ${res.status} — group id=${groupID}`;
  steps.push(step5);

  // Step 6: assign the custom role to the group, scoped to the population.
  // PingOne does not have a separate "assign group to population" endpoint.
  // The population scope is expressed directly on the role assignment:
  //   scope.id   — the population ID
  //   scope.type — "POPULATION" (must be uppercase)
  // Members of the group inherit the custom role within this population only.
  const groupRolePayload = {
    role:  { id: customRoleID },
    scope: { id: populationID, type: 'POPULATION' },
  };
  res = await apiCall('POST', `/environments/${targetEnvID}/groups/${groupID}/roleAssignments`, token, groupRolePayload);
  const step6 = { title: 'Assign custom role to group, scoped to population', body: pretty(res.rawText), detail: `HTTP ${res.status}`, url: `POST ${res.fullURL}` };
  if (res.status >= 400) {
    steps.push(step6);
    return { success: false, steps };
  }
  step6.ok = true;
  steps.push(step6);

  // Step 7: create a user inside the population.
  // Placing the user in the same population as the role-assignment scope
  // ensures group membership activates the scoped custom role for this user.
  // The population field requires a reference object { id } — not a plain string.
  const userPayload = {
    username:   `app-manager-test-${roleSuffix}`,
    email:      `app-manager-test-${roleSuffix}@example.com`,
    population: { id: populationID },
    name:       { given: 'App', family: 'Manager' },
  };
  res = await apiCall('POST', `/environments/${targetEnvID}/users`, token, userPayload);
  const step7 = { title: 'Register a new user into the population', body: pretty(res.rawText), detail: `HTTP ${res.status}`, url: `POST ${res.fullURL}` };
  if (res.status >= 400) {
    steps.push(step7);
    return { success: false, steps };
  }
  const userID = res.parsed && res.parsed.id;
  if (!userID) {
    step7.detail = 'User created but response contained no id.';
    steps.push(step7);
    return { success: false, steps };
  }
  step7.ok     = true;
  step7.detail = `HTTP ${res.status} — user id=${userID}`;
  steps.push(step7);

  // Step 8: add the user to the group.
  // The POST body is just the group ID reference; PingOne looks up the group's
  // role assignments and propagates them to this user. PingOne returns 201 with
  // a body or 204 No Content — both indicate success.
  res = await apiCall('POST', `/environments/${targetEnvID}/users/${userID}/memberOfGroups`, token, { id: groupID });
  const step8 = { title: 'Add user to the group', body: pretty(res.rawText), url: `POST ${res.fullURL}` };
  if (res.status >= 400) {
    step8.detail = `HTTP ${res.status}`;
    steps.push(step8);
    return { success: false, steps };
  }
  step8.ok     = true;
  step8.detail = 'User added to group; role assignment now applies via group membership.';
  steps.push(step8);

  // Step 9: verify the user's effective role assignments.
  // GET /users/{id}/roleAssignments returns both directly-assigned roles and
  // roles inherited through group membership. We do a simple string-contains
  // check for the custom role ID. If absent, propagation may still be in
  // progress — the step is marked failed with a note about this possibility.
  res = await apiCall('GET', `/environments/${targetEnvID}/users/${userID}/roleAssignments`, token);
  const step9 = { title: 'Verify user role assignments', body: pretty(res.rawText), detail: `HTTP ${res.status}`, url: `GET ${res.fullURL}` };
  if (res.status >= 400) {
    steps.push(step9);
    return { success: false, steps };
  }
  if (!res.rawText.includes(customRoleID)) {
    step9.ok     = false;
    step9.detail = `HTTP ${res.status} — user does not yet appear to have the custom role; check the raw response below. Role assignments via groups may require a brief propagation delay.`;
    steps.push(step9);
    return { success: false, steps };
  }
  step9.ok     = true;
  step9.detail = `HTTP ${res.status} — user's role assignments include the custom role (inherited via group).`;
  steps.push(step9);

  return { success: true, steps };
}

// --- Helpers ---

/**
 * Search the _embedded.roles array returned by GET /roles for a role whose
 * name matches the given string (case-insensitive).
 * Returns [id, name] or ['', ''] if not found.
 *
 * PingOne wraps list responses in a HAL _embedded envelope. For most tenants
 * the default page size covers all platform roles in one request so pagination
 * is not needed here.
 */
function findRoleID(parsed, name) {
  const roles = parsed?._embedded?.roles;
  if (!Array.isArray(roles)) return ['', ''];
  for (const role of roles) {
    if (typeof role.name === 'string' && role.name.toLowerCase() === name.toLowerCase()) {
      return [role.id || '', role.name];
    }
  }
  return ['', ''];
}

// --- Express app ---

const app = express();
app.use(express.urlencoded({ extended: true }));

app.get('/', (_req, res) => res.send(indexHTML));

app.post('/run', async (req, res) => {
  try {
    const data = await runWorkflow();
    res.send(resultsHTML(data));
  } catch (err) {
    res.status(500).send(`<pre>${escapeHTML(err.stack || err.message)}</pre>`);
  }
});

app.listen(3000, () => {
  console.log('Custom Admin Role workflow on http://localhost:3000');
});
