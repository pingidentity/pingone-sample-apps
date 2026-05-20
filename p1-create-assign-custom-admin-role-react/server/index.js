require('dotenv').config();
const express = require('express');

const adminEnvID        = process.env.PINGONE_ADMIN_ENV_ID;
const adminClientID     = process.env.PINGONE_ADMIN_CLIENT_ID;
const adminClientSecret = process.env.PINGONE_ADMIN_CLIENT_SECRET;
const targetEnvID       = process.env.PINGONE_TARGET_ENV_ID;
const authPath          = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');
const apiPath           = (process.env.PINGONE_API_PATH  || '').replace(/\/$/, '');

if (!adminEnvID || !adminClientID || !adminClientSecret || !targetEnvID || !authPath || !apiPath) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// PingOne API helpers
// ---------------------------------------------------------------------------

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
 * Issue a JSON request to the management API.
 * Returns { fullURL, status, raw (string), parsed (object|null) }.
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

function pretty(raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

function findRoleID(parsed, name) {
  const roles = parsed?._embedded?.roles ?? [];
  for (const role of roles) {
    if (typeof role.name === 'string' && role.name.toLowerCase() === name.toLowerCase()) {
      return { id: role.id ?? '', name: role.name };
    }
  }
  return { id: '', name: '' };
}

function responseMentionsRole(raw, roleID) {
  return raw.includes(roleID);
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

async function runWorkflow() {
  const steps = [];

  // Step 0: admin token (client_credentials)
  let token;
  try {
    token = await getAdminToken();
  } catch (err) {
    steps.push({ title: 'Obtain admin access token', ok: false, detail: err.message, body: '', url: '', collapsed: false });
    return { success: false, steps };
  }
  steps.push({ title: 'Obtain admin access token', ok: true, detail: 'client_credentials grant succeeded.', body: '', url: '', collapsed: false });

  // Step 1: GET /roles — list platform roles
  const rolesRes = await apiCall('GET', '/roles', token, null);
  const step1 = {
    title: 'List platform roles',
    url: `GET ${rolesRes.fullURL}`,
    body: pretty(rolesRes.raw),
    detail: `HTTP ${rolesRes.status}`,
    collapsed: true,
    ok: false,
  };
  if (rolesRes.status >= 400) {
    steps.push(step1);
    return { success: false, steps };
  }
  step1.ok = true;
  steps.push(step1);

  const rolesURL = `GET ${rolesRes.fullURL}`;

  // Find Application Owner role
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

  // Find Organization Admin role
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

  // Step 2: select permissions
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

  // Step 3: create custom admin role
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

  // Step 4: create population
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

  // Step 5: create group
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

  // Step 6: assign custom role to group, scoped to population
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

  // Step 7: create user in the population
  const userPayload = {
    username:   `app-manager-test-${roleSuffix}`,
    email:      `app-manager-test-${roleSuffix}@example.com`,
    population: { id: populationID },
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

  // Step 8: add user to group
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

  // Step 9: verify role assignments on the user
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
