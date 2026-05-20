require('dotenv').config();
const express = require('express');
const path = require('path');

const adminEnvID        = process.env.PINGONE_ADMIN_ENV_ID;
const adminClientID     = process.env.PINGONE_ADMIN_CLIENT_ID;
const adminClientSecret = process.env.PINGONE_ADMIN_CLIENT_SECRET;
const targetEnvID       = process.env.PINGONE_TARGET_ENV_ID;
const authPath = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');
const apiPath  = (process.env.PINGONE_API_PATH  || '').replace(/\/$/, '');

if (!adminEnvID || !adminClientID || !adminClientSecret || !targetEnvID || !authPath || !apiPath) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// ── PingOne helpers ──────────────────────────────────────────────────────────

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
 * Returns { url, status, raw, parsed }.
 */
async function apiCall(method, urlPath, token, payload) {
  const fullURL = apiPath + urlPath;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
  };
  let body;
  if (payload !== undefined && payload !== null) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(payload);
  }
  const resp = await fetch(fullURL, { method, headers, body });
  const text = await resp.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch {}
  return { url: fullURL, status: resp.status, raw: text, parsed };
}

function pretty(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
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

function responseMentionsRole(text, roleID) {
  return text.includes(roleID);
}

// ── Workflow ─────────────────────────────────────────────────────────────────

async function runWorkflow() {
  const steps = [];
  const roleSuffix = Date.now();

  // Step 0: Admin token
  let token;
  try {
    token = await getAdminToken();
    steps.push({ title: 'Obtain admin access token', ok: true, detail: 'client_credentials grant succeeded.', body: '', url: '', collapsed: false });
  } catch (err) {
    steps.push({ title: 'Obtain admin access token', ok: false, detail: err.message, body: '', url: '', collapsed: false });
    return { success: false, steps };
  }

  // Step 1: List platform roles
  const rolesResult = await apiCall('GET', '/roles', token, null);
  const rolesURL = `GET ${rolesResult.url}`;
  const step1 = {
    title: 'List platform roles',
    ok: false,
    detail: `HTTP ${rolesResult.status}`,
    body: pretty(rolesResult.raw),
    url: rolesURL,
    collapsed: true,
  };
  if (rolesResult.status >= 400) {
    steps.push(step1);
    return { success: false, steps };
  }
  step1.ok = true;
  steps.push(step1);

  // Find Application Owner role
  const { id: appOwnerID, name: appOwnerName } = findRoleID(rolesResult.parsed, 'Application Owner');
  if (!appOwnerID) {
    steps.push({ title: 'Find Application Owner platform role', ok: false, detail: "Could not find an 'Application Owner' role in this tenant.", body: '', url: rolesURL, collapsed: false });
    return { success: false, steps };
  }
  steps.push({ title: 'Find Application Owner platform role', ok: true, detail: `Found "${appOwnerName}" (id=${appOwnerID}) — we'll borrow its application permissions and drop the create permission.`, body: '', url: rolesURL, collapsed: false });

  // Find Organization Admin role
  const { id: orgAdminID } = findRoleID(rolesResult.parsed, 'Organization Admin');
  if (!orgAdminID) {
    steps.push({ title: 'Find Organization Admin platform role', ok: false, detail: "Could not find an 'Organization Admin' role — cannot grant delegation authority.", body: '', url: rolesURL, collapsed: false });
    return { success: false, steps };
  }
  steps.push({ title: 'Find Organization Admin platform role', ok: true, detail: `Found (id=${orgAdminID}) — will add to canBeAssignedBy on the custom role.`, body: '', url: rolesURL, collapsed: false });

  // Step 2: Select permissions
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

  // Step 3: Create custom admin role
  const customRolePayload = {
    name: `App Manager (Read/Update) ${roleSuffix}`,
    description: 'Trimmed-down Application Owner: can read and update applications but cannot create them.',
    applicableTo: ['ENVIRONMENT', 'POPULATION'],
    permissions: selected,
    canBeAssignedBy: [{ id: orgAdminID }],
  };
  const r3 = await apiCall('POST', `/environments/${targetEnvID}/roles`, token, customRolePayload);
  const step3 = {
    title: 'Create custom admin role',
    ok: false,
    detail: `HTTP ${r3.status}`,
    body: pretty(r3.raw),
    url: `POST ${r3.url}`,
    collapsed: false,
  };
  if (r3.status >= 400) {
    steps.push(step3);
    return { success: false, steps };
  }
  const customRoleID = r3.parsed?.id ?? '';
  if (!customRoleID) {
    step3.detail = 'Role created but response contained no id.';
    steps.push(step3);
    return { success: false, steps };
  }
  step3.ok = true;
  step3.detail = `HTTP ${r3.status} — custom role id=${customRoleID}`;
  steps.push(step3);

  // Step 4: Create population
  const popPayload = {
    name: `App Management Scope ${roleSuffix}`,
    description: 'Population that scopes the trimmed-down App Manager role.',
  };
  const r4 = await apiCall('POST', `/environments/${targetEnvID}/populations`, token, popPayload);
  const step4 = {
    title: 'Create population',
    ok: false,
    detail: `HTTP ${r4.status}`,
    body: pretty(r4.raw),
    url: `POST ${r4.url}`,
    collapsed: false,
  };
  if (r4.status >= 400) {
    steps.push(step4);
    return { success: false, steps };
  }
  const populationID = r4.parsed?.id ?? '';
  if (!populationID) {
    step4.detail = 'Population created but response contained no id.';
    steps.push(step4);
    return { success: false, steps };
  }
  step4.ok = true;
  step4.detail = `HTTP ${r4.status} — population id=${populationID}`;
  steps.push(step4);

  // Step 5: Create group
  const groupPayload = {
    name: `App Managers ${roleSuffix}`,
    description: 'Group that receives the trimmed-down App Manager role.',
  };
  const r5 = await apiCall('POST', `/environments/${targetEnvID}/groups`, token, groupPayload);
  const step5 = {
    title: 'Create group',
    ok: false,
    detail: `HTTP ${r5.status}`,
    body: pretty(r5.raw),
    url: `POST ${r5.url}`,
    collapsed: false,
  };
  if (r5.status >= 400) {
    steps.push(step5);
    return { success: false, steps };
  }
  const groupID = r5.parsed?.id ?? '';
  if (!groupID) {
    step5.detail = 'Group created but response contained no id.';
    steps.push(step5);
    return { success: false, steps };
  }
  step5.ok = true;
  step5.detail = `HTTP ${r5.status} — group id=${groupID}`;
  steps.push(step5);

  // Step 6: Assign custom role to group, scoped to population
  const groupRolePayload = {
    role: { id: customRoleID },
    scope: { id: populationID, type: 'POPULATION' },
  };
  const r6 = await apiCall('POST', `/environments/${targetEnvID}/groups/${groupID}/roleAssignments`, token, groupRolePayload);
  const step6 = {
    title: 'Assign custom role to group, scoped to population',
    ok: false,
    detail: `HTTP ${r6.status}`,
    body: pretty(r6.raw),
    url: `POST ${r6.url}`,
    collapsed: false,
  };
  if (r6.status >= 400) {
    steps.push(step6);
    return { success: false, steps };
  }
  step6.ok = true;
  steps.push(step6);

  // Step 7: Create user in the population
  const userPayload = {
    username: `app-manager-test-${roleSuffix}`,
    email: `app-manager-test-${roleSuffix}@example.com`,
    population: { id: populationID },
    name: { given: 'App', family: 'Manager' },
  };
  const r7 = await apiCall('POST', `/environments/${targetEnvID}/users`, token, userPayload);
  const step7 = {
    title: 'Register a new user into the population',
    ok: false,
    detail: `HTTP ${r7.status}`,
    body: pretty(r7.raw),
    url: `POST ${r7.url}`,
    collapsed: false,
  };
  if (r7.status >= 400) {
    steps.push(step7);
    return { success: false, steps };
  }
  const userID = r7.parsed?.id ?? '';
  if (!userID) {
    step7.detail = 'User created but response contained no id.';
    steps.push(step7);
    return { success: false, steps };
  }
  step7.ok = true;
  step7.detail = `HTTP ${r7.status} — user id=${userID}`;
  steps.push(step7);

  // Step 8: Add user to the group
  const r8 = await apiCall('POST', `/environments/${targetEnvID}/users/${userID}/memberOfGroups`, token, { id: groupID });
  const step8 = {
    title: 'Add user to the group',
    ok: false,
    detail: '',
    body: pretty(r8.raw),
    url: `POST ${r8.url}`,
    collapsed: false,
  };
  if (r8.status >= 400) {
    step8.detail = `HTTP ${r8.status}`;
    steps.push(step8);
    return { success: false, steps };
  }
  step8.ok = true;
  step8.detail = 'User added to group; role assignment now applies via group membership.';
  steps.push(step8);

  // Step 9: Verify role assignments on the user
  const r9 = await apiCall('GET', `/environments/${targetEnvID}/users/${userID}/roleAssignments`, token, null);
  const step9 = {
    title: 'Verify user role assignments',
    ok: false,
    detail: `HTTP ${r9.status}`,
    body: pretty(r9.raw),
    url: `GET ${r9.url}`,
    collapsed: false,
  };
  if (r9.status >= 400) {
    steps.push(step9);
    return { success: false, steps };
  }
  if (!responseMentionsRole(r9.raw, customRoleID)) {
    step9.ok = false;
    step9.detail = `HTTP ${r9.status} — user does not yet appear to have the custom role; check the raw response below. Role assignments via groups may require a brief propagation delay.`;
    steps.push(step9);
    return { success: false, steps };
  }
  step9.ok = true;
  step9.detail = `HTTP ${r9.status} — user's role assignments include the custom role (inherited via group).`;
  steps.push(step9);

  return { success: true, steps };
}

// ── Express app ──────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

app.post('/api/run', async (_req, res) => {
  try {
    const result = await runWorkflow();
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, steps: [{ title: 'Internal server error', ok: false, detail: err.message, body: '', url: '', collapsed: false }] });
  }
});

// Serve the built Angular app (production).
const angularDist = path.join(__dirname, '..', 'client', 'dist', 'p1-create-assign-custom-admin-role-angular', 'browser');
app.use(express.static(angularDist));
app.get('*', (_req, res) => {
  res.sendFile(path.join(angularDist, 'index.html'));
});

app.listen(3000, () => {
  console.log('Custom Admin Role workflow backend on http://localhost:3000');
});
