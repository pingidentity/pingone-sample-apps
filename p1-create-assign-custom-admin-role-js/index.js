require('dotenv').config();
const express = require('express');

const adminEnvID        = process.env.PINGONE_ADMIN_ENV_ID;
const adminClientID     = process.env.PINGONE_ADMIN_CLIENT_ID;
const adminClientSecret = process.env.PINGONE_ADMIN_CLIENT_SECRET;
const targetEnvID       = process.env.PINGONE_TARGET_ENV_ID;
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
  body{font-family:sans-serif; margin:40px; max-width:900px;}
  button{font-size:16px; padding:10px 20px; cursor:pointer;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word;}
  .step{margin-top:18px;}
  .step h3{margin:0 0 6px 0;}
  .ok{color:#0a7a0a;}
  .err{color:#b00020;}
</style>
</head>
<body>
  <h2>Custom Admin Role Workflow</h2>
  <p>Creates a trimmed-down application admin role, assigns it to a group scoped to a population, registers a user into that population, and verifies the inherited role assignment.</p>
  <form action="/run" method="POST"><button type="submit">Run Workflow</button></form>
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
  body{font-family:sans-serif; margin:40px; max-width:900px;}
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
  <h2>Workflow Result</h2>
  <div class="banner ${bannerClass}">${bannerMsg}</div>
  ${stepsHTML}
  <p><a href="/">Back</a></p>
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

// apiCall issues a JSON request to the management API with the admin bearer token.
// Returns { fullURL, status, rawText, parsed }.
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

function pretty(rawText) {
  try {
    return JSON.stringify(JSON.parse(rawText), null, 2);
  } catch (_) {
    return rawText;
  }
}

// --- Workflow ---

async function runWorkflow() {
  const steps = [];

  // Step 0: admin token
  let token;
  try {
    token = await getAdminToken();
  } catch (err) {
    steps.push({ title: 'Obtain admin access token', ok: false, detail: err.message });
    return { success: false, steps };
  }
  steps.push({ title: 'Obtain admin access token', ok: true, detail: 'client_credentials grant succeeded.' });

  // Step 1: list platform roles
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

  // Find Application Owner role id
  const [appOwnerID, appOwnerName] = findRoleID(res.parsed, 'Application Owner');
  if (!appOwnerID) {
    steps.push({ title: 'Find Application Owner platform role', ok: false, detail: "Could not find an 'Application Owner' role in this tenant.", url: rolesURLLabel });
    return { success: false, steps };
  }
  steps.push({ title: 'Find Application Owner platform role', ok: true, detail: `Found "${appOwnerName}" (id=${appOwnerID}) — we'll borrow its application permissions and drop the create permission.`, url: rolesURLLabel });

  // Find Organization Admin role id — needed in canBeAssignedBy
  const [orgAdminID] = findRoleID(res.parsed, 'Organization Admin');
  if (!orgAdminID) {
    steps.push({ title: 'Find Organization Admin platform role', ok: false, detail: "Could not find an 'Organization Admin' role — cannot grant delegation authority.", url: rolesURLLabel });
    return { success: false, steps };
  }
  steps.push({ title: 'Find Organization Admin platform role', ok: true, detail: `Found (id=${orgAdminID}) — will add to canBeAssignedBy on the custom role.`, url: rolesURLLabel });

  // Select permissions
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

  // Step 3: create custom admin role
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

  // Step 4: create a population
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

  // Step 5: create a group
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

  // Step 6: assign the custom role to the group, scoped to the population
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

  // Step 7: create a user in the population
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

  // Step 8: add the user to the group
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

  // Step 9: verify role assignments on the user
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

// findRoleID searches _embedded.roles for a case-insensitive name match.
// Returns [id, name] or ['', ''].
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
