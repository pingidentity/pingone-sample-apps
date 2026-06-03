/**
 * PingOne DaVinci Sign-On — React backend (Express)
 *
 * This Express server drives the DaVinci sign-on flow and exposes it as a
 * single JSON endpoint (POST /api/run) consumed by the React frontend. All
 * PingOne API calls happen here; the browser never holds credentials.
 *
 * Workflow (three steps):
 *  1. GET  /as/authorize?response_mode=pi.flow
 *     Initialises a DaVinci flow session. PingOne returns JSON flow handles
 *     (interactionId, interactionToken, connectionId, capabilityName, id)
 *     instead of redirecting the browser.
 *  2. POST /davinci/connections/{connectionId}/capabilities/{capabilityName}
 *     Submits the user's credentials to the waiting DaVinci node. On success
 *     the flow returns an authorization code in authorizeResponse.code.
 *  3. POST /as/token
 *     Standard OAuth 2.0 authorization_code exchange. Returns an access token.
 *
 * See server/.env.example for required environment variables.
 */
require('dotenv').config();
const express = require('express');
const path    = require('path');

// Strip trailing slashes so URL concatenation is always safe.
const envID        = process.env.PINGONE_ENV_ID;
const clientID     = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
const authPath     = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');
const redirectURI  = process.env.PINGONE_REDIRECT_URI;

if (!envID || !clientID || !clientSecret || !authPath || !redirectURI) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// PingOne helpers
// ---------------------------------------------------------------------------

/**
 * pretty — return indented JSON string for display in step cards.
 * Falls back to the raw string when the body is not valid JSON.
 */
function pretty(raw) {
  try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
}

/**
 * startFlow — GET /as/authorize?response_mode=pi.flow
 *
 * response_mode=pi.flow tells PingOne to return the DaVinci flow state as a
 * JSON body rather than redirecting the browser. The response contains the
 * session handles needed to drive subsequent capability requests.
 *
 * Returns { flowState, fullURL, rawBody } or throws on error.
 * flowState: { interactionId, interactionToken, connectionId, capabilityName, id }
 */
async function startFlow() {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     clientID,
    redirect_uri:  redirectURI,
    scope:         'openid',
    response_mode: 'pi.flow',
  });
  const fullURL = `${authPath}/${envID}/as/authorize?${params.toString()}`;

  const resp = await fetch(fullURL, {
    method:  'GET',
    headers: {
      // X-Requested-With: ping-sdk tells PingOne this is a programmatic SDK
      // client. Combined with response_mode=pi.flow, it ensures the server
      // returns JSON flow handles rather than an HTML login page.
      'X-Requested-With': 'ping-sdk',
      'Accept':           'application/json',
    },
  });
  const raw = await resp.text();

  if (resp.status >= 400) {
    throw new Error(`authorize returned ${resp.status}: ${raw}`);
  }

  let data;
  try { data = JSON.parse(raw); } catch {
    throw new Error(`authorize response was not JSON (status ${resp.status}): ${raw}`);
  }

  const state = {
    interactionId:    data.interactionId    ?? '',
    interactionToken: data.interactionToken ?? '',
    connectionId:     data.connectionId     ?? '',
    capabilityName:   data.capabilityName   ?? '',
    id:               data.id               ?? '',
  };

  if (!state.interactionId || !state.connectionId || !state.capabilityName) {
    throw new Error(`authorize response missing flow handles: ${raw}`);
  }

  return { flowState: state, fullURL, rawBody: raw };
}

/**
 * submitSignOn — POST /davinci/connections/{connectionId}/capabilities/{capabilityName}
 *
 * Posts the user's credentials to the DaVinci capability URL. The request body
 * is the DaVinci runtime envelope. On success the flow returns an authorization
 * code in authorizeResponse.code.
 *
 * Returns { code, fullURL, rawBody } or throws on error.
 */
async function submitSignOn(flowState, username, password) {
  const fullURL = `${authPath}/${envID}/davinci/connections/${flowState.connectionId}/capabilities/${flowState.capabilityName}`;

  const payload = {
    id:        flowState.id,
    eventName: 'continue',
    parameters: {
      eventType: 'submit',
      data: {
        actionKey: 'SIGNON',
        formData: { username, password },
      },
    },
  };

  const resp = await fetch(fullURL, {
    method:  'POST',
    headers: {
      'Content-Type':     'application/json',
      'Accept':           'application/json',
      'X-Requested-With': 'ping-sdk',
      // interactionId / interactionToken are the DaVinci session correlation
      // handles from startFlow. They must be sent as headers on every capability
      // request so DaVinci can locate the live flow session.
      'interactionId':    flowState.interactionId,
      'interactionToken': flowState.interactionToken,
    },
    body: JSON.stringify(payload),
  });
  const raw = await resp.text();

  if (resp.status >= 400) {
    throw new Error(`capability returned ${resp.status}: ${raw}`);
  }

  let data;
  try { data = JSON.parse(raw); } catch {
    throw new Error(`capability response was not JSON (status ${resp.status}): ${raw}`);
  }

  // authorizeResponse.code is present only when the DaVinci flow has reached
  // its terminal success node. If absent, the flow needs another step (e.g.
  // MFA) that this sample does not handle.
  const code = data?.authorizeResponse?.code ?? '';
  if (!code) {
    throw new Error(`flow did not return an authorization code (likely needs another step): ${raw}`);
  }

  return { code, fullURL, rawBody: raw };
}

/**
 * exchangeToken — POST /as/token
 *
 * Standard OAuth 2.0 authorization_code exchange. Authentication uses HTTP
 * Basic (CLIENT_SECRET_BASIC): clientID:clientSecret base64-encoded.
 *
 * Returns { accessToken, fullURL, rawBody } or throws on error.
 */
async function exchangeToken(code) {
  const fullURL = `${authPath}/${envID}/as/token`;

  const body = new URLSearchParams({
    grant_type:   'authorization_code',
    code,
    redirect_uri: redirectURI,
    scope:        'openid',
  });

  const credentials = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');

  const resp = await fetch(fullURL, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Accept':        'application/json',
      'Authorization': `Basic ${credentials}`,
    },
    body,
  });
  const raw = await resp.text();

  if (resp.status >= 400) {
    throw new Error(`token endpoint returned ${resp.status}: ${raw}`);
  }

  let data;
  try { data = JSON.parse(raw); } catch {
    throw new Error(`token response was not JSON (status ${resp.status}): ${raw}`);
  }

  const accessToken = data.access_token ?? '';
  if (!accessToken) {
    throw new Error(`token response missing access_token: ${raw}`);
  }

  return { accessToken, fullURL, rawBody: raw };
}

/**
 * checkFlowPolicyAssignment — startup probe to confirm the OIDC app has a
 * DaVinci flow policy assigned.
 *
 * Without the assignment, the authorize endpoint issues a redirect instead of
 * returning JSON flow handles. Detecting this at startup gives a clear error
 * rather than a cryptic mid-login failure.
 */
async function checkFlowPolicyAssignment() {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     clientID,
    redirect_uri:  redirectURI,
    scope:         'openid',
    response_mode: 'pi.flow',
  });
  const url = `${authPath}/${envID}/as/authorize?${params.toString()}`;

  const resp = await fetch(url, {
    method:   'GET',
    headers:  { 'X-Requested-With': 'ping-sdk', 'Accept': 'application/json' },
    redirect: 'manual',  // surface 302/303 instead of silently following them
  });

  if (resp.status === 302 || resp.status === 303) {
    throw new Error(
      `The authorize endpoint redirected instead of returning a DaVinci flow.\n` +
      `  Your OIDC app likely has no flow policy assignment.\n` +
      `  Fix: assign a DaVinci flow policy to app "${clientID}" in environment "${envID}".\n` +
      `  See README.md → PingOne configuration for instructions.`
    );
  }

  const raw = await resp.text();
  let data;
  try { data = JSON.parse(raw); } catch { data = null; }

  if (!data?.interactionId) {
    throw new Error(
      `The authorize endpoint did not return a DaVinci flow (status ${resp.status}).\n` +
      `  Check that the OIDC app has a flow policy assignment and that\n` +
      `  PINGONE_CLIENT_ID / PINGONE_ENV_ID / PINGONE_AUTH_PATH are correct.\n` +
      `  Response: ${raw}`
    );
  }

  console.log('Startup check passed: DaVinci flow policy assignment is present.');
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/**
 * runSignOn drives the full three-step DaVinci sign-on and returns
 * { success, steps[] }. Each step object matches the StepResult shape
 * expected by the React frontend. On failure the function returns immediately.
 */
async function runSignOn(username, password) {
  const steps = [];

  // Step 1: Start DaVinci Flow
  let flowState, startURL, startBody;
  try {
    const result = await startFlow();
    flowState = result.flowState;
    startURL  = result.fullURL;
    startBody = result.rawBody;
  } catch (err) {
    steps.push({
      title:     'Start DaVinci Flow',
      ok:        false,
      detail:    err.message,
      body:      '',
      url:       `GET ${authPath}/${envID}/as/authorize`,
      collapsed: false,
    });
    return { success: false, steps };
  }
  steps.push({
    title:     'Start DaVinci Flow',
    ok:        true,
    detail:    `flow started id=${flowState.id} capability=${flowState.capabilityName}`,
    body:      pretty(startBody),
    url:       `GET ${startURL}`,
    collapsed: false,
  });

  // Step 2: Submit Sign-On
  let code, submitURL, submitBody;
  try {
    const result = await submitSignOn(flowState, username, password);
    code       = result.code;
    submitURL  = result.fullURL;
    submitBody = result.rawBody;
  } catch (err) {
    steps.push({
      title:     'Submit Sign-On',
      ok:        false,
      detail:    err.message,
      body:      '',
      url:       `POST ${authPath}/${envID}/davinci/connections/…/capabilities/…`,
      collapsed: false,
    });
    return { success: false, steps };
  }
  steps.push({
    title:     'Submit Sign-On',
    ok:        true,
    detail:    'authorization code received',
    body:      pretty(submitBody),
    url:       `POST ${submitURL}`,
    collapsed: false,
  });

  // Step 3: Exchange Authorization Code
  let accessToken, tokenURL, tokenBody;
  try {
    const result = await exchangeToken(code);
    accessToken = result.accessToken;
    tokenURL    = result.fullURL;
    tokenBody   = result.rawBody;
  } catch (err) {
    steps.push({
      title:     'Exchange Authorization Code',
      ok:        false,
      detail:    err.message,
      body:      '',
      url:       `POST ${authPath}/${envID}/as/token`,
      collapsed: false,
    });
    return { success: false, steps };
  }
  steps.push({
    title:     'Exchange Authorization Code',
    ok:        true,
    detail:    'access_token received',
    body:      pretty(tokenBody),
    url:       `POST ${tokenURL}`,
    collapsed: false,
  });

  return { success: true, steps, accessToken };
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

// Serve logo from the repo root (one level up from server/).
app.get('/logo.png', (req, res) => {
  res.sendFile(path.join(__dirname, '../logo.png'));
});

// Serve built React dist in production.
app.use(express.static(path.join(__dirname, '../client/dist')));

/**
 * POST /api/run — accepts { username, password } and drives the full
 * DaVinci sign-on flow. Returns { success, steps[], accessToken? }.
 */
app.post('/api/run', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      steps: [{
        title:     'Validation error',
        ok:        false,
        detail:    'username and password are required.',
        body:      '',
        url:       '',
        collapsed: false,
      }],
    });
  }
  try {
    const result = await runSignOn(username, password);
    res.json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      steps: [{
        title:     'Unexpected error',
        ok:        false,
        detail:    err.message,
        body:      '',
        url:       '',
        collapsed: false,
      }],
    });
  }
});

// Run the startup check before accepting traffic.
checkFlowPolicyAssignment()
  .then(() => {
    app.listen(3000, () => {
      console.log('DaVinci Sign-On backend on http://localhost:3000');
    });
  })
  .catch((err) => {
    console.error(`Startup check failed: ${err.message}`);
    process.exit(1);
  });
