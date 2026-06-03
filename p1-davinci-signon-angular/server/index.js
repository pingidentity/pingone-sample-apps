/**
 * PingOne DaVinci Sign-On — Angular backend (Express)
 *
 * Exposes POST /api/run which accepts { username, password } and drives the
 * three-step DaVinci sign-on flow on behalf of the Angular frontend. All
 * PingOne credentials stay server-side; the Angular client never holds them.
 *
 * Flow overview:
 *  1. GET /as/authorize?response_mode=pi.flow — initialise a DaVinci flow session.
 *     PingOne returns JSON flow handles (interactionId, interactionToken,
 *     connectionId, capabilityName, id) instead of redirecting the browser.
 *  2. POST /davinci/connections/{connectionId}/capabilities/{capabilityName} —
 *     submit credentials to the capability node DaVinci is waiting on.
 *     A successful response contains authorizeResponse.code.
 *  3. POST /as/token — exchange the authorization code for an access token
 *     using the standard OAuth 2.0 authorization_code grant (CLIENT_SECRET_BASIC).
 *
 * checkFlowPolicyAssignment() runs at startup to confirm the OIDC app has a
 * DaVinci flow policy assigned; without it the authorize endpoint redirects
 * instead of returning JSON handles, causing a confusing mid-login failure.
 */
require('dotenv').config();
const express = require('express');
const path    = require('path');

const envID        = process.env.PINGONE_ENV_ID;
const clientID     = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
const authPath     = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');
const redirectURI  = process.env.PINGONE_REDIRECT_URI;

if (!envID || !clientID || !clientSecret || !authPath || !redirectURI) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// ── PingOne helpers ──────────────────────────────────────────────────────────

/**
 * Pretty-print raw JSON text for display in step cards.
 * Falls back to the raw string if it is not valid JSON.
 */
function pretty(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}

/**
 * startFlow — GET /as/authorize?response_mode=pi.flow
 *
 * response_mode=pi.flow instructs PingOne to return the DaVinci flow state as
 * JSON instead of redirecting the browser. The response contains:
 *   interactionId / interactionToken — session correlation handles that must be
 *     sent as headers on every subsequent capability request.
 *   connectionId / capabilityName — identify the DaVinci connector node waiting
 *     for input; the capability URL is built from these values.
 *   id — the flow instance ID echoed back in the capability request body.
 *
 * Returns { state, url, raw } where state holds the five handles.
 */
async function startFlow() {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     clientID,
    redirect_uri:  redirectURI,
    scope:         'openid',
    response_mode: 'pi.flow',
  });
  const url = `${authPath}/${envID}/as/authorize?${params}`;
  const resp = await fetch(url, {
    headers: {
      'X-Requested-With': 'ping-sdk',
      'Accept': 'application/json',
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
  return { state, url: `GET ${url}`, raw };
}

/**
 * submitSignOn — POST /davinci/connections/{connectionId}/capabilities/{capabilityName}
 *
 * Submits the user's credentials to the DaVinci capability node that is waiting
 * for input. The request body is the DaVinci runtime envelope:
 *   id          — flow instance ID from startFlow, so DaVinci can locate the
 *                 correct in-progress execution context.
 *   eventName   — "continue" advances the flow past the current node.
 *   parameters.data.actionKey — "SIGNON" selects the sign-on branch.
 *   parameters.data.formData  — the user-supplied credentials.
 *
 * interactionId and interactionToken are sent as request headers (not in the
 * body) — DaVinci requires them as headers to locate the live flow session.
 *
 * On success the flow completes and the response contains
 * authorizeResponse.code — an authorization code ready for token exchange.
 *
 * Returns { code, url, raw }.
 */
async function submitSignOn(state, username, password) {
  const capURL = `${authPath}/${envID}/davinci/connections/${state.connectionId}/capabilities/${state.capabilityName}`;
  const payload = {
    id:        state.id,
    eventName: 'continue',
    parameters: {
      eventType: 'submit',
      data: {
        actionKey: 'SIGNON',
        formData:  { username, password },
      },
    },
  };
  const resp = await fetch(capURL, {
    method: 'POST',
    headers: {
      'Content-Type':    'application/json',
      'Accept':          'application/json',
      'X-Requested-With': 'ping-sdk',
      'interactionId':   state.interactionId,
      'interactionToken': state.interactionToken,
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
  const authResp = data.authorizeResponse;
  if (!authResp || typeof authResp !== 'object') {
    throw new Error(`flow did not return an authorization code (likely needs another step): ${raw}`);
  }
  const code = authResp.code ?? '';
  if (!code) {
    throw new Error(`authorizeResponse missing code: ${raw}`);
  }
  return { code, url: `POST ${capURL}`, raw };
}

/**
 * exchangeToken — POST /as/token (standard authorization_code exchange)
 *
 * Exchanges the authorization code for an access token. Authentication uses
 * HTTP Basic (CLIENT_SECRET_BASIC): clientID:clientSecret are base64-encoded
 * in the Authorization header. The redirect_uri must exactly match the value
 * sent in the authorize request and the one registered on the PingOne app.
 *
 * Returns { token, url, raw }.
 */
async function exchangeToken(code) {
  const tokenURL = `${authPath}/${envID}/as/token`;
  const body = new URLSearchParams({
    grant_type:   'authorization_code',
    code,
    redirect_uri: redirectURI,
    scope:        'openid',
  });
  const credentials = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  const resp = await fetch(tokenURL, {
    method: 'POST',
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
  const token = data.access_token ?? '';
  if (!token) {
    throw new Error(`token response missing access_token: ${raw}`);
  }
  return { token, url: `POST ${tokenURL}`, raw };
}

/**
 * checkFlowPolicyAssignment — startup probe of the authorize endpoint.
 *
 * When the OIDC app has a DaVinci flow policy assigned, the authorize endpoint
 * returns 200 JSON with flow handles. Without a flow policy assignment PingOne
 * issues a 302 redirect to its default login page, which this app cannot handle.
 * Detecting this at startup produces a clear error instead of a cryptic
 * mid-login failure.
 *
 * The { redirect: 'manual' } fetch option causes a redirect to be returned as
 * an opaque response (type "opaqueredirect", status 0) rather than followed.
 */
async function checkFlowPolicyAssignment() {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     clientID,
    redirect_uri:  redirectURI,
    scope:         'openid',
    response_mode: 'pi.flow',
  });
  const url = `${authPath}/${envID}/as/authorize?${params}`;
  const resp = await fetch(url, {
    redirect: 'manual',
    headers: {
      'X-Requested-With': 'ping-sdk',
      'Accept': 'application/json',
    },
  });
  // An opaque redirect (status 0) or explicit 302/303 means no flow policy.
  if (resp.status === 302 || resp.status === 303 || resp.type === 'opaqueredirect') {
    throw new Error(
      `The authorize endpoint redirected instead of returning a DaVinci flow.\n` +
      `  Your OIDC app likely has no flow policy assignment.\n` +
      `  Fix: assign a DaVinci flow policy to app "${clientID}" in environment "${envID}".\n` +
      `  See README.md → PingOne configuration for instructions.`
    );
  }
  const raw = await resp.text();
  let data;
  try { data = JSON.parse(raw); } catch { data = {}; }
  if (!data.interactionId) {
    throw new Error(
      `The authorize endpoint did not return a DaVinci flow (status ${resp.status}).\n` +
      `  Check that the OIDC app has a flow policy assignment and that\n` +
      `  PINGONE_CLIENT_ID / PINGONE_ENV_ID / PINGONE_AUTH_PATH are correct.\n` +
      `  Response: ${raw}`
    );
  }
  console.log('Startup check passed: DaVinci flow policy assignment is present.');
}

// ── Workflow ─────────────────────────────────────────────────────────────────

/**
 * runSignOn drives the full three-step flow and returns { success, steps[] }.
 * Each step object matches the StepResult interface expected by the Angular
 * frontend. On failure the function returns immediately.
 */
async function runSignOn(username, password) {
  const steps = [];

  // Step 1: initialise the DaVinci flow session.
  let flowResult;
  try {
    flowResult = await startFlow();
  } catch (err) {
    steps.push({
      title: 'Start DaVinci Flow',
      ok: false,
      detail: `Failed to start flow: ${err.message}`,
      body: '',
      url: '',
      collapsed: false,
    });
    return { success: false, steps };
  }
  const { state } = flowResult;
  steps.push({
    title: 'Start DaVinci Flow',
    ok: true,
    detail: `flow started id=${state.id} capability=${state.capabilityName}`,
    body: pretty(flowResult.raw),
    url: flowResult.url,
    collapsed: false,
  });

  // Step 2: submit credentials to the capability node.
  let signOnResult;
  try {
    signOnResult = await submitSignOn(state, username, password);
  } catch (err) {
    steps.push({
      title: 'Submit Sign-On',
      ok: false,
      detail: `Failed to submit credentials: ${err.message}`,
      body: '',
      url: '',
      collapsed: false,
    });
    return { success: false, steps };
  }
  steps.push({
    title: 'Submit Sign-On',
    ok: true,
    detail: 'authorization code received',
    body: pretty(signOnResult.raw),
    url: signOnResult.url,
    collapsed: false,
  });

  // Step 3: exchange the authorization code for an access token.
  let tokenResult;
  try {
    tokenResult = await exchangeToken(signOnResult.code);
  } catch (err) {
    steps.push({
      title: 'Exchange Authorization Code',
      ok: false,
      detail: `Failed to exchange token: ${err.message}`,
      body: '',
      url: '',
      collapsed: false,
    });
    return { success: false, steps };
  }
  steps.push({
    title: 'Exchange Authorization Code',
    ok: true,
    detail: 'access_token received',
    body: pretty(tokenResult.raw),
    url: tokenResult.url,
    collapsed: false,
  });

  return { success: true, steps };
}

// ── Express app ──────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// Serve logo.png from the app root (one level above server/).
app.get('/logo.png', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'logo.png'));
});

app.post('/api/run', async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      steps: [{ title: 'Validation error', ok: false, detail: 'username and password are required', body: '', url: '', collapsed: false }],
    });
  }
  try {
    const result = await runSignOn(username, password);
    res.json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      steps: [{ title: 'Internal server error', ok: false, detail: err.message, body: '', url: '', collapsed: false }],
    });
  }
});

// Serve the built Angular app (production).
const angularDist = path.join(__dirname, '..', 'client', 'dist', 'p1-davinci-signon-angular', 'browser');
app.use(express.static(angularDist));
app.get('*', (_req, res) => {
  res.sendFile(path.join(angularDist, 'index.html'));
});

// Run startup check then begin listening.
checkFlowPolicyAssignment()
  .then(() => {
    app.listen(3000, () => {
      console.log('DaVinci Sign-On demo backend on http://localhost:3000');
    });
  })
  .catch(err => {
    console.error(`Startup check failed: ${err.message}`);
    process.exit(1);
  });
