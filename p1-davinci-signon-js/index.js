/**
 * PingOne DaVinci Sign-On Flow — Node.js / Express
 *
 * Overview of the three-step flow:
 *
 *  1. GET /as/authorize?response_mode=pi.flow
 *     Instead of redirecting the browser, PingOne returns a JSON envelope
 *     describing the first DaVinci capability the client must drive.
 *     The response contains handles (interactionId, interactionToken,
 *     connectionId, capabilityName, id) that identify both the live flow
 *     session and the specific connector node that is waiting for input.
 *
 *  2. POST /davinci/connections/{connectionId}/capabilities/{capabilityName}
 *     The client submits credentials to the capability URL using the handles
 *     from step 1 as request headers (interactionId, interactionToken).
 *     The DaVinci flow validates the credentials and — on a simple sign-on
 *     flow — returns an authorization code in authorizeResponse.code.
 *
 *  3. POST /as/token  (standard OAuth 2.0 authorization_code exchange)
 *     The authorization code is exchanged for an access token using the
 *     OIDC web app's client_id and client_secret (CLIENT_SECRET_BASIC).
 *
 * Prerequisites in PingOne:
 *   - A Web App (OIDC, authorization_code, CLIENT_SECRET_BASIC) with a
 *     DaVinci flow policy assignment pointing at a sign-on flow.
 *   - The DaVinci flow must use the API integration method (JSON responses).
 *   - A test user in the population the flow's PingOne SSO connector targets.
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

// --- HTML helpers ---

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// --- HTML Templates ---

const indexHTML = `
<!DOCTYPE html>
<html>
<head><title>DaVinci Sign-On</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;} button:hover{background:#b8002f;} input{font-size:15px; padding:6px 8px; min-width:280px;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2>DaVinci Sign-On Flow with PingOne Auth</h2>
    <p>Sign in with credentials. The PingOne authorize endpoint hands the request to the assigned DaVinci flow policy; this app drives the flow to completion and exchanges the resulting code for a token.</p>
    <form action="/login" method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        <button type="submit">Sign On</button>
    </form>
</div>
</body>
</html>`;

function dashboardHTML(token) {
  return `
<!DOCTYPE html>
<html>
<head><title>Signed In</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2 style="color:#0a7a0a;">Sign-On Successful</h2>
    <p>The DaVinci flow returned an authorization code, which was exchanged for an access token:</p>
    <pre>${escapeHTML(token)}</pre>
    <a href="/">Sign Out</a>
</div>
</body>
</html>`;
}

function renderErrorHTML(msg) {
  return `
<!DOCTYPE html>
<html>
<head><title>Error</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2 style="color:#b00020;">Sign-On Error</h2>
    <pre>${escapeHTML(msg)}</pre>
    <a href="/">Try Again</a>
</div>
</body>
</html>`;
}

// --- DaVinci flow helpers ---

/**
 * checkFlowPolicyAssignment probes the authorize endpoint at startup to confirm
 * the OIDC app has a DaVinci flow policy assigned.
 *
 * When response_mode=pi.flow is used with a properly configured app, PingOne
 * returns a 200 JSON body containing flow handles. Without a flow policy
 * assignment PingOne issues a 302 redirect to its default login page instead,
 * which this app cannot handle. Detecting this at startup gives a clear error
 * message rather than a cryptic mid-login failure.
 */
async function checkFlowPolicyAssignment() {
  const params = new URLSearchParams({
    response_type:  'code',
    client_id:      clientID,
    redirect_uri:   redirectURI,
    scope:          'openid',
    response_mode:  'pi.flow',
  });
  const authURL = `${authPath}/${envID}/as/authorize?${params.toString()}`;

  // Use redirect: 'manual' so a 302 is returned to us rather than silently
  // followed to the login page.
  const resp = await fetch(authURL, {
    redirect: 'manual',
    headers: {
      'X-Requested-With': 'ping-sdk',
      'Accept':           'application/json',
    },
  });

  if (resp.status === 302 || resp.status === 303 || resp.type === 'opaqueredirect') {
    throw new Error(
      `the authorize endpoint redirected instead of returning a DaVinci flow.\n` +
      `  Your OIDC app likely has no flow policy assignment.\n` +
      `  Fix: assign a DaVinci flow policy to app "${clientID}" in environment "${envID}".\n` +
      `  See README.md → PingOne configuration for instructions.`
    );
  }

  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch (_) { data = {}; }

  if (!data.interactionId) {
    throw new Error(
      `the authorize endpoint did not return a DaVinci flow (status ${resp.status}).\n` +
      `  Check that the OIDC app has a flow policy assignment and that\n` +
      `  PINGONE_CLIENT_ID / PINGONE_ENV_ID / PINGONE_AUTH_PATH are correct.\n` +
      `  Response: ${text}`
    );
  }

  console.log('Startup check passed: DaVinci flow policy assignment is present.');
}

/**
 * startFlow calls GET /as/authorize?response_mode=pi.flow to initialise a
 * DaVinci flow session.
 *
 * response_mode=pi.flow instructs PingOne to return the flow state as a JSON
 * body rather than redirecting the browser. The response describes the first
 * DaVinci node waiting for client input and contains the session handles
 * (interactionId, interactionToken, connectionId, capabilityName, id) needed
 * to drive subsequent steps.
 */
async function startFlow() {
  const params = new URLSearchParams({
    response_type:  'code',
    client_id:      clientID,
    redirect_uri:   redirectURI,
    scope:          'openid',
    response_mode:  'pi.flow',
  });
  const authURL = `${authPath}/${envID}/as/authorize?${params.toString()}`;

  const resp = await fetch(authURL, {
    headers: {
      // X-Requested-With: ping-sdk tells PingOne this is a programmatic SDK
      // client. Combined with response_mode=pi.flow it ensures the server returns
      // JSON flow handles rather than an HTML login page.
      'X-Requested-With': 'ping-sdk',
      'Accept':           'application/json',
    },
  });

  const text = await resp.text();
  if (resp.status >= 400) {
    throw new Error(`authorize returned ${resp.status}: ${text}`);
  }

  let data;
  try { data = JSON.parse(text); } catch (_) {
    throw new Error(`authorize response was not JSON: ${text}`);
  }

  const state = {
    interactionId:    data.interactionId    || '',
    interactionToken: data.interactionToken || '',
    connectionId:     data.connectionId     || '',
    capabilityName:   data.capabilityName   || '',
    id:               data.id               || '',
  };

  if (!state.interactionId || !state.connectionId || !state.capabilityName) {
    throw new Error(`authorize response missing flow handles: ${text}`);
  }
  return state;
}

/**
 * submitSignOn posts credentials to the DaVinci capability URL constructed
 * from the flow handles returned in step 1.
 *
 * The request body shape is the DaVinci runtime envelope:
 *   - id: the flow instance ID from startFlow, echoed so DaVinci can match
 *     this request to the correct in-progress execution.
 *   - eventName: "continue" advances the flow past the current node.
 *   - parameters.data.actionKey: "SIGNON" selects the sign-on branch of the
 *     PingOne SSO connector (as opposed to "REGISTER" for self-service signup).
 *   - parameters.data.formData: the user-supplied field values. For a basic
 *     sign-on flow the connector expects "username" and "password".
 *
 * On success the flow completes and the response contains
 * authorizeResponse.code — an authorization code ready for token exchange.
 */
async function submitSignOn(state, username, password) {
  const payload = {
    id:        state.id,
    eventName: 'continue',
    parameters: {
      eventType: 'submit',
      data: {
        actionKey: 'SIGNON',
        formData: { username, password },
      },
    },
  };

  // The capability URL encodes which DaVinci connector and node to invoke.
  // connectionId identifies the PingOne SSO connector instance in this flow;
  // capabilityName is the specific action within that connector (e.g. userLookup).
  const capURL = `${authPath}/${envID}/davinci/connections/${state.connectionId}/capabilities/${state.capabilityName}`;

  const resp = await fetch(capURL, {
    method: 'POST',
    headers: {
      'Content-Type':     'application/json',
      'Accept':           'application/json',
      'X-Requested-With': 'ping-sdk',
      // interactionId and interactionToken are the DaVinci session correlation
      // handles from startFlow. They must be sent as headers (not in the body)
      // on every capability request so DaVinci can locate the live flow session.
      'interactionId':    state.interactionId,
      'interactionToken': state.interactionToken,
    },
    body: JSON.stringify(payload),
  });

  const text = await resp.text();
  if (resp.status >= 400) {
    throw new Error(`capability returned ${resp.status}: ${text}`);
  }

  let data;
  try { data = JSON.parse(text); } catch (_) {
    throw new Error(`capability response was not JSON: ${text}`);
  }

  // authorizeResponse.code is present only when the DaVinci flow has reached
  // its terminal success node. If it is absent the flow needs another step
  // (e.g. MFA) that this sample does not handle.
  const authResp = data.authorizeResponse;
  if (!authResp || typeof authResp !== 'object') {
    throw new Error(`flow did not return an authorization code (likely needs another step): ${text}`);
  }
  const code = authResp.code || '';
  if (!code) {
    throw new Error(`authorizeResponse missing code: ${text}`);
  }
  return code;
}

/**
 * exchangeToken performs a standard OAuth 2.0 authorization_code token
 * exchange at the PingOne token endpoint.
 *
 * The redirect_uri must exactly match the value sent in the authorize request
 * and the one registered on the PingOne app — PingOne validates all three
 * match before issuing tokens. Authentication uses HTTP Basic (CLIENT_SECRET_BASIC):
 * the client_id and client_secret are base64-encoded in the Authorization header.
 */
async function exchangeToken(code) {
  const body        = new URLSearchParams({
    grant_type:   'authorization_code',
    code,
    redirect_uri: redirectURI,
    scope:        'openid',
  });
  const credentials = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  const tokenURL    = `${authPath}/${envID}/as/token`;

  const resp = await fetch(tokenURL, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Accept':        'application/json',
      'Authorization': `Basic ${credentials}`,
    },
    body,
  });

  const text = await resp.text();
  if (resp.status >= 400) {
    throw new Error(`token endpoint returned ${resp.status}: ${text}`);
  }

  let data;
  try { data = JSON.parse(text); } catch (_) {
    throw new Error(`token response was not JSON: ${text}`);
  }

  const token = data.access_token || '';
  if (!token) {
    throw new Error(`token response missing access_token: ${text}`);
  }
  return token;
}

// --- Express app ---

const app = express();
app.use(express.urlencoded({ extended: true }));

app.get('/logo.png', (_req, res) => res.sendFile(path.join(__dirname, 'logo.png')));

app.get('/', (_req, res) => res.send(indexHTML));

/**
 * handleLogin orchestrates the full three-step sign-on sequence in response
 * to a form POST from the login page. Each step calls a focused helper so the
 * sequence reads top-to-bottom as plain English.
 */
app.post('/login', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  // Step 1: Call the PingOne authorize endpoint with response_mode=pi.flow.
  // This does not authenticate the user yet — it initialises a DaVinci flow
  // session and returns the handles needed to drive it.
  let state;
  try {
    state = await startFlow();
  } catch (err) {
    return res.send(renderErrorHTML('Failed to start flow: ' + err.message));
  }
  console.log(`[signon] flow started id=${state.id} capability=${state.capabilityName}`);

  // Step 2: Submit the user's credentials to the capability that DaVinci is
  // waiting on. For a standard sign-on flow this is the PingOne SSO connector's
  // userLookup/password-check node, and a successful response includes an
  // authorization code in authorizeResponse.code.
  let authCode;
  try {
    authCode = await submitSignOn(state, username, password);
  } catch (err) {
    return res.send(renderErrorHTML('Failed to submit credentials: ' + err.message));
  }
  console.log('[signon] received authorization code');

  // Step 3: Trade the authorization code for tokens at the standard PingOne
  // token endpoint. This is identical to any other authorization_code exchange.
  let token;
  try {
    token = await exchangeToken(authCode);
  } catch (err) {
    return res.send(renderErrorHTML('Failed to exchange token: ' + err.message));
  }

  res.send(dashboardHTML(token));
});

// --- Startup ---

checkFlowPolicyAssignment()
  .then(() => {
    app.listen(3000, () => {
      console.log('DaVinci Sign-On demo starting on http://localhost:3000');
    });
  })
  .catch(err => {
    console.error(`Startup check failed: ${err.message}`);
    process.exit(1);
  });
