// PingOne Native Flows MFA Demo — Node.js / Express
//
// Overview of the four-step flow:
//
//  1. GET /as/authorize?response_mode=pi.flow
//     Initialises a PingOne Flow session without redirecting the browser.
//     PingOne returns a JSON body containing a flow ID (response.id) and
//     sets session cookies (ST, ST-NO-SS) that must be captured and replayed
//     on every subsequent /flows/{id} call.
//
//  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.usernamePassword.check+json
//     Submits username + password to the active flow. The response status
//     field determines the next step:
//       "COMPLETED"                             — proceed to /as/resume
//       "OTP_REQUIRED" / "DEVICE_SELECTION_REQUIRED" /
//       "MULTI_FACTOR_AUTHENTICATION_REQUIRED"  — show the OTP form
//
//  3. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.otp.check+json
//     (only when MFA is required) Submits the one-time passcode. Status
//     "COMPLETED" means the OTP was accepted.
//
//  4. GET /as/resume?flowId={flowID}
//     Signals PingOne the native flow is done. PingOne returns either a JSON
//     body with authorizeResponse.code or a 302 redirect to the registered
//     redirect_uri with ?code= in the query string. Both paths are handled
//     below. The code is then exchanged at POST /as/token for an access token.
//
// Why two PingOne apps?
//
//   /flows/{id} is a management-plane API. PingOne requires a Bearer token
//   from an admin worker app (client_credentials grant) on every /flows/{id}
//   call in addition to the session cookies. A separate end-user OIDC app
//   drives the flow and issues the final tokens.
//
// Key constraints:
//   - Accept: */* on all /flows/ and /as/authorize calls — PingOne uses vendor
//     content types (application/vnd.pingidentity.*+json) and returns 406 if
//     you restrict Accept to application/json.
//   - Cookies must be captured and replayed manually — Node's fetch does not
//     have a built-in cookie jar, and path scoping would drop PingOne's ST
//     cookies anyway. We store raw "name=value" strings and build the Cookie
//     header ourselves.
//   - redirect: 'manual' on all PingOne calls — prevents fetch from following
//     302 responses so we can inspect Location headers ourselves.

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');

// The logo is embedded as a base64 data URI so the single-file app has no
// separate static-file serving requirement.
const logoPNG = fs.readFileSync(path.join(__dirname, '..', 'assets', 'logo.png')).toString('base64');
const logoSrc = `data:image/png;base64,${logoPNG}`;

// End-user OIDC app credentials — used only for the final token exchange.
const envID = process.env.PINGONE_ENV_ID;
const clientID = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
const authPath = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');

// Admin worker app credentials — used only to obtain the management-plane
// bearer token required by the /flows/{id} API.
const adminEnvID = process.env.PINGONE_ADMIN_ENV_ID;
const adminClientID = process.env.PINGONE_ADMIN_CLIENT_ID;
const adminClientSecret = process.env.PINGONE_ADMIN_CLIENT_SECRET;

if (!envID || !clientID || !clientSecret || !authPath) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}
if (!adminEnvID || !adminClientID || !adminClientSecret) {
  console.error('Missing admin worker app credentials. Please check your .env file.');
  process.exit(1);
}

// In-memory session store keyed by flowID.
// Holds the admin bearer token and the raw "name=value" cookie strings captured
// from PingOne responses. This lets handleMFAVerify pick up exactly where
// handleLogin left off without the user having to re-authenticate.
const sessionStore = new Map();

// getAdminToken fetches a short-lived access token from the admin worker app
// using the client_credentials grant. The token authorises the management-plane
// /flows/{id} API calls that drive the native flow. A fresh token is fetched
// at the start of each login attempt so expiry is not a concern here.
async function getAdminToken() {
  const body = new URLSearchParams({ grant_type: 'client_credentials' });
  // CLIENT_SECRET_BASIC: base64(clientID:clientSecret) in the Authorization header.
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
  if (!json.access_token) throw new Error(`No access_token in response: ${JSON.stringify(json)}`);
  return json.access_token;
}

// captureCookies extracts Set-Cookie values from a PingOne response and stores
// them as raw "name=value" strings in session.cookies.
//
// Why not use a cookie jar?
//   Node's fetch does not have a built-in cookie jar, and RFC 6265 path
//   scoping would silently drop PingOne's ST / ST-NO-SS cookies when the
//   request path changes between flow steps. Storing raw name=value pairs
//   and building the Cookie header manually is the only reliable approach.
//
// If a cookie with the same name is already stored it is replaced, because
// PingOne may issue updated ST values across flow steps.
function captureCookies(session, resp) {
  const setCookie = resp.headers.getSetCookie ? resp.headers.getSetCookie() : resp.headers.raw?.()['set-cookie'] || [];
  for (const raw of setCookie) {
    const nameValue = raw.split(';')[0]; // strip path, domain, etc.
    const name = nameValue.split('=')[0];
    const idx = session.cookies.findIndex(c => c.startsWith(`${name}=`));
    if (idx >= 0) session.cookies[idx] = nameValue;
    else session.cookies.push(nameValue);
  }
}

// cookieHeader joins all stored cookies into the single "Cookie: a=1; b=2"
// header value expected by PingOne.
function cookieHeader(session) {
  return session.cookies.join('; ');
}

// --- HTML Templates ---

const indexHTML = `
<!DOCTYPE html>
<html>
<head><title>Login</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:15px; padding:10px 20px; cursor:pointer;} button:hover{background:#c40034;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Secure Login</h2>
  <form action="/login" method="POST">
    <label>Username:</label><br>
    <input type="text" name="username" required><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>
    <button type="submit">Log In</button>
  </form>
</div>
</body>
</html>`;

// mfaHTML embeds the flowID in a hidden form field so the /mfa-verify handler
// can look up the in-progress session when the user submits the OTP.
const mfaHTML = (flowID) => `
<!DOCTYPE html>
<html>
<head><title>MFA Required</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:15px; padding:10px 20px; cursor:pointer;} button:hover{background:#c40034;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Two-Factor Authentication</h2>
  <p>Please enter the verification code sent to your email.</p>
  <form action="/mfa-verify" method="POST">
    <input type="hidden" name="flowId" value="${flowID}">
    <label>MFA Code:</label><br>
    <input type="text" name="otp" required><br><br>
    <button type="submit">Verify</button>
  </form>
</div>
</body>
</html>`;

const dashboardHTML = (token) => `
<!DOCTYPE html>
<html>
<head><title>Dashboard</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} pre{background:#f4f4f4; padding:12px; border-left:3px solid #888;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2 style="color:#0a7a0a;">Login Successful!</h2>
  <p>You have securely authenticated. Here is your Access Token:</p>
  <pre style="white-space: pre-wrap; word-wrap: break-word;">${token}</pre>
  <a href="/">Log Out</a>
</div>
</body>
</html>`;

const errorHTML = (msg) => `
<!DOCTYPE html>
<html>
<head><title>Error</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} pre{background:#f4f4f4; padding:12px; border-left:3px solid #888;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2 style="color:#b00020;">Authentication Error</h2>
  <pre>${msg}</pre>
  <a href="/">Try Again</a>
</div>
</body>
</html>`;

// --- Express app ---

const app = express();
app.use(express.urlencoded({ extended: true }));

app.get('/', (_req, res) => res.send(indexHTML));

// POST /login — steps 1 and 2: initialise the flow and submit credentials.
app.post('/login', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  try {
    const adminToken = await getAdminToken();
    const session = { adminToken, cookies: [] };

    // Step 1: Initialise the PingOne Flow session.
    //
    // response_mode=pi.flow — return JSON flow state instead of redirecting.
    // Accept: */* — required because PingOne uses vendor content types; a
    //   strict Accept: application/json causes a 406 Not Acceptable.
    // redirect: 'manual' — prevents fetch from silently following any 302
    //   PingOne might issue, so we always get the raw response.
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session, initResp);
    const initJson = await initResp.json();
    let flowID = initJson.id;
    console.log(`[login] authorize flowID: ${flowID}`);

    // Step 2: Submit credentials to the active flow.
    //
    // Content-Type: application/vnd.pingidentity.usernamePassword.check+json
    //   tells the flow engine which action to perform. Using application/json
    //   here returns a 415 Unsupported Media Type.
    //
    // Authorization: Bearer <adminToken> — the management-plane bearer token.
    // Cookie: <ST; ST-NO-SS> — the session cookies from step 1.
    // Both headers are required; omitting either causes a 401.
    const loginResp = await fetch(`${authPath}/${envID}/flows/${flowID}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.pingidentity.usernamePassword.check+json',
        'Accept': '*/*',
        'Authorization': `Bearer ${session.adminToken}`,
        'Cookie': cookieHeader(session),
      },
      body: JSON.stringify({ username, password }),
      redirect: 'manual',
    });
    captureCookies(session, loginResp);
    const loginJson = await loginResp.json();
    console.log(`[login] credentials result status=${loginJson.status} id=${loginJson.id}`);

    // PingOne may return an updated flow ID after the credential check. Always
    // use the latest ID so subsequent calls target the correct flow state.
    if (loginJson.id) flowID = loginJson.id;
    sessionStore.set(flowID, session);

    // Route based on the flow status:
    //   COMPLETED — no MFA required for this user; proceed to resume.
    //   OTP_REQUIRED / DEVICE_SELECTION_REQUIRED /
    //   MULTI_FACTOR_AUTHENTICATION_REQUIRED — PingOne has sent an OTP;
    //     show the MFA form.
    if (loginJson.status === 'COMPLETED') {
      return completeLoginAndRender(res, flowID, session);
    }
    if (['OTP_REQUIRED', 'DEVICE_SELECTION_REQUIRED', 'MULTI_FACTOR_AUTHENTICATION_REQUIRED'].includes(loginJson.status)) {
      return res.send(mfaHTML(flowID));
    }
    return res.send(errorHTML(`Unexpected login status: ${JSON.stringify(loginJson)}`));
  } catch (err) {
    return res.send(errorHTML(err.message));
  }
});

// POST /mfa-verify — step 3: submit the OTP to PingOne.
//
// The flowID is posted from the hidden form field rendered by the MFA page.
// It is used to look up the in-progress session (admin token + cookies) so
// the /flows/{id} call can be authenticated correctly.
app.post('/mfa-verify', async (req, res) => {
  let flowID = (req.body.flowId || '').trim();
  const otp = (req.body.otp || '').trim();

  const session = sessionStore.get(flowID);
  if (!session) return res.send(errorHTML('Session expired or lost. Please try logging in again.'));

  try {
    console.log(`[mfa] sending OTP check, flowID=${flowID}`);
    // Content-Type: application/vnd.pingidentity.otp.check+json tells the
    // flow engine to validate the OTP against the user's enrolled MFA device.
    // The same Accept: */* and dual-auth (Bearer + cookies) rules apply here.
    const mfaResp = await fetch(`${authPath}/${envID}/flows/${flowID}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.pingidentity.otp.check+json',
        'Accept': '*/*',
        'Authorization': `Bearer ${session.adminToken}`,
        'Cookie': cookieHeader(session),
      },
      body: JSON.stringify({ otp }),
      redirect: 'manual',
    });
    captureCookies(session, mfaResp);
    const mfaJson = await mfaResp.json();
    console.log('[mfa] result:', mfaJson);

    // Update the session store key if PingOne issued a new flow ID, so the
    // next step always uses the correct handle.
    if (mfaJson.id && mfaJson.id !== flowID) {
      sessionStore.set(mfaJson.id, session);
      sessionStore.delete(flowID);
      flowID = mfaJson.id;
    }

    if (mfaJson.status === 'COMPLETED') {
      sessionStore.delete(flowID);
      return completeLoginAndRender(res, flowID, session);
    }
    return res.send(errorHTML(`MFA Failed. Response: ${JSON.stringify(mfaJson)}`));
  } catch (err) {
    return res.send(errorHTML(err.message));
  }
});

// completeLoginAndRender drives step 4: call GET /as/resume to signal PingOne
// the native flow is complete, extract the authorization code, and exchange it
// for an access token.
//
// /as/resume behaviour:
//   - If the app is configured for server-side redirect handling, PingOne may
//     return a JSON body containing authorizeResponse.code.
//   - More commonly, PingOne issues a 302 redirect to the registered
//     redirect_uri with ?code= in the query string. redirect: 'manual' keeps
//     us in control so we can read the Location header ourselves.
//
// Only the session cookies are sent here — no admin bearer token is required
// because /as/resume is part of the OAuth 2.0 authorization endpoint, not
// the management plane.
async function completeLoginAndRender(res, flowID, session) {
  const resumeResp = await fetch(`${authPath}/${envID}/as/resume?flowId=${flowID}`, {
    headers: {
      'Accept': '*/*',
      'Cookie': cookieHeader(session),
    },
    redirect: 'manual',
  });
  captureCookies(session, resumeResp);
  console.log(`[resume] status code: ${resumeResp.status}`);

  // Try JSON body first; fall back to the Location redirect URL.
  let authCode = '';
  const contentType = resumeResp.headers.get('content-type') || '';
  if (contentType.includes('json')) {
    const resumeJson = await resumeResp.json();
    authCode = resumeJson?.authorizeResponse?.code || '';
  }
  if (!authCode) {
    const loc = resumeResp.headers.get('location');
    if (loc) {
      try { authCode = new URL(loc).searchParams.get('code') || ''; } catch {}
    }
  }
  if (!authCode) return res.send(errorHTML('Failed to get authorization code from resume.'));

  // Step 4b: Standard authorization_code token exchange using the end-user
  // OIDC app's credentials. The redirect_uri must exactly match the value
  // sent in the authorize request and registered on the PingOne app.
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: 'http://localhost:3000/callback',
  });
  const creds = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  const tokenResp = await fetch(`${authPath}/${envID}/as/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${creds}`,
    },
    body: tokenBody,
  });
  const tokenJson = await tokenResp.json();
  if (!tokenJson.access_token) return res.send(errorHTML(`Failed to parse access token. Output: ${JSON.stringify(tokenJson)}`));

  return res.send(dashboardHTML(tokenJson.access_token));
}

app.listen(3000, async () => {
  // Verify admin credentials at startup rather than discovering a bad secret
  // mid-login. A startup failure is far easier to diagnose than a mid-flow 401.
  try {
    await getAdminToken();
    console.log('Admin token smoke-test passed.');
  } catch (err) {
    console.error('Failed to get admin token at startup:', err.message);
    process.exit(1);
  }
  console.log('MFA Demo starting on http://localhost:3000');
});
