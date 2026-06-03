// PingOne Native Flows MFA Demo — React backend (Node.js / Express)
//
// This server exposes two JSON API endpoints consumed by the React frontend:
//   POST /api/login      — steps 1 and 2: initialise the flow, submit credentials
//   POST /api/mfa-verify — step 3: submit the OTP
//
// Both endpoints return a JSON object:
//   { status: 'COMPLETED', accessToken: '...' }  — flow done, token issued
//   { status: 'MFA_REQUIRED' }                   — OTP sent, show the MFA form
//   { status: 'ERROR', message: '...' }           — something went wrong
//
// Overview of the four-step PingOne Flows sequence:
//
//  1. GET /as/authorize?response_mode=pi.flow
//     Initialises a PingOne Flow session without redirecting the browser.
//     PingOne returns a JSON body whose "id" field is the flow ID used on all
//     subsequent /flows/{id} calls. PingOne also sets session cookies (ST,
//     ST-NO-SS) that must be captured and replayed on every later call.
//
//  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.usernamePassword.check+json
//     Submits username + password to the active flow. The response "status"
//     field determines the next step:
//       "COMPLETED"                             — proceed to /as/resume
//       "OTP_REQUIRED" / "DEVICE_SELECTION_REQUIRED" /
//       "MULTI_FACTOR_AUTHENTICATION_REQUIRED"  — OTP sent; return MFA_REQUIRED
//
//  3. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.otp.check+json
//     (only when MFA is required) Submits the one-time passcode. Status
//     "COMPLETED" means the OTP was accepted.
//
//  4. GET /as/resume?flowId={flowID}  (finishFlow helper)
//     Signals PingOne the native flow is done. PingOne returns either a JSON
//     body with authorizeResponse.code or a 302 redirect to the registered
//     redirect_uri with ?code= in the query string. The code is then
//     exchanged at POST /as/token for an access token.
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
//   - redirect: 'manual' on all PingOne calls — prevents fetch from silently
//     following 302 responses so we can inspect Location headers ourselves.
//   - Cookies must be captured and replayed manually — Node's fetch has no
//     built-in cookie jar, and RFC 6265 path scoping would drop PingOne's ST
//     cookies between flow steps anyway.
//   - Browser-to-server session continuity uses an httpOnly `sid` cookie so
//     the React frontend never touches PingOne cookies directly.

require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');

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
  console.error('Missing required environment variables.');
  process.exit(1);
}
if (!adminEnvID || !adminClientID || !adminClientSecret) {
  console.error('Missing admin worker app credentials.');
  process.exit(1);
}

// Server-side session store keyed by a random `sid` cookie value.
// Each session holds:
//   adminToken — the management-plane bearer token for /flows/ calls
//   cookies    — raw "name=value" strings captured from PingOne responses
//   flowID     — the current flow ID, updated as PingOne progresses the flow
//
// The browser receives only the opaque `sid` cookie; PingOne credentials and
// cookies are never exposed to the React client.
const sessions = new Map();

// getAdminToken fetches a short-lived access token from the admin worker app
// using the client_credentials grant. The token authorises all /flows/{id}
// management API calls. A fresh token is fetched at the start of each login.
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
  if (!json.access_token) throw new Error(`No access_token: ${JSON.stringify(json)}`);
  return json.access_token;
}

// captureCookies extracts Set-Cookie values from a PingOne response and stores
// them as raw "name=value" strings in session.cookies.
//
// Why manual capture instead of a cookie jar?
//   Node's fetch has no built-in cookie jar, and RFC 6265 path scoping would
//   silently drop PingOne's ST / ST-NO-SS cookies when the request path
//   changes between flow steps. Manual capture-and-replay is the only
//   reliable approach.
//
// If a cookie with the same name already exists it is replaced, because
// PingOne may issue updated ST values across flow steps.
function captureCookies(session, resp) {
  const setCookie = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
  for (const raw of setCookie) {
    const nv = raw.split(';')[0]; // strip path, domain, expiry attributes
    const name = nv.split('=')[0];
    const idx = session.cookies.findIndex(c => c.startsWith(`${name}=`));
    if (idx >= 0) session.cookies[idx] = nv;
    else session.cookies.push(nv);
  }
}

// cookieHeader joins all captured cookies into the single "Cookie: a=1; b=2"
// header value expected by PingOne.
const cookieHeader = (s) => s.cookies.join('; ');

// getOrCreateSession ties a browser request to its server-side session via an
// httpOnly `sid` cookie. A new session is created the first time a client is
// seen. The session persists across the login and MFA steps, allowing the
// admin token and PingOne cookies captured in /api/login to be reused in
// /api/mfa-verify without the client ever seeing PingOne credentials.
function getOrCreateSession(req, res) {
  let sid = req.cookies.sid;
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, { adminToken: null, cookies: [], flowID: null });
    res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
  }
  return sessions.get(sid);
}

const app = express();
app.use(express.json());
app.use(cookieParser());

// POST /api/login — steps 1 and 2: initialise the flow and submit credentials.
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const session = getOrCreateSession(req, res);
    // Reset the session for a fresh login attempt in case the user is retrying.
    session.adminToken = await getAdminToken();
    session.cookies = [];

    // Step 1: Initialise the PingOne Flow session.
    //
    // response_mode=pi.flow — return JSON flow state instead of redirecting.
    // Accept: */* — required because PingOne uses vendor content types; a
    //   strict Accept: application/json causes a 406 Not Acceptable.
    // redirect: 'manual' — prevents fetch from following any 302 automatically.
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session, initResp);
    const initJson = await initResp.json();
    let flowID = initJson.id;

    // Step 2: Submit credentials to the active flow.
    //
    // Content-Type: application/vnd.pingidentity.usernamePassword.check+json
    //   tells the flow engine which action to perform.
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
    // PingOne may return an updated flow ID after the credential check. Always
    // use the latest ID so subsequent calls target the correct flow state.
    if (loginJson.id) flowID = loginJson.id;
    session.flowID = flowID; // persist for use in /api/mfa-verify

    // Route based on the flow status:
    //   COMPLETED — no MFA required; finish the flow and return the token.
    //   OTP_REQUIRED / DEVICE_SELECTION_REQUIRED /
    //   MULTI_FACTOR_AUTHENTICATION_REQUIRED — OTP sent; tell the client to
    //     show the MFA form.
    if (loginJson.status === 'COMPLETED') {
      const token = await finishFlow(session, flowID);
      return res.json({ status: 'COMPLETED', accessToken: token });
    }
    if (['OTP_REQUIRED', 'DEVICE_SELECTION_REQUIRED', 'MULTI_FACTOR_AUTHENTICATION_REQUIRED'].includes(loginJson.status)) {
      return res.json({ status: 'MFA_REQUIRED' });
    }
    return res.status(400).json({ status: 'ERROR', message: `Unexpected status: ${JSON.stringify(loginJson)}` });
  } catch (err) {
    return res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

// POST /api/mfa-verify — step 3: submit the OTP to PingOne.
//
// The browser's `sid` cookie identifies the server-side session that holds
// the admin token, PingOne session cookies, and the current flowID from the
// login step. If the session is missing (e.g. server restart) the client is
// asked to start over.
app.post('/api/mfa-verify', async (req, res) => {
  try {
    const { otp } = req.body;
    const sid = req.cookies.sid;
    const session = sid && sessions.get(sid);
    if (!session || !session.flowID) {
      return res.status(400).json({ status: 'ERROR', message: 'Session expired. Please log in again.' });
    }

    // Content-Type: application/vnd.pingidentity.otp.check+json tells the
    // flow engine to validate the OTP against the user's enrolled MFA device.
    // The same Accept: */* and dual-auth (Bearer + cookies) rules apply here.
    const mfaResp = await fetch(`${authPath}/${envID}/flows/${session.flowID}`, {
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
    // Update the stored flowID if PingOne issued a new one after the OTP check.
    if (mfaJson.id) session.flowID = mfaJson.id;

    if (mfaJson.status === 'COMPLETED') {
      const token = await finishFlow(session, session.flowID);
      return res.json({ status: 'COMPLETED', accessToken: token });
    }
    return res.status(400).json({ status: 'ERROR', message: `MFA Failed: ${JSON.stringify(mfaJson)}` });
  } catch (err) {
    return res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

// finishFlow drives step 4: call GET /as/resume to signal PingOne the native
// flow is complete, extract the authorization code, and exchange it for tokens.
//
// /as/resume behaviour:
//   - PingOne may return a JSON body containing authorizeResponse.code, or
//   - PingOne may issue a 302 redirect to the registered redirect_uri with
//     ?code= in the query string. redirect: 'manual' keeps us in control so
//     we can read the Location header ourselves.
//
// Only the session cookies are sent to /as/resume. The admin bearer token is
// NOT required because /as/resume is part of the OAuth 2.0 authorization
// endpoint, not the management plane.
async function finishFlow(session, flowID) {
  const resumeResp = await fetch(`${authPath}/${envID}/as/resume?flowId=${flowID}`, {
    headers: { Accept: '*/*', Cookie: cookieHeader(session) },
    redirect: 'manual',
  });
  captureCookies(session, resumeResp);

  // Try JSON body first; fall back to the Location redirect URL.
  let authCode = '';
  const ct = resumeResp.headers.get('content-type') || '';
  if (ct.includes('json')) {
    const j = await resumeResp.json();
    authCode = j?.authorizeResponse?.code || '';
  }
  if (!authCode) {
    const loc = resumeResp.headers.get('location');
    if (loc) try { authCode = new URL(loc).searchParams.get('code') || ''; } catch {}
  }
  if (!authCode) throw new Error('Failed to get authorization code from resume.');

  // Standard authorization_code token exchange using the end-user OIDC app's
  // credentials. The redirect_uri must exactly match the value sent in the
  // authorize request and registered on the PingOne app.
  const creds = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  const tokenResp = await fetch(`${authPath}/${envID}/as/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${creds}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: 'http://localhost:3000/callback',
    }),
  });
  const tokenJson = await tokenResp.json();
  if (!tokenJson.access_token) throw new Error(`No access_token: ${JSON.stringify(tokenJson)}`);
  return tokenJson.access_token;
}

// Serve the built React app for production use.
// In development the Vite dev server (port 5173) proxies /api/* to this
// Express server, so this static middleware is only active after `npm run build`.
app.use(express.static(path.join(__dirname, '..', 'client', 'dist')));
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'client', 'dist', 'index.html'));
});

app.listen(3000, async () => {
  // Verify admin credentials at startup so a misconfiguration is caught
  // immediately rather than surfacing as a mid-login 401.
  try {
    await getAdminToken();
    console.log('Admin token smoke-test passed.');
  } catch (err) {
    console.error('Failed to get admin token at startup:', err.message);
    process.exit(1);
  }
  console.log('MFA Demo backend on http://localhost:3000');
});
