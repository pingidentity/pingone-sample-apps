/**
 * PingOne User Registration — React backend (Express)
 *
 * This server implements the same PingOne native authentication flow as the
 * single-file Node.js app (p1-user-registration-js), but adapted for a
 * React SPA: instead of rendering HTML, every endpoint returns JSON consumed
 * by the React frontend. Session state (PingOne flow cookies + flow ID) is
 * stored server-side and associated with the browser via a simple sid cookie.
 *
 * How registration differs from sign-on
 * --------------------------------------
 * Registration creates a new user account in PingOne using the native flow
 * API. No admin worker app token is required — the same OIDC app credentials
 * (PINGONE_CLIENT_ID / PINGONE_CLIENT_SECRET) cover both registration and
 * subsequent sign-on. This is different from management-API workflows that
 * require a separate admin worker app with client_credentials.
 *
 * API surface exposed to the React client:
 *   POST /api/register  — starts a new flow, registers the user
 *                         Returns { status: 'VERIFICATION_REQUIRED' | 'COMPLETED' | 'ERROR' }
 *   POST /api/verify    — submits the email OTP
 *                         Returns { status: 'COMPLETED' | 'ERROR' }
 *   POST /api/login     — signs an existing user in
 *                         Returns { status: 'COMPLETED', accessToken } | { status: 'ERROR' }
 *
 * Registration sub-flow (2–3 steps):
 *  1. GET  /as/authorize?response_mode=pi.flow
 *     Starts a PingOne authentication session. response_mode=pi.flow makes
 *     PingOne return a JSON body with a flow ID instead of redirecting the
 *     browser. The response also sets session cookies that must be replayed on
 *     every subsequent call to this flow.
 *  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.user.register+json
 *     Creates the user. status=COMPLETED means no email verification is required.
 *     status=VERIFICATION_CODE_REQUIRED means PingOne sent an OTP to the email.
 *  3. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.user.verify+json
 *     (Only when step 2 returned VERIFICATION_CODE_REQUIRED.) Submits the OTP.
 *
 * Sign-on sub-flow (4 steps):
 *  1. GET  /as/authorize?response_mode=pi.flow  (fresh session)
 *  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.usernamePassword.check+json
 *  3. GET  /as/resume?flowId={flowID}  — bridges back to the OAuth 2.0 layer;
 *     delivers an authorization code via JSON body or Location header redirect.
 *  4. POST /as/token  — authorization_code grant, returns access_token.
 *
 * Session design
 * --------------
 * The browser receives a random sid cookie (httpOnly, sameSite=lax). The server
 * holds a Map from sid -> { flowID, cookies[] }. This is intentionally simple —
 * a production app should use a persistent store (Redis, database) and set
 * secure: true on the cookie.
 *
 * Cookie handling
 * ---------------
 * PingOne session cookies (ST, ST-NO-SS) must be replayed verbatim on every
 * flow request. The Node.js fetch API does not manage cookies automatically, so
 * this file captures them from Set-Cookie headers and attaches them manually.
 * The sid session ties the cookies to the correct browser tab across the
 * asynchronous registration → verification two-step.
 */

require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');

const envID = process.env.PINGONE_ENV_ID;
const clientID = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
// Strip trailing slash to avoid double-slash in URL construction.
const authPath = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');

if (!envID || !clientID || !clientSecret || !authPath) {
  console.error('Missing required environment variables.');
  process.exit(1);
}

/**
 * Server-side session store: sid -> { flowID, cookies[] }
 *
 * flowID is the PingOne flow identifier returned by /as/authorize. It is
 * stored here so the /api/verify handler can continue a flow started by
 * /api/register without the client having to transmit the ID explicitly.
 *
 * cookies is the set of PingOne session cookies (ST, ST-NO-SS) captured from
 * PingOne responses. They are replayed on every subsequent flow request so
 * PingOne can locate the active session server-side.
 */
const sessions = new Map();

/**
 * captureCookies extracts the name=value portion from each Set-Cookie header
 * and upserts it into the store array. Upserting (replacing if the name already
 * exists) is necessary because PingOne refreshes cookie values on every response
 * — replaying a stale value produces a 401.
 *
 * @param {string[]} store  - mutable array of "name=value" strings
 * @param {Response} resp   - fetch Response to extract Set-Cookie headers from
 */
function captureCookies(store, resp) {
  // getSetCookie() returns all Set-Cookie headers as an array (Node 18+). Each
  // entry looks like "ST=abc; Path=/; HttpOnly". Strip everything after the
  // first semicolon to keep only the name=value pair.
  const setCookie = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
  for (const raw of setCookie) {
    const nv = raw.split(';')[0];
    const name = nv.split('=')[0];
    const idx = store.findIndex(c => c.startsWith(`${name}=`));
    if (idx >= 0) store[idx] = nv;
    else store.push(nv);
  }
}

/**
 * cookieHeader joins stored "name=value" strings into a single Cookie header
 * value. Assembling manually bypasses RFC 6265 path-scoping that would silently
 * drop cookies when the request path differs from the path recorded at capture.
 */
const cookieHeader = (s) => s.join('; ');

/**
 * getOrCreateSession ensures every request has a server-side session entry and
 * a corresponding sid cookie in the browser.
 *
 * A new sid is generated when none exists or when the stored sid has no matching
 * entry (e.g. server restart). httpOnly prevents client-side script from reading
 * the sid value; sameSite=lax mitigates CSRF for the POST endpoints.
 */
function getOrCreateSession(req, res) {
  let sid = req.cookies.sid;
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, { flowID: null, cookies: [] });
    res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
  }
  return sessions.get(sid);
}

const app = express();
app.use(express.json());
app.use(cookieParser());

/**
 * POST /api/register
 *
 * Initialises a PingOne flow and registers the new user.
 *
 * The response status tells the React client what to render next:
 *   VERIFICATION_REQUIRED — show the OTP input form.
 *   COMPLETED             — show the success screen.
 *   ERROR                 — show the error screen with message.
 *
 * PingOne flow cookies and the flow ID are stored in the server-side session
 * so /api/verify can resume the same flow without the client passing them back.
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const session = getOrCreateSession(req, res);
    // Clear any cookies from a previous flow attempt.
    session.cookies = [];

    // Step 1: Initialise the PingOne authentication flow.
    // response_mode=pi.flow returns JSON with a flow ID; redirect: 'manual'
    // prevents fetch from following any 302 PingOne might emit if the flag were
    // absent or misread. Accept: '*/*' is required because the flow API returns
    // a vendor content type (application/vnd.pingidentity.*+json).
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session.cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.status(400).json({ status: 'ERROR', message: `No flowId: ${JSON.stringify(initJson)}` });
    session.flowID = flowID;

    // Step 2: Register the new user.
    // The Content-Type selects the registration operation. PingOne validates the
    // password against the environment's policy before creating the account.
    const regResp = await fetch(`${authPath}/${envID}/flows/${flowID}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.pingidentity.user.register+json',
        'Accept': '*/*',
        'Cookie': cookieHeader(session.cookies),
      },
      body: JSON.stringify({ username, email, password }),
      redirect: 'manual',
    });
    captureCookies(session.cookies, regResp);
    const regJson = await regResp.json();

    if (regJson.status === 'VERIFICATION_CODE_REQUIRED') return res.json({ status: 'VERIFICATION_REQUIRED' });
    if (regJson.status === 'COMPLETED') return res.json({ status: 'COMPLETED' });
    return res.status(400).json({ status: 'ERROR', message: `Unexpected status: ${JSON.stringify(regJson)}` });
  } catch (err) {
    return res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

/**
 * POST /api/verify
 *
 * Submits the email OTP to complete a pending registration.
 *
 * The session's stored flowID and cookies are used to resume the PingOne flow
 * that was started in /api/register. No flow ID or cookie data needs to travel
 * through the browser — the sid cookie is enough to look up the server-side
 * context. If the session has expired (server restart, missing sid) the client
 * receives an error and must start over.
 */
app.post('/api/verify', async (req, res) => {
  try {
    const { code } = req.body;
    const sid = req.cookies.sid;
    const session = sid && sessions.get(sid);
    if (!session || !session.flowID) return res.status(400).json({ status: 'ERROR', message: 'Session expired.' });

    // Content-Type application/vnd.pingidentity.user.verify+json distinguishes
    // this OTP submission from another registration or login attempt on the same
    // flow endpoint.
    const verifyResp = await fetch(`${authPath}/${envID}/flows/${session.flowID}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.pingidentity.user.verify+json',
        'Accept': '*/*',
        'Cookie': cookieHeader(session.cookies),
      },
      body: JSON.stringify({ verificationCode: code }),
      redirect: 'manual',
    });
    captureCookies(session.cookies, verifyResp);
    const verifyJson = await verifyResp.json();

    if (verifyJson.status === 'COMPLETED') return res.json({ status: 'COMPLETED' });
    return res.status(400).json({ status: 'ERROR', message: `Verification failed: ${JSON.stringify(verifyJson)}` });
  } catch (err) {
    return res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

/**
 * POST /api/login
 *
 * Drives the four-step sign-on sub-flow for an existing user.
 *
 * Step 1: Initialise a fresh PingOne flow (independent of any prior registration).
 * Step 2: Validate credentials via usernamePassword.check+json.
 * Step 3: Resume the OAuth 2.0 session via /as/resume?flowId=...
 *   PingOne returns the authorization code either as:
 *   - A JSON body with authorizeResponse.code
 *   - A 302 Location header containing ?code=...
 *   Both are checked. redirect: 'manual' is essential for the latter case —
 *   without it fetch would follow the redirect and we would lose the Location
 *   header containing the code.
 * Step 4: Exchange the code at /as/token using HTTP Basic auth.
 *   The redirect_uri must exactly match both the /as/authorize call above and
 *   the URI registered on the PingOne OIDC application.
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const session = getOrCreateSession(req, res);
    session.cookies = [];

    // Step 1: Initialise a fresh authentication session.
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session.cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.status(400).json({ status: 'ERROR', message: `No flowId: ${JSON.stringify(initJson)}` });
    session.flowID = flowID;

    // Step 2: Validate credentials.
    const loginResp = await fetch(`${authPath}/${envID}/flows/${flowID}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.pingidentity.usernamePassword.check+json',
        'Accept': '*/*',
        'Cookie': cookieHeader(session.cookies),
      },
      body: JSON.stringify({ username, password }),
      redirect: 'manual',
    });
    captureCookies(session.cookies, loginResp);
    const loginJson = await loginResp.json();
    if (loginJson.status !== 'COMPLETED') {
      return res.status(400).json({ status: 'ERROR', message: `Login failed or requires MFA. Status: ${JSON.stringify(loginJson)}` });
    }

    // Step 3: Resume to obtain the authorization code.
    const resumeResp = await fetch(`${authPath}/${envID}/as/resume?flowId=${flowID}`, {
      headers: { Accept: '*/*', Cookie: cookieHeader(session.cookies) },
      redirect: 'manual',
    });
    captureCookies(session.cookies, resumeResp);

    let authCode = '';
    const ct = resumeResp.headers.get('content-type') || '';
    if (ct.includes('json')) {
      const j = await resumeResp.json();
      authCode = j?.authorizeResponse?.code || '';
    }
    if (!authCode) {
      // Standard OIDC redirect: code is a query parameter on the Location URL.
      const loc = resumeResp.headers.get('location');
      if (loc) try { authCode = new URL(loc).searchParams.get('code') || ''; } catch {}
    }
    if (!authCode) return res.status(400).json({ status: 'ERROR', message: 'Failed to get authorization code.' });

    // Step 4: Exchange the code for an access token using HTTP Basic auth.
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
    if (!tokenJson.access_token) return res.status(400).json({ status: 'ERROR', message: `Failed to parse token: ${JSON.stringify(tokenJson)}` });
    return res.json({ status: 'COMPLETED', accessToken: tokenJson.access_token });
  } catch (err) {
    return res.status(500).json({ status: 'ERROR', message: err.message });
  }
});

// Serve the React build in production. The Vite build writes to client/dist.
// In development the Vite dev server (port 5173) proxies /api calls to this
// server, so this static middleware is never hit.
app.use(express.static(path.join(__dirname, '..', 'client', 'dist')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, '..', 'client', 'dist', 'index.html')));

app.listen(3000, () => console.log('Server starting on http://localhost:3000'));
