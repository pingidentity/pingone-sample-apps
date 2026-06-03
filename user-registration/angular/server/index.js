/**
 * PingOne User Registration — Angular backend (Express)
 *
 * This server is the Angular-flavoured counterpart of the React backend
 * (p1-user-registration-react/server/index.js). The PingOne flow logic is
 * identical; the only structural difference is that the Angular CLI build
 * writes to a nested browser/ subdirectory, so the static-file path differs.
 *
 * How registration differs from sign-on
 * --------------------------------------
 * Registration creates a new user account in PingOne via the native flow API.
 * No admin worker app is required — the same OIDC application credentials
 * (PINGONE_CLIENT_ID / PINGONE_CLIENT_SECRET) serve both registration and the
 * subsequent sign-on flow. This is distinct from management-API workflows where
 * a separate admin worker app with client_credentials is needed.
 *
 * API surface exposed to the Angular client:
 *   POST /api/register  — starts a flow, registers the user
 *                         Returns { status: 'VERIFICATION_REQUIRED' | 'COMPLETED' | 'ERROR' }
 *   POST /api/verify    — submits the email OTP
 *                         Returns { status: 'COMPLETED' | 'ERROR' }
 *   POST /api/login     — signs an existing user in
 *                         Returns { status: 'COMPLETED', accessToken } | { status: 'ERROR' }
 *
 * Registration sub-flow (2–3 steps):
 *  1. GET  /as/authorize?response_mode=pi.flow
 *     Starts a PingOne authentication session and returns a JSON body with a
 *     flow ID. The response sets session cookies that must be replayed on every
 *     subsequent call to the same flow.
 *  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.user.register+json
 *     Creates the user. status=COMPLETED means the account is live. Status
 *     VERIFICATION_CODE_REQUIRED means PingOne emailed a 6-digit OTP.
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
 * holds a Map from sid -> { flowID, cookies[] }. Storing state server-side means
 * neither the flow ID nor PingOne session cookies are ever exposed to the browser.
 *
 * Cookie handling
 * ---------------
 * PingOne session cookies (ST, ST-NO-SS) must be replayed verbatim on every flow
 * request. The Node.js fetch API does not manage cookies automatically, so this
 * file captures them from Set-Cookie headers and sends them manually. The sid
 * session associates the cookies with the correct browser tab across the
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
 * flowID is the PingOne flow identifier from /as/authorize. It persists
 * between /api/register and /api/verify so the client never handles it.
 *
 * cookies is the set of PingOne session cookies captured from flow responses.
 * They must be replayed on every subsequent flow request.
 */
const sessions = new Map();

/**
 * captureCookies extracts the name=value pair from each Set-Cookie header in
 * resp and upserts it into the store array. Upserting (replacing if the name
 * already exists) prevents stale PingOne session cookie values from causing 401
 * errors on subsequent requests.
 *
 * @param {string[]} store  - mutable cookie array, modified in place
 * @param {Response} resp   - fetch Response whose Set-Cookie headers to capture
 */
function captureCookies(store, resp) {
  // getSetCookie() is available in Node 18+. Each Set-Cookie string looks like
  // "ST=abc123; Path=/; HttpOnly". We only need the "name=value" portion.
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
 * cookieHeader joins stored "name=value" strings into a single Cookie header.
 * Assembling manually bypasses RFC 6265 path-scoping that would silently drop
 * cookies when the request path doesn't match the path they were set on.
 */
const cookieHeader = (s) => s.join('; ');

/**
 * getOrCreateSession ensures every request has a server-side session and a
 * matching sid cookie in the browser. httpOnly prevents JavaScript from reading
 * the sid; sameSite=lax mitigates CSRF on the POST endpoints.
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
 * Returns { status: 'VERIFICATION_REQUIRED' | 'COMPLETED' | 'ERROR' }.
 * The Angular client switches its view based on the status field.
 *
 * PingOne flow cookies and the flow ID are saved in the server-side session
 * so /api/verify can resume the same flow without the client transmitting them.
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const session = getOrCreateSession(req, res);
    // Reset cookies from any prior flow attempt on this session.
    session.cookies = [];

    // Step 1: Initialise the PingOne authentication flow.
    // response_mode=pi.flow → JSON body with flow ID (no browser redirect).
    // redirect: 'manual' → don't follow any 302 PingOne might emit.
    // Accept: '*/*' → required; the flow API uses vendor content types.
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session.cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.status(400).json({ status: 'ERROR', message: `No flowId: ${JSON.stringify(initJson)}` });
    session.flowID = flowID;

    // Step 2: Register the new user.
    // The Content-Type selects the registration operation on the flow.
    // PingOne validates the password against the environment's policy before
    // creating the account.
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
 * The server-side session (via the sid cookie) supplies both the flow ID and
 * the PingOne session cookies — no flow state is stored in the browser. If the
 * session has expired (server restart, missing sid) the client must restart.
 */
app.post('/api/verify', async (req, res) => {
  try {
    const { code } = req.body;
    const sid = req.cookies.sid;
    const session = sid && sessions.get(sid);
    if (!session || !session.flowID) return res.status(400).json({ status: 'ERROR', message: 'Session expired.' });

    // Content-Type application/vnd.pingidentity.user.verify+json tells PingOne
    // this is an OTP submission, not a new registration or login attempt.
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
 * Step 3: Resume the OAuth 2.0 session via GET /as/resume?flowId=...
 *   PingOne returns the authorization code as either:
 *   - A JSON body field: authorizeResponse.code
 *   - A 302 Location header: ?code=<value>
 *   redirect: 'manual' is critical so the Location header is not silently
 *   consumed by fetch before we can read the code from it.
 * Step 4: Exchange the code at /as/token.
 *   HTTP Basic auth (clientID:clientSecret) is the CLIENT_SECRET_BASIC method.
 *   The redirect_uri must exactly match both the authorize call and the PingOne
 *   application configuration.
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
      const loc = resumeResp.headers.get('location');
      if (loc) try { authCode = new URL(loc).searchParams.get('code') || ''; } catch {}
    }
    if (!authCode) return res.status(400).json({ status: 'ERROR', message: 'Failed to get authorization code.' });

    // Step 4: Exchange the code for an access token.
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

// Angular CLI builds to client/dist/<project>/browser — the extra browser/
// subdirectory is an Angular 17+ convention (separate browser and server bundles).
// Point this at that folder after running `ng build` in the client directory.
const angularDist = path.join(__dirname, '..', 'client', 'dist', 'p1-user-registration-angular', 'browser');
app.use(express.static(angularDist));
app.get('*', (_req, res) => res.sendFile(path.join(angularDist, 'index.html')));

app.listen(3000, () => console.log('Server starting on http://localhost:3000'));
