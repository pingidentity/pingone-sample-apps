/**
 * PingOne User Registration — Node.js / Express implementation
 *
 * This app demonstrates self-service user registration against the PingOne
 * native authentication API, followed by a standard OIDC sign-on flow for the
 * newly created user.
 *
 * How registration differs from sign-on
 * --------------------------------------
 * A typical sign-on flow authenticates a user who already exists in PingOne's
 * directory and ends with an OAuth 2.0 authorization code that can be exchanged
 * for tokens. Registration is a pre-authentication step: it creates the user
 * account first. No admin worker app token is required here — the same OIDC
 * application that drives sign-on can also accept registrations through the
 * native flow API, so a single set of credentials (PINGONE_CLIENT_ID /
 * PINGONE_CLIENT_SECRET) covers the entire workflow.
 *
 * Registration sub-flow (2–3 steps):
 *  1. GET  /as/authorize?response_mode=pi.flow
 *     Initialises a PingOne authentication session. response_mode=pi.flow
 *     makes PingOne return a JSON body containing a flow ID instead of
 *     redirecting the browser. The response also sets session cookies that
 *     must be replayed on every subsequent call to this flow.
 *  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.user.register+json
 *     Creates the new user. PingOne either completes immediately
 *     (status=COMPLETED) or — if the environment has email verification
 *     enabled — returns status=VERIFICATION_CODE_REQUIRED and emails a 6-digit
 *     OTP to the address supplied in the request body.
 *  3. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.user.verify+json
 *     (Only when step 2 required verification.) Submits the OTP. A
 *     status=COMPLETED response means the account is active.
 *
 * Sign-on sub-flow (4 steps):
 *  1. GET  /as/authorize?response_mode=pi.flow  (fresh session, no relation to registration)
 *  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.usernamePassword.check+json
 *     Validates credentials.  status=COMPLETED means authentication passed.
 *  3. GET  /as/resume?flowId={flowID}
 *     Bridges the native flow back to the OAuth 2.0 layer. PingOne either
 *     issues a 302 redirect with ?code=... or returns JSON with
 *     authorizeResponse.code. Both cases are handled.
 *  4. POST /as/token  — standard authorization_code token exchange.
 *
 * Cookie handling
 * ---------------
 * PingOne sets session cookies (ST, ST-NO-SS) on the initial /as/authorize
 * response. All subsequent requests to the same flow must replay those cookies
 * verbatim. The Node.js fetch API does not manage cookies automatically, so
 * this file captures them from Set-Cookie headers and sends them manually via
 * the Cookie header on every flow request.
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');

// Embed the logo as a base64 data URI so the single-file server doesn't need
// to serve a separate static asset route.
const logoPNG = fs.readFileSync(path.join(__dirname, '..', 'assets', 'logo.png')).toString('base64');
const logoSrc = `data:image/png;base64,${logoPNG}`;

const envID = process.env.PINGONE_ENV_ID;
const clientID = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
// Trailing slash stripped to avoid double-slash in URL construction below.
const authPath = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');

if (!envID || !clientID || !clientSecret || !authPath) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

/**
 * Per-flow cookie store keyed by PingOne flow ID.
 *
 * When a registration begins, /as/authorize sets session cookies that PingOne
 * uses to correlate all subsequent requests to the same flow. If the user must
 * verify their email, the OTP arrives on a separate HTTP request — potentially
 * seconds later. The store preserves the cookies between the /register and
 * /verify handlers. Entries are deleted once the flow reaches COMPLETED.
 */
const flowStore = new Map();

/**
 * captureCookies extracts the name=value pair from each Set-Cookie header in
 * resp and upserts it into the store array. Upsert (replace if the name already
 * exists) is important because PingOne refreshes its session cookie values on
 * every response — replaying a stale value causes a 401 on the next request.
 *
 * @param {string[]} store  - mutable cookie array, modified in place
 * @param {Response} resp   - fetch Response whose Set-Cookie headers to capture
 */
function captureCookies(store, resp) {
  // resp.headers.getSetCookie() returns all Set-Cookie headers as an array,
  // available in Node 18+. Each entry has the full directive string, e.g.
  // "ST=abc123; Path=/; HttpOnly". We only need the name=value portion.
  const setCookie = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
  for (const raw of setCookie) {
    const nv = raw.split(';')[0];          // strip directives (Path, HttpOnly …)
    const name = nv.split('=')[0];
    const idx = store.findIndex(c => c.startsWith(`${name}=`));
    if (idx >= 0) store[idx] = nv;         // update existing entry
    else store.push(nv);                    // add new entry
  }
}

/**
 * cookieHeader joins the raw "name=value" strings in store into a single
 * Cookie header value suitable for sending on the next PingOne request.
 *
 * Assembling the header manually (rather than using a cookie jar) bypasses
 * RFC 6265 path-scoping rules that would silently drop cookies whose recorded
 * path doesn't match the current request path.
 *
 * @param {string[]} store
 * @returns {string}
 */
const cookieHeader = (store) => store.join('; ');

// --- HTML Templates ---

const indexHTML = `
<!DOCTYPE html>
<html>
<head><title>PingOne Demo</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:15px; padding:10px 20px; cursor:pointer;} button:hover{background:#c40034;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Sign Up</h2>
  <form action="/register" method="POST">
    <label>Username:</label><br>
    <input type="text" name="username" required><br><br>
    <label>Email:</label><br>
    <input type="email" name="email" required><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>
    <button type="submit">Register</button>
  </form>
  <br><hr><br>
  <p>Already have an account? <a href="/login-page">Log in here</a></p>
</div>
</body>
</html>`;

const loginHTML = `
<!DOCTYPE html>
<html>
<head><title>Login</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:15px; padding:10px 20px; cursor:pointer;} button:hover{background:#c40034;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Login</h2>
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

// verifyHTML is a function so the hidden flowId field can be interpolated at
// request time — the ID is not known until /as/authorize responds.
const verifyHTML = (flowID) => `
<!DOCTYPE html>
<html>
<head><title>Verify Email</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:15px; padding:10px 20px; cursor:pointer;} button:hover{background:#c40034;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Check Your Email</h2>
  <p>We've sent a 6-digit verification code to your email address.</p>
  <form action="/verify" method="POST">
    <input type="hidden" name="flowId" value="${flowID}">
    <label>Verification Code:</label><br>
    <input type="text" name="code" required><br><br>
    <button type="submit">Verify &amp; Complete</button>
  </form>
</div>
</body>
</html>`;

const successHTML = `
<!DOCTYPE html>
<html>
<head><title>Success!</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2 style="color:#0a7a0a;">Registration Complete!</h2>
  <p>Your account has been successfully created and verified via PingOne.</p>
  <a href="/login-page">Click here to Log In</a>
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
  <h2>Welcome to your Dashboard!</h2>
  <p>You have successfully authenticated. Here is your Access Token:</p>
  <pre style="white-space: pre-wrap; word-wrap: break-word;">${token}</pre>
  <a href="/">Log Out (Return to Home)</a>
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
  <h2 style="color:#b00020;">Something went wrong</h2>
  <pre>${msg}</pre>
  <a href="/">Try Again</a>
</div>
</body>
</html>`;

// --- Express app ---

const app = express();
// express.urlencoded is required to parse HTML form bodies (application/x-www-form-urlencoded)
// submitted by the registration and login forms.
app.use(express.urlencoded({ extended: true }));

app.get('/', (_req, res) => res.send(indexHTML));
app.get('/login-page', (_req, res) => res.send(loginHTML));

/**
 * POST /register — drives the PingOne registration sub-flow.
 *
 * Step 1: Initialise the flow via GET /as/authorize?response_mode=pi.flow.
 *   - redirect: 'manual' prevents fetch from following the 302 that PingOne
 *     would issue if the client didn't set response_mode=pi.flow. With the flag
 *     set, PingOne returns a JSON body with a flow ID instead.
 *   - Accept: '*\/*' is required; the flow API returns a vendor content type
 *     that would be rejected if Accept were set to application/json only.
 *
 * Step 2: Submit the new user's details to /flows/{flowID} with the register
 *   content type. The response status field indicates what happens next:
 *   - VERIFICATION_CODE_REQUIRED: email OTP was sent; render the OTP form.
 *   - COMPLETED: no verification configured; account is live immediately.
 */
app.post('/register', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const email = (req.body.email || '').trim();
    const password = req.body.password || '';

    const cookies = [];

    // Step 1: Initialise the PingOne authentication flow.
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.send(errorHTML(`Failed to retrieve flowId. Response: ${JSON.stringify(initJson)}`));

    // Step 2: Register the new user.
    // The Content-Type header selects the registration operation on the flow.
    // The body must include at minimum username, email, and password. PingOne
    // validates the password against the environment's password policy before
    // creating the account.
    const regResp = await fetch(`${authPath}/${envID}/flows/${flowID}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.pingidentity.user.register+json',
        'Accept': '*/*',
        'Cookie': cookieHeader(cookies),
      },
      body: JSON.stringify({ username, email, password }),
      redirect: 'manual',
    });
    captureCookies(cookies, regResp);
    const regJson = await regResp.json();

    // Save the in-progress flow cookies so the /verify handler can resume the
    // same PingOne session when the user submits their OTP.
    flowStore.set(flowID, cookies);

    if (regJson.status === 'VERIFICATION_CODE_REQUIRED') {
      // Email verification is enabled; the OTP has been sent. Render the form.
      return res.send(verifyHTML(flowID));
    }
    if (regJson.status === 'COMPLETED') {
      // No verification required — account is live.
      flowStore.delete(flowID);
      return res.send(successHTML);
    }
    return res.send(errorHTML(`Unexpected registration status: ${JSON.stringify(regJson)}`));
  } catch (err) {
    return res.send(errorHTML(err.message));
  }
});

/**
 * POST /verify — submits the email OTP to complete the registration flow.
 *
 * The flowId hidden field in the OTP form was embedded by the /register handler.
 * It is used to look up the saved PingOne session cookies so this request is
 * associated with the same active flow. Without those cookies PingOne cannot
 * recognise this request as belonging to the pending registration.
 */
app.post('/verify', async (req, res) => {
  try {
    const flowID = (req.body.flowId || '').trim();
    const code = (req.body.code || '').trim();

    // Retrieve the cookies stored during the registration step.
    const cookies = flowStore.get(flowID) || [];

    // Content-Type application/vnd.pingidentity.user.verify+json tells PingOne
    // this POST carries an OTP, not another registration attempt.
    const verifyResp = await fetch(`${authPath}/${envID}/flows/${flowID}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.pingidentity.user.verify+json',
        'Accept': '*/*',
        'Cookie': cookieHeader(cookies),
      },
      body: JSON.stringify({ verificationCode: code }),
      redirect: 'manual',
    });
    captureCookies(cookies, verifyResp);
    const verifyJson = await verifyResp.json();

    if (verifyJson.status === 'COMPLETED') {
      flowStore.delete(flowID);
      return res.send(successHTML);
    }
    return res.send(errorHTML(`Verification failed. Response: ${JSON.stringify(verifyJson)}`));
  } catch (err) {
    return res.send(errorHTML(err.message));
  }
});

/**
 * POST /login — drives the PingOne sign-on sub-flow for an existing user.
 *
 * Step 1: Initialise a fresh authentication flow (same /as/authorize call as
 *   registration, but for a new session with no prior state).
 *
 * Step 2: Validate credentials via POST /flows/{flowID} with the
 *   usernamePassword.check content type. status=COMPLETED means PingOne
 *   accepted the credentials and considers the user authenticated.
 *
 * Step 3: Resume the OAuth 2.0 session via GET /as/resume?flowId=...
 *   PingOne returns the authorization code in one of two ways:
 *   - As a 302 Location header:  ?code=<value>  (standard OIDC redirect)
 *   - As a JSON body:  { authorizeResponse: { code: "<value>" } }
 *   Both cases are checked so the app works in any PingOne configuration.
 *
 * Step 4: Exchange the code for tokens at POST /as/token using HTTP Basic
 *   auth (clientID:clientSecret base64-encoded in the Authorization header).
 *   The redirect_uri must exactly match both the authorize call and the value
 *   registered on the PingOne application.
 */
app.post('/login', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';
    const cookies = [];

    // Step 1: Initialise a fresh authentication session.
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.send(errorHTML(`Failed to retrieve flowId. Response: ${JSON.stringify(initJson)}`));

    // Step 2: Validate the user's credentials.
    const loginResp = await fetch(`${authPath}/${envID}/flows/${flowID}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.pingidentity.usernamePassword.check+json',
        'Accept': '*/*',
        'Cookie': cookieHeader(cookies),
      },
      body: JSON.stringify({ username, password }),
      redirect: 'manual',
    });
    captureCookies(cookies, loginResp);
    const loginJson = await loginResp.json();

    if (loginJson.status !== 'COMPLETED') {
      return res.send(errorHTML(`Login failed or requires MFA. Status: ${JSON.stringify(loginJson)}`));
    }

    // Step 3: Resume to get the authorization code.
    // redirect: 'manual' is critical here — the code is in the Location header
    // of the 302 response and would be lost if fetch followed the redirect.
    const resumeResp = await fetch(`${authPath}/${envID}/as/resume?flowId=${flowID}`, {
      headers: { Accept: '*/*', Cookie: cookieHeader(cookies) },
      redirect: 'manual',
    });
    captureCookies(cookies, resumeResp);

    let authCode = '';
    const ct = resumeResp.headers.get('content-type') || '';
    if (ct.includes('json')) {
      const j = await resumeResp.json();
      authCode = j?.authorizeResponse?.code || '';
    }
    if (!authCode) {
      // Fall back to the Location header (standard OIDC redirect case).
      const loc = resumeResp.headers.get('location');
      if (loc) try { authCode = new URL(loc).searchParams.get('code') || ''; } catch {}
    }
    if (!authCode) return res.send(errorHTML('Failed to get authorization code from resume.'));

    // Step 4: Exchange the code for an access token.
    // base64-encode clientID:clientSecret for HTTP Basic (CLIENT_SECRET_BASIC).
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
    if (!tokenJson.access_token) return res.send(errorHTML(`Failed to parse access token. Output: ${JSON.stringify(tokenJson)}`));

    return res.send(dashboardHTML(tokenJson.access_token));
  } catch (err) {
    return res.send(errorHTML(err.message));
  }
});

app.listen(3000, () => console.log('Server starting on http://localhost:3000'));
