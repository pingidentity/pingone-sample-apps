require('dotenv').config();
const express = require('express');

const envID = process.env.PINGONE_ENV_ID;
const clientID = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
const authPath = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');

if (!envID || !clientID || !clientSecret || !authPath) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// Per-flow cookie store keyed by flowID.
// Holds raw "name=value" cookie strings captured from PingOne responses so we can replay them
// verbatim across requests, bypassing strict RFC 6265 path scoping.
const flowStore = new Map();

function captureCookies(store, resp) {
  const setCookie = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
  for (const raw of setCookie) {
    const nv = raw.split(';')[0];
    const name = nv.split('=')[0];
    const idx = store.findIndex(c => c.startsWith(`${name}=`));
    if (idx >= 0) store[idx] = nv;
    else store.push(nv);
  }
}

const cookieHeader = (store) => store.join('; ');

// --- HTML Templates ---

const indexHTML = `
<!DOCTYPE html>
<html>
<head><title>PingOne Demo</title><style>body{font-family:sans-serif; margin:40px;}</style></head>
<body>
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
</body>
</html>`;

const loginHTML = `
<!DOCTYPE html>
<html>
<head><title>Login</title><style>body{font-family:sans-serif; margin:40px;}</style></head>
<body>
  <h2>Login</h2>
  <form action="/login" method="POST">
    <label>Username:</label><br>
    <input type="text" name="username" required><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>
    <button type="submit">Log In</button>
  </form>
</body>
</html>`;

const verifyHTML = (flowID) => `
<!DOCTYPE html>
<html>
<head><title>Verify Email</title><style>body{font-family:sans-serif; margin:40px;}</style></head>
<body>
  <h2>Check Your Email</h2>
  <p>We've sent a 6-digit verification code to your email address.</p>
  <form action="/verify" method="POST">
    <input type="hidden" name="flowId" value="${flowID}">
    <label>Verification Code:</label><br>
    <input type="text" name="code" required><br><br>
    <button type="submit">Verify &amp; Complete</button>
  </form>
</body>
</html>`;

const successHTML = `
<!DOCTYPE html>
<html>
<head><title>Success!</title><style>body{font-family:sans-serif; margin:40px;}</style></head>
<body>
  <h2 style="color: green;">Registration Complete!</h2>
  <p>Your account has been successfully created and verified via PingOne.</p>
  <a href="/login-page">Click here to Log In</a>
</body>
</html>`;

const dashboardHTML = (token) => `
<!DOCTYPE html>
<html>
<head><title>Dashboard</title><style>body{font-family:sans-serif; margin:40px;} pre{background:#eee; padding:15px;}</style></head>
<body>
  <h2 style="color: blue;">Welcome to your Dashboard!</h2>
  <p>You have successfully authenticated. Here is your Access Token:</p>
  <pre style="white-space: pre-wrap; word-wrap: break-word;">${token}</pre>
  <a href="/">Log Out (Return to Home)</a>
</body>
</html>`;

const errorHTML = (msg) => `
<!DOCTYPE html>
<html>
<head><title>Error</title><style>body{font-family:sans-serif; margin:40px;}</style></head>
<body>
  <h2 style="color: red;">Something went wrong</h2>
  <pre>${msg}</pre>
  <a href="/">Try Again</a>
</body>
</html>`;

// --- Express app ---

const app = express();
app.use(express.urlencoded({ extended: true }));

app.get('/', (_req, res) => res.send(indexHTML));
app.get('/login-page', (_req, res) => res.send(loginHTML));

app.post('/register', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const email = (req.body.email || '').trim();
    const password = req.body.password || '';

    const cookies = [];

    // 1. Initialize flow
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.send(errorHTML(`Failed to retrieve flowId. Response: ${JSON.stringify(initJson)}`));

    // 2. Submit registration
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
    flowStore.set(flowID, cookies);

    if (regJson.status === 'VERIFICATION_CODE_REQUIRED') {
      return res.send(verifyHTML(flowID));
    }
    if (regJson.status === 'COMPLETED') {
      flowStore.delete(flowID);
      return res.send(successHTML);
    }
    return res.send(errorHTML(`Unexpected registration status: ${JSON.stringify(regJson)}`));
  } catch (err) {
    return res.send(errorHTML(err.message));
  }
});

app.post('/verify', async (req, res) => {
  try {
    const flowID = (req.body.flowId || '').trim();
    const code = (req.body.code || '').trim();

    const cookies = flowStore.get(flowID) || [];

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

app.post('/login', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = req.body.password || '';
    const cookies = [];

    // 1. Initialize login flow
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.send(errorHTML(`Failed to retrieve flowId. Response: ${JSON.stringify(initJson)}`));

    // 2. Submit credentials
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

    // 3. Resume to get authorization code
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
      const loc = resumeResp.headers.get('location');
      if (loc) try { authCode = new URL(loc).searchParams.get('code') || ''; } catch {}
    }
    if (!authCode) return res.send(errorHTML('Failed to get authorization code from resume.'));

    // 4. Exchange code for token
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
