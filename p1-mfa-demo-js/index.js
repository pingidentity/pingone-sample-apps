require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');

const logoPNG = fs.readFileSync(path.join(__dirname, '..', 'assets', 'logo.png')).toString('base64');
const logoSrc = `data:image/png;base64,${logoPNG}`;

const envID = process.env.PINGONE_ENV_ID;
const clientID = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
const authPath = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');

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

// In-memory session store, keyed by flowID.
// Holds the admin bearer token and the Set-Cookie values captured from PingOne responses.
const sessionStore = new Map();

async function getAdminToken() {
  const body = new URLSearchParams({ grant_type: 'client_credentials' });
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

// Capture Set-Cookie values from a response into the session.
// Stores raw cookie strings as `name=value` so we can replay them verbatim, bypassing path scoping.
function captureCookies(session, resp) {
  const setCookie = resp.headers.getSetCookie ? resp.headers.getSetCookie() : resp.headers.raw?.()['set-cookie'] || [];
  for (const raw of setCookie) {
    const nameValue = raw.split(';')[0];
    const name = nameValue.split('=')[0];
    const idx = session.cookies.findIndex(c => c.startsWith(`${name}=`));
    if (idx >= 0) session.cookies[idx] = nameValue;
    else session.cookies.push(nameValue);
  }
}

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

app.post('/login', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  try {
    const adminToken = await getAdminToken();
    const session = { adminToken, cookies: [] };

    // 1. Initialize flow
    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session, initResp);
    const initJson = await initResp.json();
    let flowID = initJson.id;
    console.log(`[login] authorize flowID: ${flowID}`);

    // 2. Submit credentials
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

    if (loginJson.id) flowID = loginJson.id;
    sessionStore.set(flowID, session);

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

app.post('/mfa-verify', async (req, res) => {
  let flowID = (req.body.flowId || '').trim();
  const otp = (req.body.otp || '').trim();

  const session = sessionStore.get(flowID);
  if (!session) return res.send(errorHTML('Session expired or lost. Please try logging in again.'));

  try {
    console.log(`[mfa] sending OTP check, flowID=${flowID}`);
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
  try {
    await getAdminToken();
    console.log('Admin token smoke-test passed.');
  } catch (err) {
    console.error('Failed to get admin token at startup:', err.message);
    process.exit(1);
  }
  console.log('MFA Demo starting on http://localhost:3000');
});
