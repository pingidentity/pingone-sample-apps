require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');

const envID = process.env.PINGONE_ENV_ID;
const clientID = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
const authPath = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');

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

// Session keyed by a browser cookie (`sid`) → { adminToken, cookies[], flowID }.
const sessions = new Map();

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
  if (!json.access_token) throw new Error(`No access_token: ${JSON.stringify(json)}`);
  return json.access_token;
}

function captureCookies(session, resp) {
  const setCookie = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
  for (const raw of setCookie) {
    const nv = raw.split(';')[0];
    const name = nv.split('=')[0];
    const idx = session.cookies.findIndex(c => c.startsWith(`${name}=`));
    if (idx >= 0) session.cookies[idx] = nv;
    else session.cookies.push(nv);
  }
}

const cookieHeader = (s) => s.cookies.join('; ');

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

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const session = getOrCreateSession(req, res);
    session.adminToken = await getAdminToken();
    session.cookies = [];

    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session, initResp);
    const initJson = await initResp.json();
    let flowID = initJson.id;

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
    if (loginJson.id) flowID = loginJson.id;
    session.flowID = flowID;

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

app.post('/api/mfa-verify', async (req, res) => {
  try {
    const { otp } = req.body;
    const sid = req.cookies.sid;
    const session = sid && sessions.get(sid);
    if (!session || !session.flowID) {
      return res.status(400).json({ status: 'ERROR', message: 'Session expired. Please log in again.' });
    }

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

async function finishFlow(session, flowID) {
  const resumeResp = await fetch(`${authPath}/${envID}/as/resume?flowId=${flowID}`, {
    headers: { Accept: '*/*', Cookie: cookieHeader(session) },
    redirect: 'manual',
  });
  captureCookies(session, resumeResp);

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

// Serve the built React app (production).
app.use(express.static(path.join(__dirname, '..', 'client', 'dist')));
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'client', 'dist', 'index.html'));
});

app.listen(3000, async () => {
  try {
    await getAdminToken();
    console.log('Admin token smoke-test passed.');
  } catch (err) {
    console.error('Failed to get admin token at startup:', err.message);
    process.exit(1);
  }
  console.log('MFA Demo backend on http://localhost:3000');
});
