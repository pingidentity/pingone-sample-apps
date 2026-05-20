require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');

const envID = process.env.PINGONE_ENV_ID;
const clientID = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
const authPath = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');

if (!envID || !clientID || !clientSecret || !authPath) {
  console.error('Missing required environment variables.');
  process.exit(1);
}

// sid cookie -> { flowID, cookies[] }
const sessions = new Map();

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

const cookieHeader = (s) => s.join('; ');

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

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const session = getOrCreateSession(req, res);
    session.cookies = [];

    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session.cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.status(400).json({ status: 'ERROR', message: `No flowId: ${JSON.stringify(initJson)}` });
    session.flowID = flowID;

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

app.post('/api/verify', async (req, res) => {
  try {
    const { code } = req.body;
    const sid = req.cookies.sid;
    const session = sid && sessions.get(sid);
    if (!session || !session.flowID) return res.status(400).json({ status: 'ERROR', message: 'Session expired.' });

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

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const session = getOrCreateSession(req, res);
    session.cookies = [];

    const authURL = `${authPath}/${envID}/as/authorize?response_type=code&client_id=${clientID}&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow`;
    const initResp = await fetch(authURL, { headers: { Accept: '*/*' }, redirect: 'manual' });
    captureCookies(session.cookies, initResp);
    const initJson = await initResp.json();
    const flowID = initJson.id;
    if (!flowID) return res.status(400).json({ status: 'ERROR', message: `No flowId: ${JSON.stringify(initJson)}` });
    session.flowID = flowID;

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

// Angular CLI builds to client/dist/<project>/browser — point this at that folder after `ng build`.
const angularDist = path.join(__dirname, '..', 'client', 'dist', 'p1-user-registration-angular', 'browser');
app.use(express.static(angularDist));
app.get('*', (_req, res) => res.sendFile(path.join(angularDist, 'index.html')));

app.listen(3000, () => console.log('Server starting on http://localhost:3000'));
