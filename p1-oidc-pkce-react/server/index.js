import 'dotenv/config';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import express from 'express';
import cookieParser from 'cookie-parser';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const envID        = process.env.PINGONE_ENV_ID;
const clientID     = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
const authPath     = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');
const redirectURI  = process.env.PINGONE_REDIRECT_URI;
const scopes       = process.env.PINGONE_SCOPES;

if (!envID || !clientID || !clientSecret || !authPath || !redirectURI || !scopes) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// --- Session store ---
// Map<sid, session>
const sessions = new Map();

function getSession(req) {
  const sid = req.cookies && req.cookies.sid;
  if (!sid) return null;
  return sessions.get(sid) || null;
}

function getOrCreateSession(req, res) {
  const sid = req.cookies && req.cookies.sid;
  if (sid && sessions.has(sid)) {
    return sessions.get(sid);
  }
  const newSid = crypto.randomBytes(16).toString('hex');
  const session = {
    verifier: '',
    challenge: '',
    state: '',
    nonce: '',
    accessToken: '',
    idToken: '',
    refreshToken: '',
    hasRefreshToken: false,
    prepareCards: [],
    callbackCards: [],
  };
  sessions.set(newSid, session);
  res.cookie('sid', newSid, { httpOnly: true, sameSite: 'lax', path: '/' });
  return session;
}

// --- Crypto / JWT helpers ---

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function decodeJWT(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error(`Not a 3-part JWT: got ${parts.length} parts`);
  const headerBuf  = Buffer.from(parts[0], 'base64url');
  const payloadBuf = Buffer.from(parts[1], 'base64url');
  const header  = JSON.parse(headerBuf.toString('utf8'));
  const payload = JSON.parse(payloadBuf.toString('utf8'));
  return { header, payload };
}

function verifyJWS(token, header, jwks) {
  const alg = header.alg;
  const kid = header.kid;
  if (alg !== 'RS256') {
    throw new Error(`Unsupported alg "${alg}" (this sample verifies RS256 only)`);
  }
  const keys = (jwks && jwks.keys) || [];
  const match = keys.find(k => k.kid === kid);
  if (!match) throw new Error(`No JWK with kid="${kid}"`);

  const pubKey = crypto.createPublicKey({ key: match, format: 'jwk' });
  const parts = token.split('.');
  const signedInput = `${parts[0]}.${parts[1]}`;
  const sig = Buffer.from(parts[2], 'base64url');

  const verifier = crypto.createVerify('SHA256');
  verifier.update(signedInput);
  const ok = verifier.verify(pubKey, sig);
  if (!ok) throw new Error('Signature verification failed');
}

function validateIDClaims(payload, expectedIssuer, expectedAud, expectedNonce) {
  const errs = {};
  if (payload.iss !== expectedIssuer) {
    errs.iss = `got "${payload.iss}", want "${expectedIssuer}"`;
  }
  const aud = payload.aud;
  const audOK = aud === expectedAud ||
    (Array.isArray(aud) && aud.includes(expectedAud));
  if (!audOK) {
    errs.aud = `does not contain "${expectedAud}"`;
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number') {
    if (payload.exp < now) {
      errs.exp = `expired (exp=${payload.exp}, now=${now})`;
    }
  } else {
    errs.exp = 'missing or non-numeric';
  }
  if (typeof payload.iat === 'number') {
    if (payload.iat > now + 60) {
      errs.iat = `in the future (iat=${payload.iat}, now=${now})`;
    }
  }
  if (payload.nonce !== expectedNonce) {
    errs.nonce = `got "${payload.nonce}", want "${expectedNonce}"`;
  }
  return errs;
}

function prettyJSON(obj) {
  return JSON.stringify(obj, null, 2);
}

function prettyJSONOrRaw(str) {
  try {
    return prettyJSON(JSON.parse(str));
  } catch {
    return str;
  }
}

function renderClaimChecks(errs) {
  if (Object.keys(errs).length === 0) {
    return '<span style="color:#0a7a0a;">All claims valid.</span>';
  }
  const items = Object.entries(errs)
    .map(([k, v]) => `<li><code>${escapeHTML(k)}</code>: ${escapeHTML(v)}</li>`)
    .join('');
  return `<ul style="color:#b00020;">${items}</ul>`;
}

// --- Express app ---

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// POST /api/prepare
app.post('/api/prepare', (req, res) => {
  const session = getOrCreateSession(req, res);

  // Reset session state
  session.verifier = '';
  session.challenge = '';
  session.state = '';
  session.nonce = '';
  session.accessToken = '';
  session.idToken = '';
  session.refreshToken = '';
  session.hasRefreshToken = false;
  session.prepareCards = [];
  session.callbackCards = [];

  // 1. code_verifier — RFC 7636: base64url-no-pad of 32 random bytes → 43 chars
  const verifierBytes = crypto.randomBytes(32);
  const verifier = verifierBytes.toString('base64url');

  // 2. code_challenge = base64url-no-pad(SHA-256(ASCII(code_verifier)))
  const hashBuf   = crypto.createHash('sha256').update(verifier).digest();
  const challenge = hashBuf.toString('base64url');
  const hashHex   = hashBuf.toString('hex');

  // 3. state + nonce
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  // Store in session
  session.verifier  = verifier;
  session.challenge = challenge;
  session.state     = state;
  session.nonce     = nonce;

  // 4. Build /authorize URL
  const authorizeURL = `${authPath}/${envID}/as/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(clientID)}` +
    `&redirect_uri=${encodeURIComponent(redirectURI)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&state=${encodeURIComponent(state)}` +
    `&nonce=${encodeURIComponent(nonce)}` +
    `&code_challenge=${encodeURIComponent(challenge)}` +
    `&code_challenge_method=S256`;

  const prepareCards = [
    {
      title: '1. Generate code_verifier',
      ok: true,
      url: null,
      detail: `Random ${verifierBytes.length} bytes → <code>base64url</code>-no-pad → ${verifier.length}-char verifier. RFC 7636 §4.1 allows 43-128 chars from the unreserved set <code>[A-Za-z0-9-._~]</code>; base64url output naturally falls in that set.`,
      body: verifier,
      collapsed: false,
    },
    {
      title: '2. Compute code_challenge',
      ok: true,
      url: null,
      detail: '<code>code_challenge = base64url-no-pad( SHA-256( ASCII(code_verifier) ) )</code><br><code>code_challenge_method = S256</code>',
      body: `SHA-256 digest (hex):\n  ${hashHex}\n\nbase64url-no-pad encoding:\n  ${challenge}`,
      collapsed: false,
    },
    {
      title: '3. Generate state and nonce',
      ok: true,
      url: null,
      detail: 'Both are random opaque strings: <code>state</code> defends the callback from CSRF; <code>nonce</code> is echoed back as a claim in the ID token to defend against replay.',
      body: `state: ${state}\nnonce: ${nonce}`,
      collapsed: false,
    },
    {
      title: '4. Build /authorize URL',
      ok: true,
      url: 'GET ' + authorizeURL,
      detail: `Click the button below to redirect to PingOne. After you authenticate, PingOne will 302 back to <code>${escapeHTML(redirectURI)}</code> with a <code>code</code> and the original <code>state</code>.`,
      body: null,
      collapsed: false,
    },
  ];

  session.prepareCards = prepareCards;

  res.json({ prepareCards, authorizeURL });
});

// GET /callback — OAuth redirect from PingOne
app.get('/callback', async (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.redirect('/?error=nosession');
  }

  const { code: gotCode, state: gotState, error: gotErr, error_description: gotErrDesc } = req.query;
  const callbackCards = [];

  if (gotErr) {
    callbackCards.push({
      title: 'Callback received an error',
      ok: false,
      url: null,
      detail: `<code>error=${escapeHTML(gotErr)}</code><br><code>error_description=${escapeHTML(gotErrDesc || '')}</code>`,
      body: req.url,
      collapsed: false,
    });
    session.callbackCards = callbackCards;
    return res.redirect('/?callbackError=1');
  }

  // 1. Receive callback
  const rawQuery = new URLSearchParams(req.query).toString();
  callbackCards.push({
    title: '1. Receive callback',
    ok: true,
    url: `GET ${redirectURI}?${rawQuery}`,
    detail: 'PingOne redirected the browser back with <code>code</code> and <code>state</code>. The <code>code</code> is single-use and short-lived.',
    body: `code:  ${gotCode}\nstate: ${gotState}`,
    collapsed: false,
  });

  // 2. Validate state
  const stateOK = gotState === session.state;
  callbackCards.push({
    title: '2. Validate state',
    ok: stateOK,
    url: null,
    detail: `Stored state: <code>${escapeHTML(session.state)}</code><br>Returned state: <code>${escapeHTML(gotState || '')}</code><br>${stateOK ? 'Match — request is authentic.' : '<strong>Mismatch — abort.</strong>'}`,
    body: null,
    collapsed: false,
  });

  if (!stateOK) {
    session.callbackCards = callbackCards;
    return res.redirect('/?callbackError=1');
  }

  // 3. Token exchange
  const tokenURL = `${authPath}/${envID}/as/token`;
  const basic = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code: gotCode,
    redirect_uri: redirectURI,
    code_verifier: session.verifier,
  });

  let tokParsed = null;
  let tokRaw = '';
  let tokStatus = 0;
  let tokErr = null;

  try {
    const tokResp = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basic}`,
      },
      body: tokenBody,
    });
    tokStatus = tokResp.status;
    tokRaw = await tokResp.text();
    try { tokParsed = JSON.parse(tokRaw); } catch {}
  } catch (e) {
    tokErr = e;
  }

  callbackCards.push({
    title: '3. Exchange code for tokens',
    ok: tokErr === null && tokStatus < 400,
    url: `POST ${tokenURL}`,
    detail: `Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>Form body:<br>&nbsp;&nbsp;<code>grant_type=authorization_code</code><br>&nbsp;&nbsp;<code>code=${escapeHTML(gotCode || '')}</code><br>&nbsp;&nbsp;<code>redirect_uri=${escapeHTML(redirectURI)}</code><br>&nbsp;&nbsp;<strong><code>code_verifier=${escapeHTML(session.verifier)}</code></strong> ← PingOne re-hashes this and compares to the original code_challenge<br>HTTP ${tokStatus}`,
    body: prettyJSONOrRaw(tokRaw),
    collapsed: false,
  });

  if (tokErr !== null || tokStatus >= 400) {
    session.callbackCards = callbackCards;
    return res.redirect('/?callbackError=1');
  }

  const idToken      = (tokParsed && tokParsed.id_token)      || '';
  const accessToken  = (tokParsed && tokParsed.access_token)  || '';
  const refreshToken = (tokParsed && tokParsed.refresh_token) || '';
  session.accessToken  = accessToken;
  session.idToken      = idToken;
  session.refreshToken = refreshToken;

  // 4. Decode ID token
  let jwtHeader = null;
  let jwtPayload = null;
  let decodeErr = null;
  try {
    const decoded = decodeJWT(idToken);
    jwtHeader  = decoded.header;
    jwtPayload = decoded.payload;
  } catch (e) {
    decodeErr = e;
  }

  callbackCards.push({
    title: '4. Decode ID token',
    ok: decodeErr === null,
    url: null,
    detail: 'An ID token is a JWS: three base64url segments separated by dots. The header tells us which key to use; the payload contains the claims; the signature must be verified before any claim is trusted.',
    body: decodeErr
      ? `Error: ${decodeErr.message}`
      : `header:\n${prettyJSON(jwtHeader)}\n\npayload:\n${prettyJSON(jwtPayload)}`,
    collapsed: false,
  });

  // 5. Fetch JWKS
  const jwksURL = `${authPath}/${envID}/as/jwks`;
  let jwks = null;
  let jwksRaw = '';
  let jwksErr = null;

  try {
    const jwksResp = await fetch(jwksURL);
    jwksRaw = await jwksResp.text();
    try { jwks = JSON.parse(jwksRaw); } catch {}
  } catch (e) {
    jwksErr = e;
  }

  callbackCards.push({
    title: '5. Fetch JWKS',
    ok: jwksErr === null,
    url: `GET ${jwksURL}`,
    detail: 'Public keys used to verify ID token signatures. Keyed by <code>kid</code>; cache with care in production.',
    body: prettyJSONOrRaw(jwksRaw),
    collapsed: true,
  });

  // 6. Verify ID token signature
  let sigErr = null;
  try {
    verifyJWS(idToken, jwtHeader || {}, jwks || {});
  } catch (e) {
    sigErr = e;
  }

  callbackCards.push({
    title: '6. Verify ID token signature',
    ok: sigErr === null,
    url: null,
    detail: `alg: <code>${escapeHTML(String((jwtHeader && jwtHeader.alg) || ''))}</code>, kid: <code>${escapeHTML(String((jwtHeader && jwtHeader.kid) || ''))}</code><br>${sigErr === null ? 'Signature valid (RS256, key matched by <code>kid</code>).' : `Signature INVALID: ${escapeHTML(sigErr.message)}`}`,
    body: null,
    collapsed: false,
  });

  // 7. Validate ID token claims
  const expectedIssuer = `${authPath}/${envID}/as`;
  const claimsErrs = jwtPayload
    ? validateIDClaims(jwtPayload, expectedIssuer, clientID, session.nonce)
    : { decode: 'Could not decode ID token payload' };

  callbackCards.push({
    title: '7. Validate ID token claims',
    ok: Object.keys(claimsErrs).length === 0,
    url: null,
    detail: `Required checks: <code>iss</code> matches <code>${escapeHTML(expectedIssuer)}</code>, <code>aud</code> contains <code>${escapeHTML(clientID)}</code>, <code>exp</code> &gt; now, <code>iat</code> not in the future, <code>nonce</code> matches the value sent on /authorize.<br>${renderClaimChecks(claimsErrs)}`,
    body: jwtPayload ? prettyJSON(jwtPayload) : null,
    collapsed: false,
  });

  // 8. /userinfo
  const userinfoURL = `${authPath}/${envID}/as/userinfo`;
  let uiRaw = '';
  let uiStatus = 0;
  let uiErr = null;

  try {
    const uiResp = await fetch(userinfoURL, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    uiStatus = uiResp.status;
    uiRaw = await uiResp.text();
  } catch (e) {
    uiErr = e;
  }

  callbackCards.push({
    title: '8. Call /userinfo',
    ok: uiErr === null && uiStatus < 400,
    url: `GET ${userinfoURL}`,
    detail: `Header: <code>Authorization: Bearer &lt;access_token&gt;</code><br>HTTP ${uiStatus}`,
    body: prettyJSONOrRaw(uiRaw),
    collapsed: false,
  });

  // 9. Final tokens
  callbackCards.push({
    title: '9. Tokens',
    ok: true,
    url: null,
    detail: 'These are the final values returned by the token endpoint.',
    body: `access_token:\n${accessToken}\n\nid_token:\n${idToken}\n\nrefresh_token:\n${refreshToken}`,
    collapsed: true,
  });

  session.callbackCards    = callbackCards;
  session.hasRefreshToken  = !!refreshToken;

  res.redirect('/?callbackDone=1');
});

// GET /api/callback-result
app.get('/api/callback-result', (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.status(400).json({ error: 'No session' });
  }
  res.json({
    prepareCards:    session.prepareCards  || [],
    callbackCards:   session.callbackCards || [],
    hasRefreshToken: !!session.refreshToken,
  });
});

// POST /api/refresh
app.post('/api/refresh', async (req, res) => {
  const session = getSession(req);
  if (!session || !session.refreshToken) {
    return res.status(400).json({ error: 'No refresh token in session' });
  }

  const tokenURL = `${authPath}/${envID}/as/token`;
  const basic    = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  const body     = new URLSearchParams({
    grant_type:    'refresh_token',
    refresh_token: session.refreshToken,
  });

  let parsed = null;
  let raw    = '';
  let status = 0;
  let err    = null;

  try {
    const resp = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basic}`,
      },
      body,
    });
    status = resp.status;
    raw    = await resp.text();
    try { parsed = JSON.parse(raw); } catch {}
  } catch (e) {
    err = e;
  }

  const card = {
    title: 'Refresh access token',
    ok: err === null && status < 400,
    url: `POST ${tokenURL}`,
    detail: `Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>Form body:<br>&nbsp;&nbsp;<code>grant_type=refresh_token</code><br>&nbsp;&nbsp;<code>refresh_token=&lt;previous refresh_token&gt;</code><br>HTTP ${status}<br>Note: PKCE is not re-played here; the refresh grant authenticates only via client credentials. PingOne typically rotates the refresh_token on each use — store the new one.`,
    body: prettyJSONOrRaw(raw),
    collapsed: false,
  };

  if (err === null && status < 400 && parsed) {
    if (parsed.access_token)  session.accessToken  = parsed.access_token;
    if (parsed.id_token)      session.idToken      = parsed.id_token;
    if (parsed.refresh_token) session.refreshToken = parsed.refresh_token;
  }

  res.json({ refreshCards: [card] });
});

// Serve built React app
app.use(express.static(path.join(__dirname, '..', 'client', 'dist')));
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'client', 'dist', 'index.html'));
});

app.listen(3000, () => {
  console.log('PingOne OIDC PKCE demo backend on http://localhost:3000');
});
