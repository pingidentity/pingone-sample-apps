// OAuth 2.0 Client Credentials (M2M) with PingOne Protect — Angular backend
//
// This Express server performs all PingOne communication server-side.
// The Angular frontend never sees credentials or raw API responses — it only
// receives the processed step array returned by POST /api/run.
//
// Why server-side? The client_id and client_secret must never be exposed to
// the browser. Even though client_credentials tokens are meant for backend
// services, leaking the credentials would allow anyone to obtain tokens on
// behalf of your Worker app.
//
// Workflow executed by POST /api/run:
//   1.  Build token request     — assemble URL and HTTP Basic credentials.
//   2.  Call /as/token          — POST grant_type=client_credentials.
//   3.  Decode access token     — split the JWT, decode header + payload.
//   4.  Fetch JWKS              — retrieve PingOne's public signing keys.
//   5.  Verify signature        — validate the JWT signature (RS256).
//   6.  Validate claims         — check iss, client_id, exp, iat.
//   7a. Risk evaluation (A)     — trusted IP, type=EXTERNAL → LOW/MEDIUM.
//   8a. Management API call (A) — proceeds because risk is low.
//   7b. Risk evaluation (B)     — Tor IP, type=ANONYMOUS → HIGH.
//   8b. Management API call (B) — blocked because risk is HIGH.
//
// Response shape: { success: bool, steps: Step[] }
// Each Step has { title, ok, detail, body, url, collapsed, divider? }.

require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');

// All configuration comes from environment variables (loaded from .env).
// authPath  — base URL of the PingOne auth service, e.g. https://auth.pingone.com
// apiPath   — base URL of the PingOne management API, e.g. https://api.pingone.com
// Trailing slashes are stripped so we can safely append /path.
const envID           = process.env.PINGONE_ENV_ID;
const clientID        = process.env.PINGONE_CLIENT_ID;
const clientSecret    = process.env.PINGONE_CLIENT_SECRET;
const authPath        = (process.env.PINGONE_AUTH_PATH  || '').replace(/\/$/, '');
const apiPath         = (process.env.PINGONE_API_PATH   || '').replace(/\/$/, '');
// riskPolicySetID identifies the PingOne Protect policy set that defines which
// predictors are active and the score thresholds for LOW / MEDIUM / HIGH.
const riskPolicySetID = process.env.PINGONE_RISK_POLICY_SET_ID;

if (!envID || !clientID || !clientSecret || !authPath || !apiPath || !riskPolicySetID) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// pretty pretty-prints a JSON string for display. Returns the original string
// if it is not valid JSON (e.g. a plain-text error response from the server).
function pretty(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}

function prettyAny(obj) {
  try { return JSON.stringify(obj, null, 2); } catch { return String(obj); }
}

// ── JWT / JWS ────────────────────────────────────────────────────────────────

// b64urlDecode converts a base64url string to a Buffer.
// base64url differs from standard base64: "-" replaces "+", "_" replaces "/",
// and padding "=" characters are omitted. Buffer.from supports 'base64url'
// directly in newer Node versions, but this manual conversion is used here
// for broader compatibility.
function b64urlDecode(str) {
  // Convert base64url → base64, then decode
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64, 'base64');
}

// decodeJWT splits a JWT into its three base64url-encoded parts and returns
// the decoded header and payload objects.
//
// A JWT is {base64url(header)}.{base64url(payload)}.{base64url(signature)}.
// This function only decodes — it does NOT verify the signature. Call
// verifyRS256 after fetching the JWKS for cryptographic validation.
function decodeJWT(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error(`Not a 3-part JWT: ${parts.length} parts`);
  const header  = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
  const payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
  return { header, payload, parts };
}

// jwkToPublicKeyPEM converts a JWK RSA public key to a PEM-encoded SPKI
// string that Node's crypto.createVerify can accept.
//
// Node >= 15 can import a JWK directly via crypto.createPublicKey, which
// avoids manual DER construction and is used here.
function jwkToPublicKeyPEM(jwk) {
  if (jwk.kty !== 'RSA') throw new Error(`Unsupported kty ${jwk.kty} (RSA only)`);
  // crypto.createPublicKey with format:'jwk' is the idiomatic Node 15+ approach.
  const keyObject = crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
  return keyObject.export({ type: 'spki', format: 'pem' });
}

// verifyRS256 verifies the RS256 signature of a JWT against the JWKS returned
// by PingOne's /as/jwks endpoint.
//
// Verification steps:
//   1. Match the JWT's "kid" to a key in the JWKS.
//   2. Export the JWK as a PEM public key.
//   3. Hash the signed input "{base64url(header)}.{base64url(payload)}" with SHA-256.
//   4. Verify the signature over the hash with PKCS#1 v1.5.
// Throws if the signature is invalid or the key cannot be found.
function verifyRS256(token, header, jwks) {
  const alg = header.alg;
  const kid = header.kid;
  if (alg !== 'RS256') throw new Error(`Unsupported alg ${alg} (this sample verifies RS256 only)`);

  const keys = (jwks && jwks.keys) ? jwks.keys : [];
  const match = keys.find(k => k.kid === kid);
  if (!match) throw new Error(`No JWK with kid=${kid}`);

  const pem = jwkToPublicKeyPEM(match);
  const parts = token.split('.');
  // The signed input is the exact ASCII string that was transmitted — not the
  // decoded JSON. Any modification to the token invalidates the signature.
  const signedInput = `${parts[0]}.${parts[1]}`;
  const sig = b64urlDecode(parts[2]);

  const verify = crypto.createVerify('SHA256');
  verify.update(signedInput, 'utf8');
  const valid = verify.verify(pem, sig);
  if (!valid) throw new Error('Signature verification failed');
}

// ── Claim validation ─────────────────────────────────────────────────────────

// validateAccessClaims checks the claims that must be present and correct in a
// PingOne client_credentials access token.
//
// Key M2M-specific point: PingOne Worker app tokens do NOT have a "sub" claim
// because there is no authenticated user. The client's identity is in the
// "client_id" claim. Always validate client_id when consuming M2M tokens.
function validateAccessClaims(payload, expectedIssuer, expectedClientID) {
  const errs = {};
  if (payload.iss !== expectedIssuer) {
    errs.iss = `got "${payload.iss}", want "${expectedIssuer}"`;
  }
  // PingOne Worker app tokens use client_id (not sub) to identify the client.
  if (payload.client_id !== expectedClientID) {
    errs.client_id = `got "${payload.client_id}", want "${expectedClientID}"`;
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number') {
    errs.exp = 'missing or non-numeric';
  } else if (payload.exp < now) {
    errs.exp = `expired (exp=${payload.exp}, now=${now})`;
  }
  // Allow up to 60 seconds of clock skew before flagging iat as future.
  if (typeof payload.iat === 'number' && payload.iat > now + 60) {
    errs.iat = `in the future (iat=${payload.iat}, now=${now})`;
  }
  return errs;
}

function renderClaimChecks(errs) {
  if (Object.keys(errs).length === 0) return 'All claims valid.';
  return Object.entries(errs).map(([k, v]) => `${k}: ${v}`).join('\n');
}

// ── Risk helpers ─────────────────────────────────────────────────────────────

// extractRiskResult pulls the top-level verdict from a PingOne Protect
// riskEvaluations response.
//
// Response shape: { "result": { "level": "LOW", "score": 12 }, "details": {...} }
// result.level — LOW / MEDIUM / HIGH.
// result.score — combined numeric score (0–100) from all active predictors.
function extractRiskResult(parsed) {
  const res = parsed && parsed.result;
  if (!res) return { level: 'n/a', score: 'n/a' };
  const level = (typeof res.level === 'string' && res.level) ? res.level : 'n/a';
  const score = (typeof res.score === 'number') ? String(res.score)
              : (typeof res.score === 'string' && res.score) ? res.score : 'n/a';
  return { level, score };
}

// ── Workflow ─────────────────────────────────────────────────────────────────

// runWorkflow executes the full client_credentials + Protect workflow and
// returns { success, steps } where steps is an array of step objects.
//
// Note: the Angular server does not receive an HTTP request object because
// the workflow does not use the caller's real IP (it uses 127.0.0.1 as the
// trusted-user IP). This differs slightly from the Go/JS/Python versions.
async function runWorkflow() {
  const steps = [];

  // Step 1: Assemble the token request.
  // The token endpoint is always {authPath}/{envID}/as/token.
  // CLIENT_SECRET_BASIC: credentials base64-encoded as "client_id:client_secret"
  // in the Authorization header. The body contains only grant_type.
  const tokenURL = `${authPath}/${envID}/as/token`;
  const basic = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');

  // ── 1. Build token request ────────────────────────────────────────────────
  steps.push({
    title: '1. Build token request',
    ok: true,
    url: `POST ${tokenURL}`,
    detail: 'The client_credentials grant requires no user interaction. The only inputs are the client\'s own credentials.\n\n' +
            'Headers:\n  Authorization: Basic base64(client_id:client_secret)\n  Content-Type: application/x-www-form-urlencoded\n' +
            'Form body:\n  grant_type=client_credentials',
    body: `client_id:     ${clientID}\ngrant_type:    client_credentials`,
    collapsed: false,
  });

  // ── 2. Call token endpoint ────────────────────────────────────────────────
  // A successful response contains access_token (JWT), token_type ("Bearer"),
  // and expires_in. There is no refresh_token in client_credentials flows —
  // when the token expires, simply re-send the same credential exchange.
  let tokStatus = 0;
  let tokRaw = '';
  let tokParsed = null;
  try {
    const tokResp = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basic}`,
      },
      body: new URLSearchParams({ grant_type: 'client_credentials' }),
    });
    tokStatus = tokResp.status;
    tokRaw = await tokResp.text();
    try { tokParsed = JSON.parse(tokRaw); } catch {}
  } catch (err) {
    steps.push({ title: '2. Token endpoint response', ok: false, url: `POST ${tokenURL}`, detail: `Request failed: ${err.message}`, body: '', collapsed: false });
    return { success: false, steps };
  }

  const tokOK = tokStatus < 400;
  steps.push({
    title: '2. Token endpoint response',
    ok: tokOK,
    url: `POST ${tokenURL}`,
    detail: `PingOne validates the client credentials and, if valid, returns an access token. No authorization code or redirect is involved — this is the entire grant in one round trip.\nHTTP ${tokStatus}`,
    body: pretty(tokRaw),
    collapsed: false,
  });
  if (!tokOK) return { success: false, steps };

  const accessToken = tokParsed && tokParsed.access_token ? tokParsed.access_token : '';

  // ── 3. Decode access token ────────────────────────────────────────────────
  // The payload shows client_id (M2M identity — no "sub" because there is no
  // user), iss (issuer URL), exp (expiry), and scope (granted scopes).
  let header = null;
  let payload = null;
  let decodeErr = null;
  try {
    const decoded = decodeJWT(accessToken);
    header = decoded.header;
    payload = decoded.payload;
  } catch (err) {
    decodeErr = err;
  }
  steps.push({
    title: '3. Decode access token',
    ok: decodeErr === null,
    url: '',
    detail: 'The access token is a JWT. Decoding it (without yet verifying the signature) shows the claims PingOne embedded — notably client_id (the client identity for M2M tokens), iss, exp, and any scopes granted by the authorization server.',
    body: decodeErr ? decodeErr.message : `header:\n${prettyAny(header)}\n\npayload:\n${prettyAny(payload)}`,
    collapsed: false,
  });

  // ── 4. Fetch JWKS ─────────────────────────────────────────────────────────
  // PingOne publishes its RSA public signing keys at /as/jwks. Each key's kid
  // matches the kid in the JWT header, enabling correct key selection during
  // key rotation. In production, cache the JWKS and re-fetch only on a cache
  // miss (new kid encountered).
  const jwksURL = `${authPath}/${envID}/as/jwks`;
  let jwksStatus = 0;
  let jwksRaw = '';
  let jwksParsed = null;
  let jwksFetchErr = null;
  try {
    const jwksResp = await fetch(jwksURL);
    jwksStatus = jwksResp.status;
    jwksRaw = await jwksResp.text();
    try { jwksParsed = JSON.parse(jwksRaw); } catch {}
  } catch (err) {
    jwksFetchErr = err;
  }
  steps.push({
    title: '4. Fetch JWKS',
    ok: jwksFetchErr === null && jwksStatus < 400,
    url: `GET ${jwksURL}`,
    detail: 'Public keys used to verify the access token signature. In production, cache this response and re-fetch only when a new kid is encountered.',
    body: jwksFetchErr ? jwksFetchErr.message : pretty(jwksRaw),
    collapsed: true,
  });

  // ── 5. Verify access token signature ──────────────────────────────────────
  // The signed input is "{base64url(header)}.{base64url(payload)}" — the exact
  // bytes transmitted. Any modification (reordering keys, changing a claim)
  // invalidates the signature and indicates tampering.
  let verifyErr = null;
  try {
    verifyRS256(accessToken, header, jwksParsed);
  } catch (err) {
    verifyErr = err;
  }
  steps.push({
    title: '5. Verify access token signature',
    ok: verifyErr === null,
    url: '',
    detail: `alg: ${header ? header.alg : 'n/a'}, kid: ${header ? header.kid : 'n/a'}\n` +
            (verifyErr === null
              ? 'Signature valid (RS256, key matched by kid).'
              : `Signature INVALID: ${verifyErr.message}`),
    body: '',
    collapsed: false,
  });

  // ── 6. Validate access token claims ───────────────────────────────────────
  // Checks: iss matches this environment's AS issuer URL; client_id matches
  // our CLIENT_ID (M2M tokens use client_id, not sub); exp is in the future;
  // iat not more than 60 seconds in the future. No nonce check — nonces are
  // only relevant in browser-redirect flows.
  const expectedIssuer = `${authPath}/${envID}/as`;
  const claimErrs = payload ? validateAccessClaims(payload, expectedIssuer, clientID) : { payload: 'not decoded' };
  const claimDetail = `Required checks: iss matches ${expectedIssuer}, client_id matches ${clientID}, exp > now, iat not in the future.\n` +
    `Note: PingOne Worker app tokens use client_id (not sub) to identify the client. There is no nonce — no user authentication was involved.\n` +
    renderClaimChecks(claimErrs);
  steps.push({
    title: '6. Validate access token claims',
    ok: Object.keys(claimErrs).length === 0,
    url: '',
    detail: claimDetail,
    body: payload ? prettyAny(payload) : '',
    collapsed: false,
  });

  const riskURL = `${apiPath}/v1/environments/${envID}/riskEvaluations`;
  const mgmtURL = `${apiPath}/v1/environments/${envID}/users`;

  // ── Divider: User A ───────────────────────────────────────────────────────
  // Steps 7a / 8a: trusted caller.
  // IP 127.0.0.1, user.type=EXTERNAL (known user on a normal network).
  // Expected: LOW or MEDIUM risk. Management API call proceeds.
  steps.push({ divider: true, title: 'User A — trusted (real IP, type=EXTERNAL)' });

  const riskBodyA = {
    event: {
      ip:   '127.0.0.1',
      flow: { type: 'AUTHENTICATION' },
      session: { id: 'm2m-demo-session-a' },
      user: { id: 'm2m-user-trusted', type: 'EXTERNAL', name: 'm2m-user-trusted' },
      browser:     { userAgent: 'Mozilla/5.0' },
      sharingType: 'SHARED',
      targetResource: { id: 'm2m-demo-resource', name: 'm2m-demo-resource' },
    },
    riskPolicySet: { id: riskPolicySetID },
  };
  const riskStepsA = await runRiskAndGate(accessToken, riskURL, mgmtURL, riskBodyA, '7a', '8a');
  steps.push(...riskStepsA);

  // ── Divider: User B ───────────────────────────────────────────────────────
  // Steps 7b / 8b: suspicious caller. Deliberately crafted to trigger HIGH:
  //   ip:        185.220.101.1 — a Tor exit node. Anonymous Network Detection
  //              scores this at 80, above the HIGH threshold of 75.
  //   user.type: ANONYMOUS — the upstream caller's identity is unknown.
  //   userAgent: bot-like string reinforcing the suspicious profile.
  // Management API call is blocked when HIGH is returned.
  steps.push({ divider: true, title: 'User B — suspicious (Tor IP, type=ANONYMOUS)' });

  const riskBodyB = {
    event: {
      ip:   '185.220.101.1',
      flow: { type: 'AUTHENTICATION' },
      session: { id: 'm2m-demo-session-b' },
      user: { id: 'm2m-user-suspicious', type: 'ANONYMOUS', name: 'm2m-user-suspicious' },
      browser:     { userAgent: 'python-requests/2.28.0' },
      sharingType: 'SHARED',
      targetResource: { id: 'm2m-demo-resource', name: 'm2m-demo-resource' },
    },
    riskPolicySet: { id: riskPolicySetID },
  };
  const riskStepsB = await runRiskAndGate(accessToken, riskURL, mgmtURL, riskBodyB, '7b', '8b');
  steps.push(...riskStepsB);

  const allOk = steps.every(s => s.divider || s.ok);
  return { success: allOk, steps };
}

// runRiskAndGate calls PingOne Protect for one risk evaluation, then either
// proceeds with or blocks the downstream management API call.
//
// Enforcement logic:
//   LOW / MEDIUM → management API call proceeds; access token sent as Bearer.
//   HIGH         → management API call is blocked. In production this is where
//                  you deny the request, trigger step-up auth, or alert on-call.
//
// Returns an array of step objects (2 items: risk evaluation + mgmt call).
async function runRiskAndGate(accessToken, riskURL, mgmtURL, riskBody, riskStep, mgmtStep) {
  const steps = [];

  let riskStatus = 0;
  let riskRaw = '';
  let riskParsed = null;
  let riskFetchErr = null;
  try {
    const riskResp = await fetch(riskURL, {
      method: 'POST',
      headers: {
        // The same Bearer token authorizes both the Protect API and the
        // management API because they are in the same PingOne environment.
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(riskBody),
    });
    riskStatus = riskResp.status;
    riskRaw = await riskResp.text();
    try { riskParsed = JSON.parse(riskRaw); } catch {}
  } catch (err) {
    riskFetchErr = err;
  }

  const riskOK = riskFetchErr === null && riskStatus < 400;
  const { level, score } = extractRiskResult(riskParsed);

  const eventIP   = riskBody.event && riskBody.event.ip   ? riskBody.event.ip : '';
  const userType  = riskBody.event && riskBody.event.user && riskBody.event.user.type ? riskBody.event.user.type : '';

  let riskDetail;
  if (riskStep === '7b') {
    // IP 185.220.101.1 is a Tor exit node. Anonymous Network Detection scores
    // it at 80, which exceeds the HIGH threshold of 75, so the evaluation
    // returns HIGH regardless of other signals.
    riskDetail = `This evaluation is intentionally constructed to trigger a HIGH risk score.\n\n` +
      `The IP ${eventIP} is a known Tor exit node. Tor is an anonymizing network commonly associated with ` +
      `attempts to obscure origin and bypass geo-controls. PingOne Protect's Anonymous Network Detection ` +
      `predictor recognizes this IP and scores it at 80 — above the policy set's HIGH threshold of 75 — ` +
      `causing the overall evaluation to return HIGH.\n\n` +
      `user.type is set to ANONYMOUS and a bot-like user agent is supplied to further reflect ` +
      `what a real suspicious M2M caller might look like. In production you would populate these fields from ` +
      `the actual upstream caller rather than hardcoding them.\n\n` +
      `SDK signals are omitted — there is no browser SDK in an M2M flow.\n` +
      `HTTP ${riskStatus} · level: ${level} · score: ${score}`;
  } else {
    riskDetail = `Event: ip=${eventIP}, user.type=${userType}.\n` +
      `PingOne Protect scores the event against the configured risk policy set and returns a risk level (LOW / MEDIUM / HIGH) plus per-predictor details.\n` +
      `SDK signals are intentionally omitted — there is no browser SDK in an M2M flow.\n` +
      `HTTP ${riskStatus} · level: ${level} · score: ${score}`;
  }

  steps.push({
    title: `${riskStep}. PingOne Protect risk evaluation`,
    ok: riskOK,
    url: `POST ${riskURL}`,
    detail: riskDetail,
    body: `request:\n${prettyAny(riskBody)}\n\nresponse:\n${pretty(riskRaw)}`,
    collapsed: false,
  });

  if (!riskOK) {
    steps.push({
      title: `${mgmtStep}. Call PingOne Management API`,
      ok: false,
      url: `GET ${mgmtURL}`,
      detail: 'Skipped — the risk evaluation step did not succeed.',
      body: '',
      collapsed: false,
    });
    return steps;
  }

  if (level.toUpperCase() === 'HIGH') {
    steps.push({
      title: `${mgmtStep}. Call PingOne Management API`,
      ok: false,
      url: `GET ${mgmtURL}`,
      detail: `Blocked. PingOne Protect returned risk level ${level} (score: ${score}). Anonymous Network Detection flagged the IP as a known Tor exit node. The downstream management API call was not made.`,
      body: '',
      collapsed: false,
    });
    return steps;
  }

  // LOW or MEDIUM — call the management API with the same Bearer token.
  let mgmtStatus = 0;
  let mgmtRaw = '';
  let mgmtFetchErr = null;
  try {
    const mgmtResp = await fetch(mgmtURL, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    mgmtStatus = mgmtResp.status;
    mgmtRaw = await mgmtResp.text();
  } catch (err) {
    mgmtFetchErr = err;
  }

  steps.push({
    title: `${mgmtStep}. Call PingOne Management API`,
    ok: mgmtFetchErr === null && mgmtStatus < 400,
    url: `GET ${mgmtURL}`,
    detail: mgmtFetchErr
      ? `Request failed: ${mgmtFetchErr.message}`
      : `Risk level ${level} — proceeding. The access token is sent as a Bearer token.\nHTTP ${mgmtStatus}`,
    body: mgmtFetchErr ? '' : pretty(mgmtRaw),
    collapsed: false,
  });

  return steps;
}

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// POST /api/run — the single endpoint the Angular frontend calls.
// Returns { success: bool, steps: Step[] }. Each step is displayed as a card
// in the Angular UI. The frontend never calls PingOne directly.
app.post('/api/run', async (_req, res) => {
  try {
    const result = await runWorkflow();
    res.json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      steps: [{ title: 'Internal server error', ok: false, detail: err.message, body: '', url: '', collapsed: false }],
    });
  }
});

// Serve the built Angular app in production. During development the Angular
// dev server (port 4200) proxies /api/* to this server via proxy.conf.json.
const angularDist = path.join(__dirname, '..', 'client', 'dist', 'p1-m2m-client-credentials-angular', 'browser');
app.use(express.static(angularDist));
app.get('*', (_req, res) => {
  res.sendFile(path.join(angularDist, 'index.html'));
});

app.listen(3000, () => {
  console.log('M2M Client Credentials demo backend on http://localhost:3000');
});
