// OAuth 2.0 Client Credentials (M2M) with PingOne Protect — Node.js/Express
//
// What this sample demonstrates:
//   The client_credentials grant is the right OAuth 2.0 grant type whenever
//   there is no human user involved. A backend service authenticates directly
//   with PingOne using its own client_id and client_secret, receives an access
//   token, and uses that token to call PingOne APIs. There is no browser
//   redirect, no PKCE, and no authorization code — the token arrives in the
//   same HTTP response as the credential exchange.
//
// Workflow steps (rendered as cards in the UI):
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
// PingOne setup required:
//   - A Worker application (Token Endpoint Auth Method = Client Secret Basic).
//   - Roles: Identity Data Read + PingOne Protect (risk evaluation).
//   - A Protect risk policy set with Anonymous Network Detection enabled;
//     HIGH threshold at or below 75. Its UUID goes in PINGONE_RISK_POLICY_SET_ID.

require('dotenv').config();
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const express = require('express');

// Embed the logo as a base64 data URI so the single-file app has no external
// static-file dependencies. This is fine for a sample; a production app would
// serve static assets separately.
const logoPNG = fs.readFileSync(path.join(__dirname, '..', 'assets', 'logo.png')).toString('base64');
const logoSrc = `data:image/png;base64,${logoPNG}`;

// All configuration comes from environment variables (loaded from .env).
// authPath  — base URL of the PingOne auth service, e.g. https://auth.pingone.com
// apiPath   — base URL of the PingOne management API, e.g. https://api.pingone.com
// Trailing slashes are stripped so we can always append /path safely.
const envID           = process.env.PINGONE_ENV_ID;
const clientID        = process.env.PINGONE_CLIENT_ID;
const clientSecret    = process.env.PINGONE_CLIENT_SECRET;
const authPath        = (process.env.PINGONE_AUTH_PATH || '').replace(/\/$/, '');
const apiPath         = (process.env.PINGONE_API_PATH  || '').replace(/\/$/, '');
// riskPolicySetID identifies the PingOne Protect policy set to evaluate events
// against. The policy set defines which predictors are active (e.g. Anonymous
// Network Detection, Velocity) and the score thresholds for LOW/MEDIUM/HIGH.
const riskPolicySetID = process.env.PINGONE_RISK_POLICY_SET_ID;

if (!envID || !clientID || !clientSecret || !authPath || !apiPath || !riskPolicySetID) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// --- HTML helpers ---

// escapeHTML prevents XSS by replacing special HTML characters before
// inserting any user-supplied or API-returned value into an HTML page.
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function pageHTML(title, bodyHTML) {
  return `<!DOCTYPE html>
<html>
<head>
<title>${escapeHTML(title)}</title>
<style>
  body{font-family:sans-serif; margin:0; background:#f5f5f5;}
  h2{margin-top:0;}
  button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;}
  button:hover{background:#c40034;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all; margin:0;}
  code{background:#f0f0f0; padding:1px 4px; border-radius:2px;}
  .card{margin-top:18px; padding:14px 16px; border:1px solid #ddd; border-radius:4px; background:#fff;}
  .card h3{margin:0 0 6px 0;}
  .ok{color:#0a7a0a;}
  .err{color:#b00020;}
  .url{font-family:monospace; font-size:13px; color:#555; background:#f0f0f0; padding:4px 8px; border-radius:3px; display:block; margin:6px 0; word-break:break-all;}
  details{margin-top:6px;}
  summary{cursor:pointer; font-size:13px; color:#444; user-select:none; padding:2px 0;}
  details pre{margin-top:4px;}
  .divider{margin-top:30px; margin-bottom:4px; padding:8px 14px; background:#B8002F; color:#fff; border-radius:4px; font-weight:600; font-size:15px;}
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:980px;margin:0 auto;">
${bodyHTML}
</div>
</body>
</html>`;
}

// renderCards converts an array of step objects into an HTML string of cards.
//
// Steps with { divider: true, title } render as a dark-red section header.
// Regular steps have { title, ok, url, detail, body, collapsed, rawDetail }.
// Set rawDetail=true when detail already contains safe HTML (e.g. <code> tags
// built with escapeHTML calls). Plain strings are escaped automatically.
function renderCards(steps) {
  return steps.map(step => {
    if (step.divider) {
      return `<div class="divider">${escapeHTML(step.title)}</div>`;
    }
    const statusClass = step.ok ? 'ok' : 'err';
    const statusText  = step.ok ? '(ok)' : '(failed)';
    const urlDiv      = step.url    ? `<div class="url">${escapeHTML(step.url)}</div>` : '';
    // detail may be trusted HTML (rawDetail flag) or plain text to escape
    const detailHTML  = step.detail
      ? `<div>${step.rawDetail ? step.detail : escapeHTML(step.detail)}</div>`
      : '';
    let bodyBlock = '';
    if (step.body) {
      const openAttr = step.collapsed ? '' : ' open';
      bodyBlock = `<details${openAttr}><summary>Show response</summary><pre>${escapeHTML(step.body)}</pre></details>`;
    }
    return `<div class="card">
  <h3 class="${statusClass}">${escapeHTML(step.title)} ${statusText}</h3>
  ${urlDiv}
  ${detailHTML}
  ${bodyBlock}
</div>`;
  }).join('\n');
}

// pretty pretty-prints a JSON string for display. Returns the original string
// unchanged if it is not valid JSON (e.g. an error message from the server).
function pretty(rawText) {
  try { return JSON.stringify(JSON.parse(rawText), null, 2); } catch (_) { return rawText; }
}

function prettyAny(obj) {
  try { return JSON.stringify(obj, null, 2); } catch (_) { return String(obj); }
}

// --- callerIP ---
// Returns the IP address of the HTTP request initiator.
//
// In cloud deployments the app runs behind a load balancer or reverse proxy
// that rewrites socket.remoteAddress to its own IP. The original client IP is
// preserved in the X-Forwarded-For header. We use this IP as the "event.ip"
// field in the PingOne Protect risk evaluation so that network-based predictors
// (Anonymous Network Detection, geo-velocity) can operate on the real address.
function callerIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = xff.split(',')[0].trim();
    if (first) return first;
  }
  let addr = req.socket && req.socket.remoteAddress || '';
  // Strip the IPv4-mapped IPv6 prefix ::ffff: so we store a plain IPv4 string.
  if (addr.startsWith('::ffff:')) addr = addr.slice(7);
  if (addr === '::1' || addr === '') return '127.0.0.1';
  return addr;
}

// --- JWT decode / verify ---

// decodeJWT splits a JWT into its three base64url-encoded parts and returns
// the decoded header and payload objects.
//
// A JWT is {base64url(header)}.{base64url(payload)}.{base64url(signature)}.
// This function only decodes — it does NOT verify the signature. Use verifyJWS
// after fetching the JWKS to cryptographically validate the token.
function decodeJWT(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error(`Not a 3-part JWT: ${parts.length} parts`);
  const headerBuf  = Buffer.from(parts[0], 'base64url');
  const payloadBuf = Buffer.from(parts[1], 'base64url');
  const header  = JSON.parse(headerBuf.toString('utf8'));
  const payload = JSON.parse(payloadBuf.toString('utf8'));
  return { header, payload, parts };
}

// jwkToPem converts a JWK RSA public key entry (with n and e in base64url) to
// a PEM-encoded SPKI string that Node's crypto.createVerify can accept.
//
// The conversion follows the DER encoding rules for SubjectPublicKeyInfo:
//   SEQUENCE {
//     AlgorithmIdentifier (OID for rsaEncryption + NULL parameters),
//     BIT STRING { SEQUENCE { INTEGER n, INTEGER e } }
//   }
// The resulting PEM is used only for signature verification — it is not stored
// or transmitted.
function jwkToPem(jwk) {
  if (jwk.kty !== 'RSA') throw new Error(`Unsupported kty "${jwk.kty}" (RSA only)`);
  const nBuf = Buffer.from(jwk.n, 'base64url');
  const eBuf = Buffer.from(jwk.e, 'base64url');

  // DER-encode the RSAPublicKey sequence: SEQUENCE { INTEGER n, INTEGER e }
  function encodeInteger(buf) {
    // Add leading 0x00 if high bit set (avoid sign ambiguity in DER encoding)
    const b = (buf[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), buf]) : buf;
    return Buffer.concat([Buffer.from([0x02]), encodeLength(b.length), b]);
  }
  function encodeLength(len) {
    if (len < 0x80) return Buffer.from([len]);
    const hex = len.toString(16).padStart(len > 0xff ? 4 : 2, '0');
    const b   = Buffer.from(hex, 'hex');
    return Buffer.concat([Buffer.from([0x80 | b.length]), b]);
  }

  const nDer = encodeInteger(nBuf);
  const eDer = encodeInteger(eBuf);
  const seq  = Buffer.concat([nDer, eDer]);
  const seqDer = Buffer.concat([Buffer.from([0x30]), encodeLength(seq.length), seq]);

  // Wrap in SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING { seqDer } }
  const rsaOid = Buffer.from('300d06092a864886f70d0101010500', 'hex'); // OID 1.2.840.113549.1.1.1 + NULL
  const bitStr = Buffer.concat([Buffer.from([0x03]), encodeLength(seqDer.length + 1), Buffer.from([0x00]), seqDer]);
  const spki   = Buffer.concat([rsaOid, bitStr]);
  const spkiDer = Buffer.concat([Buffer.from([0x30]), encodeLength(spki.length), spki]);

  const b64 = spkiDer.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`;
}

// verifyJWS verifies the RS256 signature of a JWT against the JWKS returned
// by PingOne's /as/jwks endpoint.
//
// The verification process:
//   1. Match the JWT's "kid" header to a key in the JWKS.
//   2. Convert the JWK to a PEM public key.
//   3. Hash the signed input "{base64url(header)}.{base64url(payload)}" with SHA-256.
//   4. Verify the decoded signature against the hash using the public key.
// Throws if the signature is invalid or if the key cannot be found/decoded.
function verifyJWS(token, header, jwks) {
  const alg = header.alg;
  const kid = header.kid;
  if (alg !== 'RS256') throw new Error(`Unsupported alg "${alg}" (this sample verifies RS256 only)`);

  const keys = (jwks && jwks.keys) || [];
  const match = keys.find(k => k.kid === kid);
  if (!match) throw new Error(`No JWK with kid="${kid}"`);

  const pem = jwkToPem(match);
  const parts = token.split('.');
  const signedInput = `${parts[0]}.${parts[1]}`;
  const sig = Buffer.from(parts[2], 'base64url');

  const verify = crypto.createVerify('SHA256');
  verify.update(signedInput);
  if (!verify.verify(pem, sig)) throw new Error('Signature verification failed');
}

// --- Claim validation ---

// validateAccessClaims checks the claims that must be present and valid in a
// PingOne client_credentials access token.
//
// Key M2M-specific point: PingOne Worker app tokens do not have a "sub" claim
// because there is no authenticated user. The client's identity is in the
// "client_id" claim instead. Always validate client_id when consuming M2M
// tokens — an attacker with a valid token from a different client would pass
// a "sub" check that was accidentally checking the wrong field.
function validateAccessClaims(payload, expectedIssuer, expectedClientID) {
  const errs = {};
  if (payload.iss !== expectedIssuer) {
    errs['iss'] = `got "${payload.iss}", want "${expectedIssuer}"`;
  }
  // PingOne Worker app tokens use client_id (not sub) to identify the client.
  if (payload.client_id !== expectedClientID) {
    errs['client_id'] = `got "${payload.client_id}", want "${expectedClientID}"`;
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number') {
    if (payload.exp < nowSec) errs['exp'] = `expired (exp=${payload.exp}, now=${nowSec})`;
  } else {
    errs['exp'] = 'missing or non-numeric';
  }
  // Allow up to 60 seconds of clock skew before flagging iat as future.
  if (typeof payload.iat === 'number') {
    if (payload.iat > nowSec + 60) errs['iat'] = `in the future (iat=${payload.iat}, now=${nowSec})`;
  }
  return errs;
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

// --- Risk result extraction ---

// extractRiskResult pulls the top-level verdict out of a PingOne Protect
// riskEvaluations response.
//
// The response body has the shape:
//   { "result": { "level": "LOW", "score": 12 }, "details": { ... } }
//
// result.level is LOW / MEDIUM / HIGH. result.score is the combined numeric
// score (0–100) from all active predictors. The details object contains
// per-predictor scores and can be used to diagnose which predictor drove the
// outcome.
function extractRiskResult(parsed) {
  const res = parsed && parsed.result;
  if (!res) return { level: 'n/a', score: 'n/a' };
  const level = (typeof res.level === 'string' && res.level) ? res.level : 'n/a';
  const score = (typeof res.score === 'number') ? String(res.score)
              : (typeof res.score === 'string' && res.score) ? res.score : 'n/a';
  return { level, score };
}

// --- Risk + gate runner ---

// runRiskAndGate calls the PingOne Protect risk evaluation API for one event,
// then either proceeds with or blocks the downstream management API call based
// on the returned risk level.
//
// Enforcement logic:
//   LOW / MEDIUM → the management API call proceeds. The access token is sent
//                  as a Bearer token in the Authorization header.
//   HIGH         → the management API call is blocked. In a production system
//                  this is where you would deny the request, trigger step-up
//                  authentication, or alert on-call.
//
// Returns an object { level, score, steps } where steps is an array of step
// objects to be appended to the main workflow card list.
async function runRiskAndGate(accessToken, riskURL, mgmtURL, riskBody, riskStep, mgmtStep) {
  const steps = [];

  // Call the risk evaluation endpoint.
  // The access token obtained via client_credentials is used here as a Bearer
  // token. The same token authorizes both the Protect API and the management
  // API because they are in the same PingOne environment.
  const riskBodyStr = JSON.stringify(riskBody);
  let riskStatus = 0, riskRaw = '', riskParsed = null, riskOK = false;
  try {
    const resp = await fetch(riskURL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: riskBodyStr,
    });
    riskStatus = resp.status;
    riskRaw    = await resp.text();
    try { riskParsed = JSON.parse(riskRaw); } catch (_) {}
    riskOK = riskStatus < 400;
  } catch (err) {
    riskRaw = err.message;
  }

  const { level, score } = extractRiskResult(riskParsed);
  const eventIP   = riskBody.event && riskBody.event.ip   || '';
  const userType  = riskBody.event && riskBody.event.user && riskBody.event.user.type || '';

  let riskDetail;
  if (riskStep === '7b') {
    // This evaluation is intentionally constructed to demonstrate a HIGH score.
    // The IP 185.220.101.1 is a well-known Tor exit node. Tor is an anonymizing
    // network that routes traffic through volunteer relays to obscure the true
    // origin. PingOne Protect's Anonymous Network Detection predictor maintains
    // a database of Tor exit nodes, VPN endpoints, and other anonymizing
    // infrastructure. A score of 80 for this IP exceeds the HIGH threshold of
    // 75, so the evaluation returns HIGH regardless of other signal.
    riskDetail = `<strong>This evaluation is intentionally constructed to trigger a HIGH risk score.</strong><br><br>` +
      `The IP <code>${escapeHTML(eventIP)}</code> is a known Tor exit node. Tor is an anonymizing network commonly associated with ` +
      `attempts to obscure origin and bypass geo-controls. PingOne Protect's <strong>Anonymous Network Detection</strong> ` +
      `predictor recognizes this IP and scores it at <strong>80</strong> — above the policy set's HIGH threshold of 75 — ` +
      `causing the overall evaluation to return HIGH.<br><br>` +
      `<code>user.type</code> is set to <code>ANONYMOUS</code> and a bot-like user agent is supplied to further reflect ` +
      `what a real suspicious M2M caller might look like. In production you would populate these fields from ` +
      `the actual upstream caller rather than hardcoding them.<br><br>` +
      `SDK signals are omitted — there is no browser SDK in an M2M flow.<br>` +
      `HTTP ${riskStatus} &middot; level: <code>${escapeHTML(level)}</code> &middot; score: <code>${escapeHTML(score)}</code>`;
  } else {
    riskDetail = `Event: ip=<code>${escapeHTML(eventIP)}</code>, user.type=<code>${escapeHTML(userType)}</code>.<br>` +
      `PingOne Protect scores the event against the configured risk policy set and returns a risk level (LOW / MEDIUM / HIGH) plus per-predictor details.<br>` +
      `SDK signals are intentionally omitted — there is no browser SDK in an M2M flow.<br>` +
      `HTTP ${riskStatus} &middot; level: <code>${escapeHTML(level)}</code> &middot; score: <code>${escapeHTML(score)}</code>`;
  }

  steps.push({
    title:      `${riskStep}. PingOne Protect risk evaluation`,
    ok:         riskOK,
    url:        `POST ${riskURL}`,
    detail:     riskDetail,
    rawDetail:  true,
    body:       `request:\n${prettyAny(riskBody)}\n\nresponse:\n${pretty(riskRaw)}`,
  });

  if (!riskOK) {
    steps.push({
      title:  `${mgmtStep}. Call PingOne Management API`,
      ok:     false,
      url:    `GET ${mgmtURL}`,
      detail: 'Skipped — the risk evaluation step did not succeed.',
    });
    return { level, score, steps };
  }

  if (level.toUpperCase() === 'HIGH') {
    steps.push({
      title:     `${mgmtStep}. Call PingOne Management API`,
      ok:        false,
      url:       `GET ${mgmtURL}`,
      detail:    `<strong>Blocked.</strong> PingOne Protect returned risk level <code>${escapeHTML(level)}</code> (score: <code>${escapeHTML(score)}</code>). ` +
                 `Anonymous Network Detection flagged the IP as a known Tor exit node. ` +
                 `The downstream management API call was <strong>not</strong> made.`,
      rawDetail: true,
    });
    return { level, score, steps };
  }

  // Risk is LOW or MEDIUM — make the downstream management API call.
  let mgmtStatus = 0, mgmtRaw = '', mgmtOK = false;
  try {
    const resp = await fetch(mgmtURL, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    mgmtStatus = resp.status;
    mgmtRaw    = await resp.text();
    mgmtOK     = mgmtStatus < 400;
  } catch (err) {
    mgmtRaw = err.message;
  }

  steps.push({
    title:     `${mgmtStep}. Call PingOne Management API`,
    ok:        mgmtOK,
    url:       `GET ${mgmtURL}`,
    detail:    `Risk level <code>${escapeHTML(level)}</code> — proceeding. The access token is sent as a Bearer token.<br>HTTP ${mgmtStatus}`,
    rawDetail: true,
    body:      pretty(mgmtRaw),
  });

  return { level, score, steps };
}

// --- Workflow ---

// runWorkflow executes the full client_credentials + Protect workflow and
// returns an array of step objects for display.
//
// The workflow is entirely server-side: PingOne credentials are never exposed
// to the browser. The Express app calls PingOne directly, then returns the
// rendered HTML (or JSON for React/Angular frontends) to the client.
async function runWorkflow(req) {
  const steps = [];

  // Step 1: Assemble the token request.
  // The token endpoint URL is always {authPath}/{envID}/as/token.
  // Client authentication uses HTTP Basic (CLIENT_SECRET_BASIC): the
  // client_id and client_secret are base64-encoded as "client_id:client_secret"
  // and placed in the Authorization header. No data goes in the request body
  // except grant_type=client_credentials.
  const tokenURL = `${authPath}/${envID}/as/token`;
  const basic    = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');

  steps.push({
    title:     '1. Build token request',
    ok:        true,
    url:       `POST ${tokenURL}`,
    detail:    `The client_credentials grant requires no user interaction. The only inputs are the client's own credentials.<br><br>` +
               `Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>` +
               `Form body:<br>&nbsp;&nbsp;<code>grant_type=client_credentials</code>`,
    rawDetail: true,
    body:      `client_id:     ${clientID}\ngrant_type:    client_credentials`,
  });

  // Step 2: Call the token endpoint.
  // A successful response contains access_token (JWT), token_type ("Bearer"),
  // and expires_in (seconds). There is no refresh_token in client_credentials
  // flows — when the token expires, simply re-run this same request.
  let tokStatus = 0, tokRaw = '', tokParsed = null, tokOK = false;
  try {
    const resp = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basic}`,
      },
      body: 'grant_type=client_credentials',
    });
    tokStatus = resp.status;
    tokRaw    = await resp.text();
    try { tokParsed = JSON.parse(tokRaw); } catch (_) {}
    tokOK = tokStatus < 400;
  } catch (err) {
    tokRaw = err.message;
  }

  steps.push({
    title:     '2. Token endpoint response',
    ok:        tokOK,
    url:       `POST ${tokenURL}`,
    detail:    `PingOne validates the client credentials and, if valid, returns an access token. No authorization code or redirect is involved — this is the entire grant in one round trip.<br>HTTP ${tokStatus}`,
    rawDetail: true,
    body:      pretty(tokRaw),
  });

  if (!tokOK) return { success: false, steps };

  const accessToken = tokParsed && tokParsed.access_token;

  // Step 3: Decode the access token without verifying the signature.
  // The JWT payload contains useful claims to inspect: client_id (identifies
  // the M2M client — there is no "sub" because there is no user), iss
  // (the issuer URL), exp (expiry timestamp), and scope (granted scopes).
  let header = null, payload = null, decodeErr = null;
  try {
    const decoded = decodeJWT(accessToken);
    header  = decoded.header;
    payload = decoded.payload;
  } catch (err) {
    decodeErr = err;
  }

  steps.push({
    title:  '3. Decode access token',
    ok:     decodeErr === null,
    detail: 'The access token is a JWT. Decoding it (without yet verifying the signature) shows the claims PingOne embedded — notably <code>client_id</code> (the client identity for M2M tokens), <code>iss</code>, <code>exp</code>, and any scopes granted by the authorization server.',
    rawDetail: true,
    body:   decodeErr
      ? `Error: ${decodeErr.message}`
      : `header:\n${prettyAny(header)}\n\npayload:\n${prettyAny(payload)}`,
  });

  // Step 4: Fetch the JWKS (JSON Web Key Set).
  // PingOne publishes its public signing keys at /as/jwks. The kid (key ID) in
  // each JWKS entry matches the kid in the JWT header, allowing us to pick the
  // correct key when multiple keys are in rotation. In production you should
  // cache the JWKS and only re-fetch on a cache miss (new kid encountered).
  const jwksURL = `${authPath}/${envID}/as/jwks`;
  let jwksRaw = '', jwksParsed = null, jwksOK = false;
  try {
    const resp = await fetch(jwksURL);
    jwksRaw   = await resp.text();
    try { jwksParsed = JSON.parse(jwksRaw); } catch (_) {}
    jwksOK = resp.status < 400;
  } catch (err) {
    jwksRaw = err.message;
  }

  steps.push({
    title:     '4. Fetch JWKS',
    ok:        jwksOK,
    url:       `GET ${jwksURL}`,
    detail:    'Public keys used to verify the access token signature. In production, cache this response and re-fetch only when a new <code>kid</code> is encountered.',
    rawDetail: true,
    body:      pretty(jwksRaw),
    collapsed: true,
  });

  // Step 5: Verify the JWT signature.
  // The signed input is exactly "{base64url(header)}.{base64url(payload)}" —
  // the raw ASCII string as transmitted, not the decoded JSON. Any modification
  // to the token (reordering keys, changing a value) invalidates the signature.
  let verifyErr = null;
  if (decodeErr === null && jwksOK) {
    try {
      verifyJWS(accessToken, header, jwksParsed);
    } catch (err) {
      verifyErr = err;
    }
  } else if (decodeErr !== null) {
    verifyErr = new Error('Cannot verify — JWT decode failed');
  } else {
    verifyErr = new Error('Cannot verify — JWKS fetch failed');
  }

  const algStr = header ? escapeHTML(String(header.alg || '')) : 'n/a';
  const kidStr = header ? escapeHTML(String(header.kid || '')) : 'n/a';
  steps.push({
    title:     '5. Verify access token signature',
    ok:        verifyErr === null,
    detail:    `alg: <code>${algStr}</code>, kid: <code>${kidStr}</code><br>` +
               (verifyErr === null
                 ? 'Signature valid (RS256, key matched by <code>kid</code>).'
                 : `Signature INVALID: ${escapeHTML(verifyErr.message)}`),
    rawDetail: true,
  });

  // Step 6: Validate access token claims.
  // Even a cryptographically valid token can be rejected if the claims are
  // wrong. We check:
  //   iss       — must match this environment's authorization server URL.
  //   client_id — must match our own client ID (M2M tokens use client_id,
  //               not sub, because there is no user subject).
  //   exp       — must not be in the past.
  //   iat       — must not be more than 60 seconds in the future (clock skew).
  const expectedIssuer = `${authPath}/${envID}/as`;
  let claimsErrs = {};
  if (payload) {
    claimsErrs = validateAccessClaims(payload, expectedIssuer, clientID);
  } else {
    claimsErrs = { decode: 'JWT decode failed — cannot validate claims' };
  }

  steps.push({
    title:     '6. Validate access token claims',
    ok:        Object.keys(claimsErrs).length === 0,
    detail:    `Required checks: <code>iss</code> matches <code>${escapeHTML(expectedIssuer)}</code>, <code>client_id</code> matches <code>${escapeHTML(clientID)}</code>, <code>exp</code> &gt; now, <code>iat</code> not in the future.<br>` +
               `Note: PingOne Worker app tokens use <code>client_id</code> (not <code>sub</code>) to identify the client. There is no <code>nonce</code> — no user authentication was involved.<br>` +
               renderClaimChecks(claimsErrs),
    rawDetail: true,
    body:      payload ? prettyAny(payload) : '',
  });

  const riskURL = `${apiPath}/v1/environments/${envID}/riskEvaluations`;
  const mgmtURL = `${apiPath}/v1/environments/${envID}/users`;

  // Steps 7a / 8a — User A: trusted caller.
  // We send the real client IP and user.type=EXTERNAL (a known, identified
  // user operating from a normal network). PingOne Protect should return
  // LOW or MEDIUM, and the management API call proceeds.
  const clientIPAddr = callerIP(req);
  const riskBodyA = {
    event: {
      ip:   clientIPAddr,
      flow: { type: 'AUTHENTICATION' },
      session: { id: 'm2m-demo-session-a' },
      user: { id: 'm2m-user-trusted', type: 'EXTERNAL', name: 'm2m-user-trusted' },
      browser:     { userAgent: req.headers['user-agent'] || '' },
      sharingType: 'SHARED',
      targetResource: { id: 'm2m-demo-resource', name: 'm2m-demo-resource' },
    },
    riskPolicySet: { id: riskPolicySetID },
  };

  steps.push({ divider: true, title: 'User A — trusted (real IP, type=EXTERNAL)' });
  const resultA = await runRiskAndGate(accessToken, riskURL, mgmtURL, riskBodyA, '7a', '8a');
  steps.push(...resultA.steps);

  // Steps 7b / 8b — User B: suspicious caller.
  // The event is deliberately crafted to trigger HIGH:
  //   ip:        185.220.101.1 — a Tor exit node. Anonymous Network Detection
  //              scores this at 80, exceeding the HIGH threshold of 75.
  //   user.type: ANONYMOUS — the upstream caller's identity is unknown.
  //   userAgent: bot-like string to further reflect a suspicious profile.
  const riskBodyB = {
    event: {
      ip:   '185.220.101.1', // known Tor exit node — triggers Anonymous Network Detection
      flow: { type: 'AUTHENTICATION' },
      session: { id: 'm2m-demo-session-b' },
      user: { id: 'm2m-user-suspicious', type: 'ANONYMOUS', name: 'm2m-user-suspicious' },
      browser:     { userAgent: 'python-requests/2.28.0' }, // bot-like UA
      sharingType: 'SHARED',
      targetResource: { id: 'm2m-demo-resource', name: 'm2m-demo-resource' },
    },
    riskPolicySet: { id: riskPolicySetID },
  };

  steps.push({ divider: true, title: 'User B — suspicious (Tor IP, type=ANONYMOUS)' });
  const resultB = await runRiskAndGate(accessToken, riskURL, mgmtURL, riskBodyB, '7b', '8b');
  steps.push(...resultB.steps);

  return { success: true, steps };
}

// --- Express app ---

const app = express();
app.use(express.urlencoded({ extended: true }));

app.get('/', (_req, res) => {
  res.send(pageHTML('M2M Client Credentials — start', `
<h2>OAuth 2.0 Client Credentials (M2M) + PingOne Protect</h2>
<p>This sample walks through the OAuth 2.0 <strong>client_credentials</strong> grant. There is no user, no browser redirect, and no PKCE. The client authenticates directly with the PingOne token endpoint using its own credentials, receives an access token, and calls <strong>PingOne Protect</strong> for two risk evaluations:</p>
<ul>
  <li><strong>User A — trusted:</strong> real client IP, <code>type=EXTERNAL</code> — expected to score LOW or MEDIUM, API call proceeds.</li>
  <li><strong>User B — suspicious:</strong> Tor exit node IP (<code>185.220.101.1</code>), <code>type=ANONYMOUS</code> — expected to score HIGH via Anonymous Network Detection, API call blocked.</li>
</ul>
<p>Both paths are rendered side-by-side so you can compare what PingOne Protect returns and see how the application gates the downstream call differently in each case.</p>
<form action="/run" method="POST"><button type="submit">Run Flow</button></form>
<p style="color:#666;font-size:13px;margin-top:30px;">PingOne config required: Worker application with Token Endpoint Auth Method = Client Secret Basic. The Worker app must have roles for Identity Data (read) and PingOne Protect (risk evaluation). A Protect risk policy set must exist with Anonymous Network Detection enabled and scored above the HIGH threshold; its ID goes in <code>PINGONE_RISK_POLICY_SET_ID</code>.</p>
`));
});

app.post('/run', async (req, res) => {
  try {
    const data    = await runWorkflow(req);
    const cardsEl = renderCards(data.steps);
    res.send(pageHTML('Run — complete', cardsEl + `<p style="margin-top:20px;"><a href="/">Run again</a></p>`));
  } catch (err) {
    res.status(500).send(`<pre>${escapeHTML(err.stack || err.message)}</pre>`);
  }
});

app.listen(3000, () => {
  console.log('M2M Client Credentials demo on http://localhost:3000');
});
