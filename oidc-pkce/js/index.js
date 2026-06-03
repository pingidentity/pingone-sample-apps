'use strict';

/**
 * OIDC Authorization Code Flow with PKCE — Node.js/Express single-file sample.
 *
 * WHY PKCE?
 * The standard authorization_code flow is vulnerable to authorization code
 * interception: a malicious process on the same device can register the same
 * redirect URI and steal the code before your app redeems it. PKCE (RFC 7636,
 * Proof Key for Code Exchange) closes that gap. Before redirecting the user,
 * the client generates a random secret (code_verifier) and sends only a one-way
 * hash of it (code_challenge) to the authorization server. When the code is
 * later exchanged at the token endpoint, the client sends the original verifier.
 * The server re-hashes it and verifies the match — only the app that generated
 * the verifier can complete the exchange.
 *
 * This sample uses a CONFIDENTIAL client: the token endpoint receives both
 * HTTP Basic auth (client_id + client_secret) AND the PKCE code_verifier.
 *
 * NINE-STEP FLOW:
 *  1. Generate code_verifier  — 32 random bytes, base64url-no-pad encoded
 *  2. Compute code_challenge  — base64url-no-pad(SHA-256(ASCII(code_verifier)))
 *  3. Generate state + nonce  — CSRF and replay protection
 *  4. Build GET /as/authorize URL with code_challenge + code_challenge_method=S256
 *  5. Receive callback        — PingOne 302s back with ?code=...&state=...
 *  6. Validate state          — abort on mismatch (CSRF check)
 *  7. POST /as/token          — exchange code + code_verifier + HTTP Basic
 *  8. Decode + verify ID token (RS256 signature against JWKS)
 *  9. GET /as/userinfo        — fetch profile claims with the access token
 *
 * PINGONE PREREQUISITES:
 *  - OIDC Web App: response_type=code, grant_type=authorization_code,
 *    Token Endpoint Auth Method = CLIENT_SECRET_BASIC,
 *    PKCE Enforcement = REQUIRED, redirect URI = PINGONE_REDIRECT_URI.
 */

require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');

// Embed the logo as a base64 data URL so there is no separate static-file route.
const logoPNG = fs.readFileSync(path.join(__dirname, '..', '..', 'assets', 'logo.png')).toString('base64');
const logoSrc = `data:image/png;base64,${logoPNG}`;

// ---------------------------------------------------------------------------
// Configuration — loaded from .env (or from the process environment)
// ---------------------------------------------------------------------------

const envID        = process.env.PINGONE_ENV_ID;
const clientID     = process.env.PINGONE_CLIENT_ID;
const clientSecret = process.env.PINGONE_CLIENT_SECRET;
// Trailing slash removed so URL concatenation is consistent regardless of how
// the variable is set in .env.
const authPath     = (process.env.PINGONE_AUTH_PATH || '').replace(/\/+$/, '');
const redirectURI  = process.env.PINGONE_REDIRECT_URI;
const scopes       = process.env.PINGONE_SCOPES;

if (!envID || !clientID || !clientSecret || !authPath || !redirectURI || !scopes) {
  console.error('Missing required environment variables. Please check your .env file.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------
// Single-process in-memory Map keyed by an opaque "sid" cookie value.
// The PKCE artifacts (verifier, state, nonce) must survive the full-page
// redirect to PingOne and back — they cannot live in a closure or a React
// component, they must be server-side.
// Production apps should use Redis or a database-backed session store.

const sessions = new Map();

/**
 * Look up the session for the current request via the "sid" cookie.
 * Returns null if no matching session exists.
 */
function getSession(req) {
  const sid = req.cookies && req.cookies.sid;
  if (!sid) return null;
  return sessions.get(sid) || null;
}

/**
 * Create a fresh session, persist it, and set the "sid" cookie.
 * HttpOnly prevents JavaScript from reading the cookie; sameSite:'lax' allows
 * the browser to include it on top-level navigations (e.g. the PingOne callback
 * redirect) while blocking it on cross-site sub-requests.
 */
function newSession(res) {
  const sid = crypto.randomBytes(16).toString('hex');
  const s = {};
  sessions.set(sid, s);
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', path: '/' });
  return s;
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

/**
 * Escape user-supplied values before embedding them in HTML to prevent XSS.
 * Never insert raw user data (or data derived from URLs/responses) into HTML
 * without calling this function first.
 */
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Render an array of step cards to an HTML string.
 *
 * Each card has:
 *   title     — plain text, HTML-escaped before output
 *   ok        — bool; drives green/red heading colour
 *   url       — optional request line shown in a monospace badge
 *   detail    — trusted HTML (already safe); output raw
 *   body      — plain text response body; HTML-escaped before <pre>
 *   collapsed — bool; when true the body starts hidden
 */
function renderCards(cards) {
  return cards.map(c => {
    const statusClass = c.ok ? 'ok' : 'err';
    const statusText  = c.ok ? '(ok)' : '(failed)';
    let html = `<div class="card">\n  <h3 class="${statusClass}">${escapeHTML(c.title)} ${statusText}</h3>\n`;
    if (c.url) {
      html += `  <div class="url">${escapeHTML(c.url)}</div>\n`;
    }
    if (c.detail) {
      html += `  <div>${c.detail}</div>\n`;
    }
    if (c.body) {
      if (c.collapsed) {
        html += `  <details><summary>Show response</summary><pre>${escapeHTML(c.body)}</pre></details>\n`;
      } else {
        html += `  <details open><summary>Hide</summary><pre>${escapeHTML(c.body)}</pre></details>\n`;
      }
    }
    html += `</div>`;
    return html;
  }).join('\n');
}

/**
 * Render the result of validateIDClaims() as an HTML fragment.
 * An empty errs object produces a green "All claims valid." message.
 */
function renderClaimChecks(errs) {
  const keys = Object.keys(errs);
  if (keys.length === 0) {
    return '<span style="color:#0a7a0a;">All claims valid.</span>';
  }
  let html = '<ul style="color:#b00020;">';
  for (const k of keys) {
    html += `<li><code>${escapeHTML(k)}</code>: ${escapeHTML(errs[k])}</li>`;
  }
  html += '</ul>';
  return html;
}

/** Wrap a body fragment in the shared page shell (header, styles, layout). */
function render(res, title, bodyHTML) {
  const page = `<!DOCTYPE html>
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
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="${logoSrc}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
${bodyHTML}
</div>
</body>
</html>`;
  res.send(page);
}

function prettyJSON(obj) {
  return JSON.stringify(obj, null, 2);
}

function prettyJSONOrRaw(str) {
  try {
    return JSON.stringify(JSON.parse(str), null, 2);
  } catch (_) {
    return str;
  }
}

// ---------------------------------------------------------------------------
// JWT / JWS helpers
// ---------------------------------------------------------------------------

/**
 * Decode a compact-serialized JWT into its header and payload objects.
 * Does NOT verify the signature — call verifyJWS() for that.
 *
 * JWT segments are base64url-encoded without padding ("="). Node's Buffer
 * understands 'base64url' natively (Node 14+), so no padding needs to be added.
 */
function decodeJWT(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`not a 3-part JWT: ${parts.length} parts`);
  }
  const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  return { header, payload };
}

/**
 * Verify an RS256 JWS token against the public keys in a JWKS document.
 * Throws on any failure (unsupported alg, kid not found, bad signature).
 *
 * The RS256 signing input is the ASCII string "header_b64url.payload_b64url"
 * — the raw base64url segments from the token, not re-encoded from parsed JSON.
 * Node's crypto.createVerify('SHA256') computes SHA-256 internally, so we pass
 * the raw signedInput bytes rather than a pre-computed digest.
 */
function verifyJWS(token, header, jwks) {
  if (header.alg !== 'RS256') {
    throw new Error(`unsupported alg "${header.alg}" (this sample verifies RS256 only)`);
  }
  const keys = (jwks && jwks.keys) || [];
  // Match the key by kid (Key ID). If the token's kid does not match any key
  // in the JWKS, the signature cannot be verified — do not fall back to a random key.
  const match = keys.find(k => k.kid === header.kid);
  if (!match) {
    throw new Error(`no JWK with kid="${header.kid}"`);
  }

  // Reconstruct the RSA public key from the JWK. Node accepts the JWK object
  // directly via { key: jwkObject, format: 'jwk' }.
  const pubKey = crypto.createPublicKey({ key: match, format: 'jwk' });

  const parts = token.split('.');
  const verifier = crypto.createVerify('SHA256');
  verifier.update(parts[0] + '.' + parts[1]);
  const sig = Buffer.from(parts[2], 'base64url');
  const valid = verifier.verify(pubKey, sig);
  if (!valid) {
    throw new Error('signature verification failed');
  }
}

/**
 * Validate standard OIDC Core §3.1.3.7 ID token claims.
 * Returns an object mapping claim name → error message for any failures.
 * An empty object means all checks passed.
 *
 * Checks performed:
 *   iss   — must match the PingOne issuer for this environment
 *   aud   — may be string or array; must contain our client_id
 *   exp   — must be > now (token not expired)
 *   iat   — must not be > now + 60 s (clock skew guard)
 *   nonce — must match the value we generated before the authorize redirect
 */
function validateIDClaims(payload, expectedIssuer, expectedAud, expectedNonce) {
  const errs = {};
  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== expectedIssuer) {
    errs['iss'] = `got "${payload.iss}", want "${expectedIssuer}"`;
  }

  // aud can be a string or array (OIDC Core §2)
  const aud = payload.aud;
  let audOK = false;
  if (typeof aud === 'string') {
    audOK = aud === expectedAud;
  } else if (Array.isArray(aud)) {
    audOK = aud.includes(expectedAud);
  }
  if (!audOK) {
    errs['aud'] = `does not contain "${expectedAud}"`;
  }

  if (typeof payload.exp !== 'number') {
    errs['exp'] = 'missing or non-numeric';
  } else if (payload.exp < now) {
    errs['exp'] = `expired (exp=${payload.exp}, now=${now})`;
  }

  if (typeof payload.iat === 'number' && payload.iat > now + 60) {
    errs['iat'] = `in the future (iat=${payload.iat}, now=${now})`;
  }

  if (payload.nonce !== expectedNonce) {
    errs['nonce'] = `got "${payload.nonce}", want "${expectedNonce}"`;
  }

  return errs;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

// GET / — landing page with description and "Begin Login" button.
app.get('/', (req, res) => {
  render(res, 'OIDC Auth Code + PKCE — start', `
<h2>OIDC Authorization Code + PKCE (confidential client)</h2>
<p>This sample walks through every artifact in the OIDC Authorization Code flow with PKCE so you can see exactly what each value is, how it's derived, and how it's validated.</p>
<p>The client is <strong>confidential</strong> — the token endpoint is called with HTTP Basic auth (client ID + secret) AND the PKCE <code>code_verifier</code>.</p>
<form action="/prepare" method="POST"><button type="submit">Begin Login</button></form>
<p style="color:#666;font-size:13px;margin-top:30px;">PingOne config required: OIDC Web App with PKCE Enforcement = REQUIRED, Token Endpoint Auth Method = Client Secret Basic, redirect URI = ${escapeHTML(redirectURI)}</p>
`);
});

/**
 * POST /prepare — generate PKCE artifacts, store in session, show step cards.
 *
 * Step 1: code_verifier
 *   32 cryptographically random bytes → base64url-no-pad → 43-char string.
 *   RFC 7636 §4.1 requires 43-128 characters from [A-Za-z0-9-._~]; base64url
 *   output naturally satisfies this, so no character filtering is needed.
 *
 * Step 2: code_challenge
 *   SHA-256 hash of the ASCII-encoded verifier, then base64url-no-pad encoded.
 *   Node's Buffer.toString('base64url') produces the correct format without any
 *   post-processing. Do NOT use standard base64 — the "+" and "/" characters it
 *   may contain are not URL-safe, and the trailing "=" padding is forbidden.
 *
 * Step 3: state + nonce
 *   Both are random hex strings. state is echoed back by PingOne in the callback
 *   query string so we can verify the redirect came from our authorize request
 *   (CSRF protection). nonce is embedded as a claim in the ID token so we can
 *   verify the token was issued for this specific login attempt (replay protection).
 *
 * Step 4: Build /authorize URL
 *   code_challenge_method must be exactly "S256" (uppercase) — this is a fixed
 *   string value in the RFC, not derived from the algorithm name.
 */
app.post('/prepare', (req, res) => {
  const s = newSession(res);

  // 1. code_verifier — RFC 7636: 43-128 chars from unreserved set [A-Za-z0-9-._~].
  // base64url-no-pad of 32 random bytes yields 43 chars that fall entirely within the unreserved set.
  const verifierBytes = crypto.randomBytes(32);
  s.verifier = verifierBytes.toString('base64url');

  // 2. code_challenge = base64url-nopad( SHA-256( ASCII(code_verifier) ) )
  const hashBuf = crypto.createHash('sha256').update(s.verifier).digest();
  s.challenge = hashBuf.toString('base64url');

  // 3. state + nonce — independent random values for CSRF and replay protection.
  s.state = crypto.randomBytes(16).toString('hex');
  s.nonce = crypto.randomBytes(16).toString('hex');

  const authorizeURL =
    `${authPath}/${encodeURIComponent(envID)}/as/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(clientID)}` +
    `&redirect_uri=${encodeURIComponent(redirectURI)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&state=${encodeURIComponent(s.state)}` +
    `&nonce=${encodeURIComponent(s.nonce)}` +
    `&code_challenge=${encodeURIComponent(s.challenge)}` +
    `&code_challenge_method=S256`;

  const hashHex = hashBuf.toString('hex');

  const cards = [
    {
      title: '1. Generate code_verifier',
      ok: true,
      detail: `Random ${verifierBytes.length} bytes → <code>base64url</code>-no-pad → ${s.verifier.length}-char verifier. RFC 7636 §4.1 allows 43-128 chars from the unreserved set <code>[A-Za-z0-9-._~]</code>; base64url output naturally falls in that set.`,
      body: s.verifier,
    },
    {
      title: '2. Compute code_challenge',
      ok: true,
      detail: '<code>code_challenge = base64url-no-pad( SHA-256( ASCII(code_verifier) ) )</code><br><code>code_challenge_method = S256</code>',
      body: `SHA-256 digest (hex):\n  ${hashHex}\n\nbase64url-no-pad encoding:\n  ${s.challenge}`,
    },
    {
      title: '3. Generate state and nonce',
      ok: true,
      detail: 'Both are random opaque strings: <code>state</code> defends the callback from CSRF; <code>nonce</code> is echoed back as a claim in the ID token to defend against replay.',
      body: `state: ${s.state}\nnonce: ${s.nonce}`,
    },
    {
      title: '4. Build /authorize URL',
      ok: true,
      url: 'GET ' + authorizeURL,
      detail: `Click the button below to redirect to PingOne. After you authenticate, PingOne will 302 back to <code>${escapeHTML(redirectURI)}</code> with a <code>code</code> and the original <code>state</code>.`,
    },
  ];

  const body = renderCards(cards) +
    `\n<p><a href="${escapeHTML(authorizeURL)}"><button>Continue to PingOne →</button></a></p>`;
  render(res, 'Step 1 — Prepare PKCE artifacts', body);
});

/**
 * GET /callback — OAuth 2.0 redirect URI handler.
 *
 * PingOne appends ?code=...&state=... to this URL after the user authenticates.
 * This handler performs the remaining steps of the PKCE flow:
 *
 * Step 1: Extract code and state from the query string.
 * Step 2: Validate state — compare to the stored value. A mismatch indicates a
 *   forged or replayed callback; abort immediately.
 * Step 3: Exchange code for tokens — POST to /as/token with:
 *   - grant_type=authorization_code
 *   - code=<the code from step 1>
 *   - redirect_uri=<must exactly match the authorize request AND the registered URI>
 *   - code_verifier=<the secret we generated in /prepare>
 *   - Authorization: Basic base64(client_id:client_secret)
 *   PingOne recomputes SHA-256(code_verifier) and checks it against the stored
 *   code_challenge. The redirect_uri is re-checked to prevent code injection.
 * Steps 4-9: Decode + verify ID token, validate claims, call /userinfo.
 */
app.get('/callback', async (req, res) => {
  const s = getSession(req);
  if (!s) {
    render(res, 'Callback — error', '<p class="err">No session found. Cookies may have been blocked. <a href="/">Start over</a>.</p>');
    return;
  }

  const cards = [];
  const { code: gotCode, state: gotState, error: gotErr, error_description: gotErrDesc } = req.query;

  if (gotErr) {
    cards.push({
      title: 'Callback received an error',
      ok: false,
      detail: `<code>error=${escapeHTML(gotErr)}</code><br><code>error_description=${escapeHTML(gotErrDesc || '')}</code>`,
      body: new URLSearchParams(req.query).toString(),
    });
    render(res, 'Callback — error', renderCards(cards) + '<p><a href="/">Start over</a></p>');
    return;
  }

  // Card 1: Receive callback. The code is single-use — PingOne invalidates it
  // immediately after the token exchange, or after a short expiry window (~2 min).
  const rawQuery = new URLSearchParams(req.query).toString();
  cards.push({
    title: '1. Receive callback',
    ok: true,
    url: 'GET ' + redirectURI + '?' + rawQuery,
    detail: 'PingOne redirected the browser back with <code>code</code> and <code>state</code>. The <code>code</code> is single-use and short-lived.',
    body: `code:  ${gotCode}\nstate: ${gotState}`,
  });

  // Card 2: Validate state — defends against CSRF.
  // Abort without attempting a token exchange if the state does not match.
  const stateOK = gotState === s.state;
  cards.push({
    title: '2. Validate state',
    ok: stateOK,
    detail: `Stored state: <code>${escapeHTML(s.state)}</code><br>Returned state: <code>${escapeHTML(gotState)}</code><br>${stateOK ? 'Match — request is authentic.' : '<strong>Mismatch — abort.</strong>'}`,
  });
  if (!stateOK) {
    render(res, 'Callback — state mismatch', renderCards(cards) + '<p><a href="/">Start over</a></p>');
    return;
  }

  // Card 3: Token exchange — send code_verifier + HTTP Basic auth.
  // Note: uses Node 18+ built-in fetch; no node-fetch dependency required.
  const tokenURL = `${authPath}/${envID}/as/token`;
  const basic = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  const formBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code: gotCode,
    redirect_uri: redirectURI,
    code_verifier: s.verifier,
  }).toString();

  let tokRaw = '';
  let tokParsed = null;
  let tokStatus = 0;
  let tokErr = null;
  try {
    const tokResp = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + basic,
      },
      body: formBody,
    });
    tokStatus = tokResp.status;
    tokRaw = await tokResp.text();
    try { tokParsed = JSON.parse(tokRaw); } catch (_) {}
  } catch (e) {
    tokErr = e;
  }

  cards.push({
    title: '3. Exchange code for tokens',
    ok: !tokErr && tokStatus < 400,
    url: 'POST ' + tokenURL,
    detail: `Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>Form body:<br>&nbsp;&nbsp;<code>grant_type=authorization_code</code><br>&nbsp;&nbsp;<code>code=${escapeHTML(gotCode)}</code><br>&nbsp;&nbsp;<code>redirect_uri=${escapeHTML(redirectURI)}</code><br>&nbsp;&nbsp;<strong><code>code_verifier=${escapeHTML(s.verifier)}</code></strong> ← PingOne re-hashes this and compares to the original code_challenge<br>HTTP ${tokStatus}`,
    body: prettyJSONOrRaw(tokRaw),
  });
  if (tokErr || tokStatus >= 400) {
    render(res, 'Callback — token exchange failed', renderCards(cards) + '<p><a href="/">Start over</a></p>');
    return;
  }

  const idToken      = (tokParsed && tokParsed.id_token)      || '';
  const accessToken  = (tokParsed && tokParsed.access_token)  || '';
  const refreshToken = (tokParsed && tokParsed.refresh_token) || '';
  s.accessToken  = accessToken;
  s.idToken      = idToken;
  s.refreshToken = refreshToken;

  // Card 4: Decode ID token. Do NOT trust any claim until after signature
  // verification in card 6.
  let jwtHeader  = null;
  let jwtPayload = null;
  let decodeErr  = null;
  try {
    const decoded = decodeJWT(idToken);
    jwtHeader  = decoded.header;
    jwtPayload = decoded.payload;
  } catch (e) {
    decodeErr = e;
  }
  cards.push({
    title: '4. Decode ID token',
    ok: !decodeErr,
    detail: 'An ID token is a JWS: three base64url segments separated by dots. The header tells us which key to use; the payload contains the claims; the signature must be verified before any claim is trusted.',
    body: decodeErr
      ? String(decodeErr)
      : `header:\n${prettyJSON(jwtHeader)}\n\npayload:\n${prettyJSON(jwtPayload)}`,
  });

  // Card 5: Fetch JWKS — PingOne's public signing keys. Cache this in production
  // (respect Cache-Control headers). Re-fetch only if the kid is not found.
  const jwksURL = `${authPath}/${envID}/as/jwks`;
  let jwksRaw  = '';
  let jwks     = null;
  let jwksErr  = null;
  try {
    const jwksResp = await fetch(jwksURL);
    jwksRaw = await jwksResp.text();
    try { jwks = JSON.parse(jwksRaw); } catch (_) {}
  } catch (e) {
    jwksErr = e;
  }
  cards.push({
    title: '5. Fetch JWKS',
    ok: !jwksErr,
    url: 'GET ' + jwksURL,
    detail: 'Public keys used to verify ID token signatures. Keyed by <code>kid</code>; cache with care in production.',
    body: prettyJSONOrRaw(jwksRaw),
    collapsed: true,
  });

  // Card 6: Verify ID token signature — RS256 via the matched JWK.
  let verifyErr = null;
  try {
    verifyJWS(idToken, jwtHeader || {}, jwks || {});
  } catch (e) {
    verifyErr = e;
  }
  cards.push({
    title: '6. Verify ID token signature',
    ok: !verifyErr,
    detail: `alg: <code>${escapeHTML(String((jwtHeader && jwtHeader.alg) || ''))}</code>, kid: <code>${escapeHTML(String((jwtHeader && jwtHeader.kid) || ''))}</code><br>${verifyErr ? 'Signature INVALID: ' + escapeHTML(String(verifyErr)) : 'Signature valid (RS256, key matched by <code>kid</code>).'}`,
  });

  // Card 7: Validate ID token claims (iss, aud, exp, iat, nonce).
  const expectedIssuer = `${authPath}/${envID}/as`;
  const claimsErrs = jwtPayload ? validateIDClaims(jwtPayload, expectedIssuer, clientID, s.nonce) : { payload: 'could not decode' };
  cards.push({
    title: '7. Validate ID token claims',
    ok: Object.keys(claimsErrs).length === 0,
    detail: `Required checks: <code>iss</code> matches <code>${escapeHTML(expectedIssuer)}</code>, <code>aud</code> contains <code>${escapeHTML(clientID)}</code>, <code>exp</code> &gt; now, <code>iat</code> not in the future, <code>nonce</code> matches the value sent on /authorize.<br>${renderClaimChecks(claimsErrs)}`,
    body: jwtPayload ? prettyJSON(jwtPayload) : '',
  });
  s.idClaims = jwtPayload;

  // Card 8: /userinfo — returns profile claims for the authenticated user.
  // The access_token is presented as a Bearer token; PingOne validates it and
  // returns claims for the scopes that were granted.
  const userinfoURL = `${authPath}/${envID}/as/userinfo`;
  let uiRaw    = '';
  let uiStatus = 0;
  let uiErr    = null;
  try {
    const uiResp = await fetch(userinfoURL, {
      headers: { 'Authorization': 'Bearer ' + accessToken },
    });
    uiStatus = uiResp.status;
    uiRaw = await uiResp.text();
  } catch (e) {
    uiErr = e;
  }
  cards.push({
    title: '8. Call /userinfo',
    ok: !uiErr && uiStatus < 400,
    url: 'GET ' + userinfoURL,
    detail: `Header: <code>Authorization: Bearer &lt;access_token&gt;</code><br>HTTP ${uiStatus}`,
    body: prettyJSONOrRaw(uiRaw),
  });

  // Card 9: Final tokens — collapsed because the raw values are long and not
  // the focus of the walkthrough.
  cards.push({
    title: '9. Tokens',
    ok: true,
    detail: 'These are the final values returned by the token endpoint.',
    body: `access_token:\n${accessToken}\n\nid_token:\n${idToken}\n\nrefresh_token:\n${refreshToken}`,
    collapsed: true,
  });

  let body = renderCards(cards);
  if (refreshToken) {
    body += '\n<form action="/refresh" method="POST"><button type="submit">Use refresh token →</button></form>';
  }
  body += '\n<p style="margin-top:20px;"><a href="/">Start over</a></p>';
  render(res, 'Callback — complete', body);
});

/**
 * POST /refresh — use the stored refresh_token to obtain a new access_token.
 *
 * The refresh_token grant does NOT re-play PKCE — PKCE is only required for the
 * authorization_code exchange. Only HTTP Basic auth is needed here.
 *
 * PingOne typically rotates the refresh_token on every use (issues a new one and
 * invalidates the old). Always replace the stored refresh_token with the new value.
 */
app.post('/refresh', async (req, res) => {
  const s = getSession(req);
  if (!s || !s.refreshToken) {
    render(res, 'Refresh — error', '<p class="err">No refresh token in session. <a href="/">Start over</a>.</p>');
    return;
  }

  const tokenURL = `${authPath}/${envID}/as/token`;
  const basic = Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  const formBody = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: s.refreshToken,
  }).toString();

  let raw    = '';
  let parsed = null;
  let status = 0;
  let err    = null;
  try {
    const resp = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + basic,
      },
      body: formBody,
    });
    status = resp.status;
    raw = await resp.text();
    try { parsed = JSON.parse(raw); } catch (_) {}
  } catch (e) {
    err = e;
  }

  const cards = [
    {
      title: 'Refresh access token',
      ok: !err && status < 400,
      url: 'POST ' + tokenURL,
      detail: `Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>Form body:<br>&nbsp;&nbsp;<code>grant_type=refresh_token</code><br>&nbsp;&nbsp;<code>refresh_token=&lt;previous refresh_token&gt;</code><br>HTTP ${status}<br>Note: PKCE is not re-played here; the refresh grant authenticates only via client credentials. PingOne typically rotates the refresh_token on each use — store the new one.`,
      body: prettyJSONOrRaw(raw),
    },
  ];

  // Store the rotated tokens so a subsequent refresh still works.
  if (!err && status < 400 && parsed) {
    if (parsed.access_token)  s.accessToken  = parsed.access_token;
    if (parsed.id_token)      s.idToken      = parsed.id_token;
    if (parsed.refresh_token) s.refreshToken = parsed.refresh_token;
  }

  render(res, 'Refresh — result', renderCards(cards) + '<p><a href="/">Start over</a></p>');
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

app.listen(3000, () => {
  console.log('OIDC Auth Code + PKCE demo on http://localhost:3000');
});
