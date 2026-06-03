"""
OIDC Authorization Code Flow with PKCE — Python/Flask single-file sample.

WHY PKCE?
The standard authorization_code flow is vulnerable to authorization code
interception: a malicious process on the same device can register the same
redirect URI and steal the code before your app redeems it. PKCE (RFC 7636,
Proof Key for Code Exchange) closes that gap. Before redirecting the user,
the client generates a random secret (code_verifier) and sends only a one-way
hash of it (code_challenge) to the authorization server. When the code is
later exchanged at the token endpoint, the client sends the original verifier.
The server re-hashes it and verifies the match — only the app that generated
the verifier can complete the exchange.

This sample uses a CONFIDENTIAL client: the token endpoint receives both
HTTP Basic auth (client_id + client_secret) AND the PKCE code_verifier.

NINE-STEP FLOW:
  1. Generate code_verifier  — 32 random bytes, base64url-no-pad encoded
  2. Compute code_challenge  — base64url-no-pad(SHA-256(ASCII(code_verifier)))
  3. Generate state + nonce  — CSRF and replay protection
  4. Build GET /as/authorize URL with code_challenge + code_challenge_method=S256
  5. Receive callback        — PingOne 302s back with ?code=...&state=...
  6. Validate state          — abort on mismatch (CSRF check)
  7. POST /as/token          — exchange code + code_verifier + HTTP Basic
  8. Decode + verify ID token (RS256 signature against JWKS)
  9. GET /as/userinfo        — fetch profile claims with the access token

PINGONE PREREQUISITES:
  - OIDC Web App: response_type=code, grant_type=authorization_code,
    Token Endpoint Auth Method = CLIENT_SECRET_BASIC,
    PKCE Enforcement = REQUIRED, redirect URI = PINGONE_REDIRECT_URI.
"""

import os
import secrets
import hashlib
import base64
import json
import time
import html
import logging
import urllib.parse

import requests
from dotenv import load_dotenv
from flask import Flask, request, make_response

# Embed the logo as a base64 data URL so no separate static-file route is needed.
_logo_path = os.path.join(os.path.dirname(__file__), '..', '..', 'assets', 'logo.png')
LOGO_SRC = 'data:image/png;base64,' + base64.b64encode(open(_logo_path, 'rb').read()).decode()

# cryptography is used for RS256 signature verification.
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Configuration — loaded from .env (or from the process environment)
# ---------------------------------------------------------------------------

load_dotenv()

ENV_ID        = os.getenv("PINGONE_ENV_ID")
CLIENT_ID     = os.getenv("PINGONE_CLIENT_ID")
CLIENT_SECRET = os.getenv("PINGONE_CLIENT_SECRET")
# Trailing slash removed so URL concatenation is consistent regardless of how
# the variable is set in .env.
AUTH_PATH     = (os.getenv("PINGONE_AUTH_PATH") or "").rstrip("/")
REDIRECT_URI  = os.getenv("PINGONE_REDIRECT_URI")
SCOPES        = os.getenv("PINGONE_SCOPES")

if not all([ENV_ID, CLIENT_ID, CLIENT_SECRET, AUTH_PATH, REDIRECT_URI, SCOPES]):
    raise SystemExit("Missing required environment variables. Please check your .env file.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("p1-oidc-pkce")

# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------
# Single-process in-memory dict keyed by an opaque "sid" cookie value.
# The PKCE artifacts (verifier, state, nonce) must survive the full-page
# redirect to PingOne and back — they cannot live in a closure, they must
# be persisted server-side and correlated to the browser via the cookie.
# Production apps should use Redis or a database-backed session store.

SESSION_STORE: dict[str, dict] = {}


def get_session(req) -> dict | None:
    """Look up the session for the current request via the 'sid' cookie.
    Returns None if no matching session exists.
    """
    sid = req.cookies.get("sid")
    if sid:
        return SESSION_STORE.get(sid)
    return None


def new_session(response) -> tuple[str, dict]:
    """Create a fresh session, persist it, and set the 'sid' cookie.

    HttpOnly prevents JavaScript from reading the cookie value; SameSite=Lax
    allows the browser to send the cookie on top-level navigations (e.g. the
    PingOne callback redirect) while blocking it on cross-site sub-requests.
    """
    sid = secrets.token_hex(16)
    s: dict = {}
    SESSION_STORE[sid] = s
    response.set_cookie("sid", sid, httponly=True, samesite="Lax", path="/")
    return sid, s


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def pretty_json(obj) -> str:
    return json.dumps(obj, indent=2)


def pretty_json_or_raw(raw: str) -> str:
    """Pretty-print if raw is valid JSON, otherwise return it unchanged."""
    try:
        return json.dumps(json.loads(raw), indent=2)
    except (ValueError, TypeError):
        return raw


# ---------------------------------------------------------------------------
# JWT / JWS helpers
# ---------------------------------------------------------------------------

def decode_jwt(token: str) -> tuple[dict, dict]:
    """Decode a compact-serialized JWT into (header, payload) without verifying
    the signature. Call verify_jws() separately before trusting any claims.

    JWT segments are base64url-encoded without padding. Python's standard library
    requires the padding to be restored before decoding: add "==" and let
    base64.urlsafe_b64decode ignore the excess padding.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"not a 3-part JWT: {len(parts)} parts")
    header_bytes  = base64.urlsafe_b64decode(parts[0] + "==")
    payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
    header  = json.loads(header_bytes)
    payload = json.loads(payload_bytes)
    return header, payload


def jwk_to_rsa_public_key(jwk: dict):
    """Reconstruct an RSA public key from a JWK dict.

    The JWK "n" and "e" fields are base64url-encoded big-endian integers.
    "n" is the RSA modulus; "e" is the public exponent (typically 65537 = 0x010001).
    Adding "==" padding before decoding is safe — Python's urlsafe_b64decode
    ignores excess padding characters.
    """
    n_bytes = base64.urlsafe_b64decode(jwk["n"] + "==")
    e_bytes = base64.urlsafe_b64decode(jwk["e"] + "==")
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    return RSAPublicNumbers(e, n).public_key()


def verify_jws(token: str, header: dict, jwks: dict) -> None:
    """Verify an RS256 JWS token against the public keys in a JWKS document.
    Raises ValueError or InvalidSignature on any failure.

    The RS256 signing input is the ASCII string "header_b64url.payload_b64url"
    — the raw base64url segments from the token, not re-encoded from parsed JSON.
    The signature covers exactly these bytes; any re-encoding would break verification.
    """
    alg = header.get("alg")
    if alg != "RS256":
        raise ValueError(f"unsupported alg {alg!r} (this sample verifies RS256 only)")
    kid = header.get("kid")
    keys = jwks.get("keys", [])
    # Match the key by kid. Never fall back to a random key — that would silently
    # accept tokens signed by an unknown key.
    match = None
    for k in keys:
        if k.get("kid") == kid:
            match = k
            break
    if match is None:
        raise ValueError(f"no JWK with kid={kid!r}")
    pub = jwk_to_rsa_public_key(match)
    parts = token.split(".")
    signed_input = f"{parts[0]}.{parts[1]}".encode()
    sig = base64.urlsafe_b64decode(parts[2] + "==")
    try:
        pub.verify(sig, signed_input, PKCS1v15(), SHA256())
    except InvalidSignature:
        raise InvalidSignature("Signature verification failed")


def validate_id_claims(payload: dict, expected_issuer: str, expected_aud: str, expected_nonce: str) -> dict[str, str]:
    """Validate standard OIDC Core §3.1.3.7 ID token claims.
    Returns a dict of claim name → error message for any failures.
    An empty dict means all checks passed.

    Checks performed:
      iss   — must match the PingOne issuer for this environment
      aud   — may be a string or list; must contain our CLIENT_ID
      exp   — must be > now (token not expired)
      iat   — must not be > now + 60 s (clock skew guard)
      nonce — must match the value we generated before the authorize redirect
    """
    errs: dict[str, str] = {}
    iss = payload.get("iss")
    if iss != expected_issuer:
        errs["iss"] = f"got {iss!r}, want {expected_issuer!r}"

    # aud may be a single string or a list (OIDC Core §2)
    aud = payload.get("aud")
    aud_ok = False
    if isinstance(aud, str):
        aud_ok = aud == expected_aud
    elif isinstance(aud, list):
        aud_ok = expected_aud in aud
    if not aud_ok:
        errs["aud"] = f"does not contain {expected_aud!r}"

    now = time.time()
    exp = payload.get("exp")
    if exp is None:
        errs["exp"] = "missing or non-numeric"
    elif exp < now:
        errs["exp"] = f"expired (exp={int(exp)}, now={int(now)})"

    iat = payload.get("iat")
    if iat is not None and iat > now + 60:
        errs["iat"] = f"in the future (iat={int(iat)}, now={int(now)})"

    nonce = payload.get("nonce")
    if nonce != expected_nonce:
        errs["nonce"] = f"got {nonce!r}, want {expected_nonce!r}"

    return errs


# ---------------------------------------------------------------------------
# HTML rendering helpers
# ---------------------------------------------------------------------------

def render_claim_checks(errs: dict) -> str:
    """Render the result of validate_id_claims() as an HTML fragment.
    An empty dict produces a green 'All claims valid.' message.
    """
    if not errs:
        return '<span style="color:#0a7a0a;">All claims valid.</span>'
    items = "".join(
        f"<li><code>{html.escape(k)}</code>: {html.escape(v)}</li>"
        for k, v in errs.items()
    )
    return f'<ul style="color:#b00020;">{items}</ul>'


def render_cards(cards: list[dict]) -> str:
    """Render a list of step-card dicts to an HTML string.

    Each card dict may have:
      title     — plain text (HTML-escaped before output)
      ok        — bool; drives green/red heading colour
      url       — optional request line shown in a monospace badge
      detail    — trusted HTML (already safe); output raw
      body      — plain text response body; HTML-escaped before <pre>
      collapsed — bool; when true the body starts hidden
    """
    parts = []
    for c in cards:
        title = html.escape(c.get("title", ""))
        ok = c.get("ok", False)
        status_class = "ok" if ok else "err"
        status_label = "(ok)" if ok else "(failed)"

        card_html = f'<div class="card">\n'
        card_html += f'  <h3 class="{status_class}">{title} {status_label}</h3>\n'

        url = c.get("url", "")
        if url:
            card_html += f'  <div class="url">{html.escape(url)}</div>\n'

        detail = c.get("detail", "")
        if detail:
            # detail is trusted HTML — output raw (the caller is responsible for escaping)
            card_html += f"  <div>{detail}</div>\n"

        body = c.get("body", "")
        if body:
            escaped_body = html.escape(body)
            collapsed = c.get("collapsed", False)
            if collapsed:
                card_html += f"  <details><summary>Show response</summary><pre>{escaped_body}</pre></details>\n"
            else:
                card_html += f"  <details open><summary>Hide</summary><pre>{escaped_body}</pre></details>\n"

        card_html += "</div>"
        parts.append(card_html)
    return "\n".join(parts)


def render_page(title: str, body_html: str) -> str:
    """Wrap a body fragment in the shared page shell (header, styles, layout)."""
    escaped_title = html.escape(title)
    return f"""<!DOCTYPE html>
<html>
<head>
<title>{escaped_title}</title>
<style>
  body{{font-family:sans-serif; margin:0; background:#f5f5f5;}}
  h2{{margin-top:0;}}
  button{{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;}}
  pre{{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all; margin:0;}}
  code{{background:#f0f0f0; padding:1px 4px; border-radius:2px;}}
  .card{{margin-top:18px; padding:14px 16px; border:1px solid #ddd; border-radius:4px; background:#fff;}}
  .card h3{{margin:0 0 6px 0;}}
  .ok{{color:#0a7a0a;}}
  .err{{color:#b00020;}}
  .url{{font-family:monospace; font-size:13px; color:#555; background:#f0f0f0; padding:4px 8px; border-radius:3px; display:block; margin:6px 0; word-break:break-all;}}
  details{{margin-top:6px;}}
  summary{{cursor:pointer; font-size:13px; color:#444; user-select:none; padding:2px 0;}}
  details pre{{margin-top:4px;}}
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
{body_html}
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    """Landing page with description and 'Begin Login' button."""
    body_html = f"""
<h2>OIDC Authorization Code + PKCE (confidential client)</h2>
<p>This sample walks through every artifact in the OIDC Authorization Code flow with PKCE so you can see exactly what each value is, how it's derived, and how it's validated.</p>
<p>The client is <strong>confidential</strong> &mdash; the token endpoint is called with HTTP Basic auth (client ID + secret) AND the PKCE <code>code_verifier</code>.</p>
<form action="/prepare" method="POST"><button type="submit">Begin Login</button></form>
<p style="color:#666;font-size:13px;margin-top:30px;">PingOne config required: OIDC Web App with PKCE Enforcement = REQUIRED, Token Endpoint Auth Method = Client Secret Basic, redirect URI = {html.escape(REDIRECT_URI)}</p>
"""
    return render_page("OIDC Auth Code + PKCE — start", body_html)


@app.route("/prepare", methods=["POST"])
def prepare():
    """Generate PKCE artifacts, store in session, redirect to prepare-result.

    Uses the PRG (Post-Redirect-Get) pattern: the POST creates the session and
    computes all artifacts, then redirects to a GET so that browser reload or
    back-button cannot re-POST and create a second session with a different state
    while the first authorize URL is still in flight.

    Step 1: code_verifier
      32 cryptographically random bytes encoded as base64url without padding.
      Python's base64.urlsafe_b64encode adds "=" padding; rstrip(b"=") removes it.
      RFC 7636 §4.1 requires 43-128 characters from [A-Za-z0-9-._~]; base64url
      output naturally satisfies this.

    Step 2: code_challenge
      hashlib.sha256(verifier.encode()).digest() produces the raw 32-byte digest.
      base64.urlsafe_b64encode then rstrip("=") gives the correct base64url-no-pad
      encoding. Using standard base64 would produce "+" and "/" characters that
      are not URL-safe, and the "=" padding is forbidden by RFC 7636.

    Step 3: state + nonce
      secrets.token_hex(16) produces 32 hex characters from the OS CSPRNG.
      state is echoed by PingOne in the callback query string; we compare it to
      the stored value (CSRF protection). nonce is embedded as a claim in the ID
      token; we compare it to the stored value (replay protection).

    Step 4: Build /authorize URL
      code_challenge_method must be exactly "S256" (uppercase). This is a fixed
      string literal in the RFC, not derived from any algorithm name.
    """
    # 1. code_verifier — RFC 7636: 43-128 chars from unreserved set [A-Za-z0-9-._~].
    # base64url-no-pad of 32 random bytes yields 43 chars that fall entirely within the unreserved set.
    verifier_bytes = secrets.token_bytes(32)
    verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode()

    # 2. code_challenge = base64url-nopad( SHA-256( ASCII(code_verifier) ) )
    hash_bytes = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(hash_bytes).rstrip(b"=").decode()

    # 3. state + nonce — independent random values for CSRF and replay protection.
    state = secrets.token_hex(16)
    nonce = secrets.token_hex(16)

    # 4. Build /authorize URL
    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    authorize_url = f"{AUTH_PATH}/{ENV_ID}/as/authorize?{params}"

    # Store everything in the session under a new sid. The PRG redirect will then
    # serve the results page as a GET using this session.
    sid = secrets.token_hex(16)
    SESSION_STORE[sid] = {
        "verifier": verifier,
        "verifier_bytes_len": len(verifier_bytes),
        "verifier_len": len(verifier),
        "challenge": challenge,
        "hash_hex": hash_bytes.hex(),
        "state": state,
        "nonce": nonce,
        "authorize_url": authorize_url,
        "access_token": "",
        "id_token": "",
        "refresh_token": "",
        "id_claims": {},
    }

    resp = make_response("", 303)
    resp.headers["Location"] = "/prepare-result"
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax", path="/")
    return resp


@app.route("/prepare-result", methods=["GET"])
def prepare_result():
    """Display the PKCE artifact cards generated by /prepare.

    This is the GET half of the Post-Redirect-Get. It reads the artifacts from
    the session and renders them as step cards so the developer can inspect each
    value before clicking through to PingOne.
    """
    s = get_session(request)
    if s is None or "authorize_url" not in s:
        from flask import redirect as flask_redirect
        return flask_redirect("/")

    verifier            = s["verifier"]
    challenge           = s["challenge"]
    hash_hex            = s["hash_hex"]
    state               = s["state"]
    nonce               = s["nonce"]
    authorize_url       = s["authorize_url"]
    verifier_bytes_len  = s["verifier_bytes_len"]
    verifier_len        = s["verifier_len"]

    cards = [
        {
            "title": "1. Generate code_verifier",
            "ok": True,
            "detail": (
                f"Random {verifier_bytes_len} bytes &rarr; <code>base64url</code>-no-pad &rarr; "
                f"{verifier_len}-char verifier. RFC 7636 &sect;4.1 allows 43-128 chars from the unreserved set "
                f"<code>[A-Za-z0-9-._~]</code>; base64url output naturally falls in that set."
            ),
            "body": verifier,
        },
        {
            "title": "2. Compute code_challenge",
            "ok": True,
            "detail": (
                "<code>code_challenge = base64url-no-pad( SHA-256( ASCII(code_verifier) ) )</code><br>"
                "<code>code_challenge_method = S256</code>"
            ),
            "body": f"SHA-256 digest (hex):\n  {hash_hex}\n\nbase64url-no-pad encoding:\n  {challenge}",
        },
        {
            "title": "3. Generate state and nonce",
            "ok": True,
            "detail": (
                "Both are random opaque strings: <code>state</code> defends the callback from CSRF; "
                "<code>nonce</code> is echoed back as a claim in the ID token to defend against replay."
            ),
            "body": f"state: {state}\nnonce: {nonce}",
        },
        {
            "title": "4. Build /authorize URL",
            "ok": True,
            "url": f"GET {authorize_url}",
            "detail": (
                f"Click the button below to redirect to PingOne. After you authenticate, PingOne will "
                f"302 back to <code>{html.escape(REDIRECT_URI)}</code> with a <code>code</code> and the original <code>state</code>."
            ),
        },
    ]

    body_html = render_cards(cards)
    body_html += f'\n<p><a href="{html.escape(authorize_url)}"><button>Continue to PingOne &rarr;</button></a></p>'
    return render_page("Step 1 — Prepare PKCE artifacts", body_html)


@app.route("/callback", methods=["GET"])
def callback():
    """OAuth 2.0 redirect URI handler — PingOne calls this after authentication.

    PingOne appends ?code=...&state=... to this URL after the user authenticates.

    Step 1: Extract code and state from the query string.
    Step 2: Validate state — compare to the stored value. A mismatch means this
      callback was not initiated by this app (CSRF). Abort immediately.
    Step 3: Exchange code for tokens at POST /as/token:
      - code_verifier proves this client generated the code_challenge in the
        authorize request; PingOne re-hashes and compares.
      - redirect_uri must exactly match the value sent in /authorize AND the
        URI registered on the PingOne application — all three must agree.
      - HTTP Basic auth (CLIENT_SECRET_BASIC): client_id and client_secret are
        passed via the Authorization header, not in the form body.
    Steps 4-9: Decode + verify ID token, validate claims, call /userinfo.
    """
    s = get_session(request)
    if s is None:
        return render_page(
            "Callback — error",
            '<p class="err">No session found. Cookies may have been blocked. <a href="/">Start over</a>.</p>',
        )

    code  = request.args.get("code", "")
    state = request.args.get("state", "")
    error = request.args.get("error", "")

    cards = []

    if error:
        error_desc = request.args.get("error_description", "")
        cards.append({
            "title": "Callback received an error",
            "ok": False,
            "detail": (
                f"<code>error={html.escape(error)}</code><br>"
                f"<code>error_description={html.escape(error_desc)}</code>"
            ),
            "body": request.query_string.decode(),
        })
        return render_page(
            "Callback — error",
            render_cards(cards) + '<p><a href="/">Start over</a></p>',
        )

    # Card 1: Receive callback. The authorization code is single-use — PingOne
    # invalidates it immediately after the token exchange (or on expiry ~2 min).
    cards.append({
        "title": "1. Receive callback",
        "ok": True,
        "url": f"GET {REDIRECT_URI}?{request.query_string.decode()}",
        "detail": (
            "PingOne redirected the browser back with <code>code</code> and <code>state</code>. "
            "The <code>code</code> is single-use and short-lived."
        ),
        "body": f"code:  {code}\nstate: {state}",
    })

    # Card 2: Validate state — defends against CSRF.
    # Never proceed to token exchange if the state does not match.
    state_ok = state == s.get("state", "")
    cards.append({
        "title": "2. Validate state",
        "ok": state_ok,
        "detail": (
            f"Stored state: <code>{html.escape(s.get('state', ''))}</code><br>"
            f"Returned state: <code>{html.escape(state)}</code><br>"
            + ("Match &mdash; request is authentic." if state_ok else "<strong>Mismatch &mdash; abort.</strong>")
        ),
    })
    if not state_ok:
        return render_page(
            "Callback — state mismatch",
            render_cards(cards) + '<p><a href="/">Start over</a></p>',
        )

    # Card 3: Token exchange.
    # requests' auth=(CLIENT_ID, CLIENT_SECRET) encodes the credentials as HTTP
    # Basic auth (base64(client_id:client_secret) in the Authorization header).
    token_url = f"{AUTH_PATH}/{ENV_ID}/as/token"
    tok_resp = requests.post(
        token_url,
        data={
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  REDIRECT_URI,
            "code_verifier": s.get("verifier", ""),
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    tok_status = tok_resp.status_code
    tok_raw    = tok_resp.text
    try:
        tok_parsed = tok_resp.json()
    except ValueError:
        tok_parsed = {}

    cards.append({
        "title": "3. Exchange code for tokens",
        "ok": tok_status < 400,
        "url": f"POST {token_url}",
        "detail": (
            "Headers:<br>"
            "&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>"
            "&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>"
            "Form body:<br>"
            "&nbsp;&nbsp;<code>grant_type=authorization_code</code><br>"
            f"&nbsp;&nbsp;<code>code={html.escape(code)}</code><br>"
            f"&nbsp;&nbsp;<code>redirect_uri={html.escape(REDIRECT_URI)}</code><br>"
            f"&nbsp;&nbsp;<strong><code>code_verifier={html.escape(s.get('verifier', ''))}</code></strong> "
            "&larr; PingOne re-hashes this and compares to the original code_challenge<br>"
            f"HTTP {tok_status}"
        ),
        "body": pretty_json_or_raw(tok_raw),
    })
    if tok_status >= 400:
        return render_page(
            "Callback — token exchange failed",
            render_cards(cards) + '<p><a href="/">Start over</a></p>',
        )

    id_token      = tok_parsed.get("id_token", "")
    access_token  = tok_parsed.get("access_token", "")
    refresh_token = tok_parsed.get("refresh_token", "")
    s["access_token"]  = access_token
    s["id_token"]      = id_token
    s["refresh_token"] = refresh_token

    # Card 4: Decode ID token. Do NOT trust any claim until after signature
    # verification in card 6.
    try:
        jwt_header, jwt_payload = decode_jwt(id_token)
        decode_err = None
    except (ValueError, Exception) as exc:
        jwt_header, jwt_payload = {}, {}
        decode_err = exc

    cards.append({
        "title": "4. Decode ID token",
        "ok": decode_err is None,
        "detail": (
            "An ID token is a JWS: three base64url segments separated by dots. "
            "The header tells us which key to use; the payload contains the claims; "
            "the signature must be verified before any claim is trusted."
        ),
        "body": (
            f"header:\n{pretty_json(jwt_header)}\n\npayload:\n{pretty_json(jwt_payload)}"
            if decode_err is None
            else str(decode_err)
        ),
    })

    # Card 5: Fetch JWKS — PingOne's public signing keys.
    # In production, cache this response (respect Cache-Control headers).
    # Re-fetch only when a kid is not found in the cached set.
    jwks_url = f"{AUTH_PATH}/{ENV_ID}/as/jwks"
    try:
        jwks_resp = requests.get(jwks_url)
        jwks_raw  = jwks_resp.text
        jwks      = jwks_resp.json()
        jwks_err  = None
    except Exception as exc:
        jwks_raw = ""
        jwks     = {}
        jwks_err = exc

    cards.append({
        "title": "5. Fetch JWKS",
        "ok": jwks_err is None,
        "url": f"GET {jwks_url}",
        "detail": "Public keys used to verify ID token signatures. Keyed by <code>kid</code>; cache with care in production.",
        "body": pretty_json_or_raw(jwks_raw),
        "collapsed": True,
    })

    # Card 6: Verify ID token signature — RS256 via the matched JWK.
    try:
        verify_jws(id_token, jwt_header, jwks)
        verify_err = None
    except (InvalidSignature, ValueError, Exception) as exc:
        verify_err = exc

    alg_val = html.escape(str(jwt_header.get("alg", "")))
    kid_val = html.escape(str(jwt_header.get("kid", "")))
    if verify_err is None:
        verify_detail = (
            f"alg: <code>{alg_val}</code>, kid: <code>{kid_val}</code><br>"
            "Signature valid (RS256, key matched by <code>kid</code>)."
        )
    else:
        verify_detail = (
            f"alg: <code>{alg_val}</code>, kid: <code>{kid_val}</code><br>"
            f"Signature INVALID: {html.escape(str(verify_err))}"
        )

    cards.append({
        "title": "6. Verify ID token signature",
        "ok": verify_err is None,
        "detail": verify_detail,
    })

    # Card 7: Validate ID token claims (iss, aud, exp, iat, nonce).
    expected_issuer = f"{AUTH_PATH}/{ENV_ID}/as"
    claims_errs = validate_id_claims(jwt_payload, expected_issuer, CLIENT_ID, s.get("nonce", ""))
    cards.append({
        "title": "7. Validate ID token claims",
        "ok": len(claims_errs) == 0,
        "detail": (
            f"Required checks: <code>iss</code> matches <code>{html.escape(expected_issuer)}</code>, "
            f"<code>aud</code> contains <code>{html.escape(CLIENT_ID)}</code>, "
            "<code>exp</code> &gt; now, <code>iat</code> not in the future, "
            "<code>nonce</code> matches the value sent on /authorize.<br>"
            + render_claim_checks(claims_errs)
        ),
        "body": pretty_json(jwt_payload),
    })
    s["id_claims"] = jwt_payload

    # Card 8: /userinfo — fetch profile claims for the authenticated user.
    # The access token is presented as a Bearer token; PingOne validates it and
    # returns the claims for the scopes that were granted.
    userinfo_url = f"{AUTH_PATH}/{ENV_ID}/as/userinfo"
    try:
        ui_resp   = requests.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
        ui_status = ui_resp.status_code
        ui_raw    = ui_resp.text
        ui_err    = None
    except Exception as exc:
        ui_status = 0
        ui_raw    = ""
        ui_err    = exc

    cards.append({
        "title": "8. Call /userinfo",
        "ok": ui_err is None and ui_status < 400,
        "url": f"GET {userinfo_url}",
        "detail": f"Header: <code>Authorization: Bearer &lt;access_token&gt;</code><br>HTTP {ui_status}",
        "body": pretty_json_or_raw(ui_raw),
    })

    # Card 9: Final tokens — collapsed because the raw values are long and not
    # the focus of the walkthrough.
    cards.append({
        "title": "9. Tokens",
        "ok": True,
        "detail": "These are the final values returned by the token endpoint.",
        "body": f"access_token:\n{access_token}\n\nid_token:\n{id_token}\n\nrefresh_token:\n{refresh_token}",
        "collapsed": True,
    })

    body_html = render_cards(cards)
    if refresh_token:
        body_html += '\n<form action="/refresh" method="POST"><button type="submit">Use refresh token &rarr;</button></form>'
    body_html += '\n<p style="margin-top:20px;"><a href="/">Start over</a></p>'
    return render_page("Callback — complete", body_html)


@app.route("/refresh", methods=["POST"])
def refresh():
    """Use the stored refresh_token to obtain a new access_token without re-authenticating.

    The refresh_token grant does NOT re-play PKCE — PKCE only applies to the
    initial authorization_code exchange. Only HTTP Basic auth is needed here.

    PingOne typically rotates the refresh_token on every use (issues a new token
    and invalidates the old one). Always replace the stored token with the new value.
    """
    s = get_session(request)
    if s is None or not s.get("refresh_token"):
        return render_page(
            "Refresh — error",
            '<p class="err">No refresh token in session. <a href="/">Start over</a>.</p>',
        )

    token_url = f"{AUTH_PATH}/{ENV_ID}/as/token"
    try:
        resp = requests.post(
            token_url,
            data={
                "grant_type":    "refresh_token",
                "refresh_token": s["refresh_token"],
            },
            auth=(CLIENT_ID, CLIENT_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        status = resp.status_code
        raw    = resp.text
        try:
            parsed = resp.json()
        except ValueError:
            parsed = {}
        err = None
    except Exception as exc:
        status = 0
        raw    = ""
        parsed = {}
        err    = exc

    cards = [
        {
            "title": "Refresh access token",
            "ok": err is None and status < 400,
            "url": f"POST {token_url}",
            "detail": (
                "Headers:<br>"
                "&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>"
                "&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>"
                "Form body:<br>"
                "&nbsp;&nbsp;<code>grant_type=refresh_token</code><br>"
                "&nbsp;&nbsp;<code>refresh_token=&lt;previous refresh_token&gt;</code><br>"
                f"HTTP {status}<br>"
                "Note: PKCE is not re-played here; the refresh grant authenticates only via client credentials. "
                "PingOne typically rotates the refresh_token on each use &mdash; store the new one."
            ),
            "body": pretty_json_or_raw(raw),
        }
    ]

    # Store the rotated tokens so a subsequent refresh still works.
    if err is None and status < 400:
        if parsed.get("access_token"):
            s["access_token"] = parsed["access_token"]
        if parsed.get("id_token"):
            s["id_token"] = parsed["id_token"]
        if parsed.get("refresh_token"):
            s["refresh_token"] = parsed["refresh_token"]

    return render_page(
        "Refresh — result",
        render_cards(cards) + '<p><a href="/">Start over</a></p>',
    )


if __name__ == "__main__":
    print("OIDC Auth Code + PKCE demo on http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=False)
