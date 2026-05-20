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

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

load_dotenv()

ENV_ID = os.getenv("PINGONE_ENV_ID")
CLIENT_ID = os.getenv("PINGONE_CLIENT_ID")
CLIENT_SECRET = os.getenv("PINGONE_CLIENT_SECRET")
AUTH_PATH = (os.getenv("PINGONE_AUTH_PATH") or "").rstrip("/")
REDIRECT_URI = os.getenv("PINGONE_REDIRECT_URI")
SCOPES = os.getenv("PINGONE_SCOPES")

if not all([ENV_ID, CLIENT_ID, CLIENT_SECRET, AUTH_PATH, REDIRECT_URI, SCOPES]):
    raise SystemExit("Missing required environment variables. Please check your .env file.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("p1-oidc-pkce")

# --- session store ---
# Single-process in-memory session store keyed by an opaque "sid" cookie.
# Persists PKCE artifacts across the redirect to PingOne and back.
SESSION_STORE: dict[str, dict] = {}


def get_session(req) -> dict | None:
    sid = req.cookies.get("sid")
    if sid:
        return SESSION_STORE.get(sid)
    return None


def new_session(response) -> tuple[str, dict]:
    sid = secrets.token_hex(16)
    s: dict = {}
    SESSION_STORE[sid] = s
    response.set_cookie("sid", sid, httponly=True, samesite="Lax", path="/")
    return sid, s


# --- helpers ---

def pretty_json(obj) -> str:
    return json.dumps(obj, indent=2)


def pretty_json_or_raw(raw: str) -> str:
    try:
        return json.dumps(json.loads(raw), indent=2)
    except (ValueError, TypeError):
        return raw


def decode_jwt(token: str) -> tuple[dict, dict]:
    """Split on '.', base64url-decode each part, parse JSON. Raise ValueError if not 3 parts."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"not a 3-part JWT: {len(parts)} parts")
    header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
    payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
    header = json.loads(header_bytes)
    payload = json.loads(payload_bytes)
    return header, payload


def jwk_to_rsa_public_key(jwk: dict):
    n_bytes = base64.urlsafe_b64decode(jwk["n"] + "==")
    e_bytes = base64.urlsafe_b64decode(jwk["e"] + "==")
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    return RSAPublicNumbers(e, n).public_key()


def verify_jws(token: str, header: dict, jwks: dict) -> None:
    """Verify a JWS token signature using RS256. Raises on failure."""
    alg = header.get("alg")
    if alg != "RS256":
        raise ValueError(f"unsupported alg {alg!r} (this sample verifies RS256 only)")
    kid = header.get("kid")
    keys = jwks.get("keys", [])
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
    """Validate standard OIDC ID token claims. Returns dict of error messages (empty = all valid)."""
    errs: dict[str, str] = {}
    iss = payload.get("iss")
    if iss != expected_issuer:
        errs["iss"] = f"got {iss!r}, want {expected_issuer!r}"

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


def render_claim_checks(errs: dict) -> str:
    if not errs:
        return '<span style="color:#0a7a0a;">All claims valid.</span>'
    items = "".join(
        f"<li><code>{html.escape(k)}</code>: {html.escape(v)}</li>"
        for k, v in errs.items()
    )
    return f'<ul style="color:#b00020;">{items}</ul>'


def render_cards(cards: list[dict]) -> str:
    """Render a list of card dicts to HTML.

    Card fields:
      title  — plain text
      ok     — bool
      url    — optional plain text shown in .url div
      detail — trusted HTML, output raw
      body   — plain text, HTML-escaped before embedding in <pre>
      collapsed — bool, whether the details element is open
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
            # detail is trusted HTML — output raw
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
    escaped_title = html.escape(title)
    return f"""<!DOCTYPE html>
<html>
<head>
<title>{escaped_title}</title>
<style>
  body{{font-family:sans-serif; margin:40px; max-width:980px;}}
  h2{{margin-top:0;}}
  button{{font-size:16px; padding:10px 20px; cursor:pointer;}}
  pre{{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all; margin:0;}}
  code{{background:#f0f0f0; padding:1px 4px; border-radius:2px;}}
  .card{{margin-top:18px; padding:14px 16px; border:1px solid #ddd; border-radius:4px;}}
  .card h3{{margin:0 0 6px 0;}}
  .ok{{color:#0a7a0a;}}
  .err{{color:#b00020;}}
  .url{{font-family:monospace; font-size:13px; color:#555; background:#eef; padding:4px 8px; border-radius:3px; display:block; margin:6px 0; word-break:break-all;}}
  details{{margin-top:6px;}}
  summary{{cursor:pointer; font-size:13px; color:#444; user-select:none; padding:2px 0;}}
  details pre{{margin-top:4px;}}
</style>
</head>
<body>
{body_html}
</body>
</html>"""


# --- Flask app ---

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
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

    # Store everything needed to render the prepare page in the session.
    # PRG (Post-Redirect-Get): create the session here, then redirect to a GET so that
    # browser reload / back-button can't re-POST and create a second session with a
    # different state while the first authorize URL is still in flight.
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
    s = get_session(request)
    if s is None or "authorize_url" not in s:
        from flask import redirect as flask_redirect
        return flask_redirect("/")

    verifier = s["verifier"]
    challenge = s["challenge"]
    hash_hex = s["hash_hex"]
    state = s["state"]
    nonce = s["nonce"]
    authorize_url = s["authorize_url"]
    verifier_bytes_len = s["verifier_bytes_len"]
    verifier_len = s["verifier_len"]

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
    s = get_session(request)
    if s is None:
        return render_page(
            "Callback — error",
            '<p class="err">No session found. Cookies may have been blocked. <a href="/">Start over</a>.</p>',
        )

    code = request.args.get("code", "")
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

    # Card 1: Receive callback
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

    # Card 2: Validate state — defends against CSRF
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

    # Card 3: Token exchange — confidential client: HTTP Basic + code_verifier
    token_url = f"{AUTH_PATH}/{ENV_ID}/as/token"
    tok_resp = requests.post(
        token_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": s.get("verifier", ""),
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    tok_status = tok_resp.status_code
    tok_raw = tok_resp.text
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

    id_token = tok_parsed.get("id_token", "")
    access_token = tok_parsed.get("access_token", "")
    refresh_token = tok_parsed.get("refresh_token", "")
    s["access_token"] = access_token
    s["id_token"] = id_token
    s["refresh_token"] = refresh_token

    # Card 4: Decode ID token (header + payload). Signature verification is the next step.
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

    # Card 5: Fetch JWKS
    jwks_url = f"{AUTH_PATH}/{ENV_ID}/as/jwks"
    try:
        jwks_resp = requests.get(jwks_url)
        jwks_raw = jwks_resp.text
        jwks = jwks_resp.json()
        jwks_err = None
    except Exception as exc:
        jwks_raw = ""
        jwks = {}
        jwks_err = exc

    cards.append({
        "title": "5. Fetch JWKS",
        "ok": jwks_err is None,
        "url": f"GET {jwks_url}",
        "detail": "Public keys used to verify ID token signatures. Keyed by <code>kid</code>; cache with care in production.",
        "body": pretty_json_or_raw(jwks_raw),
        "collapsed": True,
    })

    # Card 6: Verify ID token signature (RS256)
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

    # Card 7: Validate ID token claims
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

    # Card 8: Call /userinfo
    userinfo_url = f"{AUTH_PATH}/{ENV_ID}/as/userinfo"
    try:
        ui_resp = requests.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        ui_status = ui_resp.status_code
        ui_raw = ui_resp.text
        ui_err = None
    except Exception as exc:
        ui_status = 0
        ui_raw = ""
        ui_err = exc

    cards.append({
        "title": "8. Call /userinfo",
        "ok": ui_err is None and ui_status < 400,
        "url": f"GET {userinfo_url}",
        "detail": (
            f"Header: <code>Authorization: Bearer &lt;access_token&gt;</code><br>HTTP {ui_status}"
        ),
        "body": pretty_json_or_raw(ui_raw),
    })

    # Card 9: Final tokens (collapsed)
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
                "grant_type": "refresh_token",
                "refresh_token": s["refresh_token"],
            },
            auth=(CLIENT_ID, CLIENT_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        status = resp.status_code
        raw = resp.text
        try:
            parsed = resp.json()
        except ValueError:
            parsed = {}
        err = None
    except Exception as exc:
        status = 0
        raw = ""
        parsed = {}
        err = exc

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
