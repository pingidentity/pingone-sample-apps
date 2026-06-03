# PingOne Native Flows MFA Demo — Python / Flask
#
# Overview of the four-step flow:
#
#  1. GET /as/authorize?response_mode=pi.flow
#     Initialises a PingOne Flow session without redirecting the browser.
#     PingOne returns a JSON body whose "id" field is the flow ID used on all
#     subsequent /flows/{id} calls. PingOne also sets session cookies (ST,
#     ST-NO-SS) that must be captured and replayed verbatim on every later
#     call or PingOne will reject the request.
#
#  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.usernamePassword.check+json
#     Submits username + password to the active flow. The response "status"
#     field determines the next step:
#       "COMPLETED"                              — proceed to /as/resume
#       "OTP_REQUIRED" / "DEVICE_SELECTION_REQUIRED" /
#       "MULTI_FACTOR_AUTHENTICATION_REQUIRED"   — show the OTP form
#
#  3. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.otp.check+json
#     (only when MFA is required) Submits the one-time passcode. Status
#     "COMPLETED" means the OTP was accepted.
#
#  4. GET /as/resume?flowId={flowID}
#     Signals PingOne the native flow is complete. PingOne returns either a
#     JSON body with authorizeResponse.code or a 302 redirect to the
#     registered redirect_uri with ?code= in the query string. Both paths are
#     handled below. The code is then exchanged at POST /as/token for tokens.
#
# Why two PingOne apps?
#
#   /flows/{id} is a management-plane API. PingOne requires a Bearer token
#   from an admin worker app (client_credentials grant) on every /flows/{id}
#   call in addition to the session cookies. A separate end-user OIDC app
#   drives the flow and issues the final tokens.
#
# Key constraints:
#   - Accept: */* on all /flows/ and /as/authorize calls — PingOne uses vendor
#     content types (application/vnd.pingidentity.*+json) and returns 406 if
#     you restrict Accept to application/json.
#   - allow_redirects=False on all PingOne calls — the requests library must
#     not follow 302 responses so we can inspect the Location header ourselves.
#   - Cookies must be captured and replayed manually — the requests library's
#     built-in cookie handling respects RFC 6265 path scoping, which silently
#     drops PingOne's ST / ST-NO-SS cookies when the request path differs
#     between flow steps. Storing raw "name=value" strings and building the
#     Cookie header manually is the only reliable approach.

import os
import base64
import logging
from urllib.parse import urlparse, parse_qs

import requests
from dotenv import load_dotenv
from flask import Flask, request

load_dotenv()

# Embed the logo as a base64 data URI so the single-file app requires no
# separate static-file serving.
_logo_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'logo.png')
LOGO_SRC = 'data:image/png;base64,' + base64.b64encode(open(_logo_path, 'rb').read()).decode()

# End-user OIDC app credentials — used only for the final token exchange at
# POST /as/token. These are not sent to the /flows/ management API.
ENV_ID = os.getenv("PINGONE_ENV_ID")
CLIENT_ID = os.getenv("PINGONE_CLIENT_ID")
CLIENT_SECRET = os.getenv("PINGONE_CLIENT_SECRET")
AUTH_PATH = (os.getenv("PINGONE_AUTH_PATH") or "").rstrip("/")

# Admin worker app credentials — used only to obtain the management-plane
# bearer token required by the /flows/{id} API.
ADMIN_ENV_ID = os.getenv("PINGONE_ADMIN_ENV_ID")
ADMIN_CLIENT_ID = os.getenv("PINGONE_ADMIN_CLIENT_ID")
ADMIN_CLIENT_SECRET = os.getenv("PINGONE_ADMIN_CLIENT_SECRET")

if not all([ENV_ID, CLIENT_ID, CLIENT_SECRET, AUTH_PATH]):
    raise SystemExit("Missing required environment variables. Please check your .env file.")
if not all([ADMIN_ENV_ID, ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET]):
    raise SystemExit("Missing admin worker app credentials. Please check your .env file.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("p1-mfa-demo")

# In-memory session store keyed by flowID.
# Each entry is a dict with:
#   admin_token — the management-plane bearer token fetched at login start
#   cookies     — list of raw "name=value" strings captured from PingOne responses
# This lets the /mfa-verify route retrieve the admin token and cookies from
# the login step without the user having to re-authenticate.
SESSION_STORE = {}


def get_admin_token() -> str:
    """Fetch a short-lived access token from the admin worker app.

    Uses the OAuth 2.0 client_credentials grant with HTTP Basic authentication
    (CLIENT_SECRET_BASIC). The returned token must be sent as
    "Authorization: Bearer <token>" on every /flows/{id} management API call.
    A fresh token is fetched at the start of each login attempt.
    """
    resp = requests.post(
        f"{AUTH_PATH}/{ADMIN_ENV_ID}/as/token",
        data={"grant_type": "client_credentials"},
        # requests.post with auth=(id, secret) sends CLIENT_SECRET_BASIC
        # (base64(id:secret) in the Authorization header).
        auth=(ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    body = resp.json()
    token = body.get("access_token")
    if not token:
        raise RuntimeError(f"No access_token in response: {body}")
    return token


def capture_cookies(session: dict, resp: requests.Response) -> None:
    """Extract Set-Cookie values from a PingOne response into session['cookies'].

    Why manual capture instead of a requests.Session cookie jar?
      The requests library respects RFC 6265 path scoping: a cookie whose
      Path attribute does not match the current request path is silently
      dropped. PingOne's ST and ST-NO-SS cookies are issued on /as/authorize
      but need to be sent on /flows/{id} — a different path. A cookie jar
      would drop them. Storing raw "name=value" strings and building the
      Cookie header manually bypasses this entirely.

    If a cookie with the same name already exists it is replaced, because
    PingOne may issue updated ST values across flow steps.
    """
    for name, value in resp.cookies.items():
        entry = f"{name}={value}"
        idx = next((i for i, c in enumerate(session["cookies"]) if c.startswith(f"{name}=")), -1)
        if idx >= 0:
            session["cookies"][idx] = entry
        else:
            session["cookies"].append(entry)


def cookie_header(session: dict) -> str:
    """Join all captured cookies into a single Cookie header value."""
    return "; ".join(session["cookies"])


# --- HTML templates ---

INDEX_HTML = f"""
<!DOCTYPE html>
<html>
<head><title>Login</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}} button{{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:16px; padding:10px 20px; cursor:pointer;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
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
</html>
"""


def mfa_html(flow_id: str) -> str:
    """Render the OTP entry page with the flowID embedded as a hidden field.

    The flowID is used by /mfa-verify to look up the in-progress session
    (admin token + cookies) without requiring the user to re-authenticate.
    """
    return f"""
<!DOCTYPE html>
<html>
<head><title>MFA Required</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}} button{{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:16px; padding:10px 20px; cursor:pointer;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Two-Factor Authentication</h2>
  <p>Please enter the verification code sent to your email.</p>
  <form action="/mfa-verify" method="POST">
    <input type="hidden" name="flowId" value="{flow_id}">
    <label>MFA Code:</label><br>
    <input type="text" name="otp" required><br><br>
    <button type="submit">Verify</button>
  </form>
</div>
</body>
</html>
"""


def dashboard_html(token: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
<head><title>Dashboard</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}} pre{{background:#eee; padding:15px;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2 style="color: green;">Login Successful!</h2>
  <p>You have securely authenticated. Here is your Access Token:</p>
  <pre style="white-space: pre-wrap; word-wrap: break-word;">{token}</pre>
  <a href="/">Log Out</a>
</div>
</body>
</html>
"""


def error_html(msg: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
<head><title>Error</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2 style="color: red;">Authentication Error</h2>
  <pre>{msg}</pre>
  <a href="/">Try Again</a>
</div>
</body>
</html>
"""


app = Flask(__name__)


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/login", methods=["POST"])
def login():
    """Steps 1 and 2: initialise the PingOne Flow session and submit credentials."""
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    try:
        admin_token = get_admin_token()
    except Exception as e:
        return error_html(f"Failed to get admin token: {e}")

    session = {"admin_token": admin_token, "cookies": []}

    # Step 1: Initialise the PingOne Flow session.
    #
    # response_mode=pi.flow — return JSON flow state instead of redirecting.
    # Accept: */* — required because PingOne uses vendor content types; a
    #   strict Accept: application/json causes a 406 Not Acceptable.
    # allow_redirects=False — prevents requests from following any 302 so
    #   we always receive the raw response and can inspect it ourselves.
    auth_url = (
        f"{AUTH_PATH}/{ENV_ID}/as/authorize?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow"
    )
    init_resp = requests.get(auth_url, headers={"Accept": "*/*"}, allow_redirects=False)
    capture_cookies(session, init_resp)
    flow_id = init_resp.json().get("id")
    log.info("[login] authorize flowID: %s", flow_id)

    # Step 2: Submit credentials to the active flow.
    #
    # Content-Type: application/vnd.pingidentity.usernamePassword.check+json
    #   tells the flow engine which action to perform. Using application/json
    #   here results in a 415 Unsupported Media Type.
    #
    # Authorization: Bearer <admin_token> — the management-plane bearer token.
    # Cookie: <ST; ST-NO-SS> — the session cookies from step 1.
    # Both headers are required on every /flows/ call; omitting either causes
    # a 401 even when the other is present.
    login_resp = requests.post(
        f"{AUTH_PATH}/{ENV_ID}/flows/{flow_id}",
        json={"username": username, "password": password},
        headers={
            "Content-Type": "application/vnd.pingidentity.usernamePassword.check+json",
            "Accept": "*/*",
            "Authorization": f"Bearer {admin_token}",
            "Cookie": cookie_header(session),
        },
        allow_redirects=False,
    )
    capture_cookies(session, login_resp)
    login_json = login_resp.json()
    log.info("[login] credentials result status=%s id=%s", login_json.get("status"), login_json.get("id"))

    # PingOne may return an updated flow ID after the credential check. Always
    # use the latest ID so subsequent calls target the correct flow state.
    if login_json.get("id"):
        flow_id = login_json["id"]
    SESSION_STORE[flow_id] = session

    # Route based on the flow status:
    #   COMPLETED — no MFA required for this user; proceed to resume.
    #   OTP_REQUIRED / DEVICE_SELECTION_REQUIRED /
    #   MULTI_FACTOR_AUTHENTICATION_REQUIRED — PingOne has sent an OTP;
    #     show the MFA form.
    status = login_json.get("status")
    if status == "COMPLETED":
        return complete_login_and_render(flow_id, session)
    if status in ("OTP_REQUIRED", "DEVICE_SELECTION_REQUIRED", "MULTI_FACTOR_AUTHENTICATION_REQUIRED"):
        return mfa_html(flow_id)
    return error_html(f"Unexpected login status: {login_json}")


@app.route("/mfa-verify", methods=["POST"])
def mfa_verify():
    """Step 3: submit the OTP to PingOne and advance to token exchange on success.

    The flowID posted by the hidden form field is used to look up the
    in-progress session (admin token + cookies) so the /flows/{id} call can
    be authenticated correctly.
    """
    flow_id = (request.form.get("flowId") or "").strip()
    otp = (request.form.get("otp") or "").strip()

    session = SESSION_STORE.get(flow_id)
    if not session:
        return error_html("Session expired or lost. Please try logging in again.")

    log.info("[mfa] sending OTP check, flowID=%s", flow_id)
    # Content-Type: application/vnd.pingidentity.otp.check+json tells the
    # flow engine to validate the OTP against the user's enrolled MFA device.
    # The same Accept: */* and dual-auth (Bearer + cookies) rules apply here.
    mfa_resp = requests.post(
        f"{AUTH_PATH}/{ENV_ID}/flows/{flow_id}",
        json={"otp": otp},
        headers={
            "Content-Type": "application/vnd.pingidentity.otp.check+json",
            "Accept": "*/*",
            "Authorization": f"Bearer {session['admin_token']}",
            "Cookie": cookie_header(session),
        },
        allow_redirects=False,
    )
    capture_cookies(session, mfa_resp)
    mfa_json = mfa_resp.json()
    log.info("[mfa] result: %s", mfa_json)

    # PingOne may issue a new flow ID after the OTP check. Update the session
    # store key so subsequent steps use the correct handle.
    new_id = mfa_json.get("id")
    if new_id and new_id != flow_id:
        SESSION_STORE[new_id] = session
        SESSION_STORE.pop(flow_id, None)
        flow_id = new_id

    if mfa_json.get("status") == "COMPLETED":
        SESSION_STORE.pop(flow_id, None)
        return complete_login_and_render(flow_id, session)

    return error_html(f"MFA Failed. Response: {mfa_json}")


def complete_login_and_render(flow_id: str, session: dict) -> str:
    """Steps 4a and 4b: call /as/resume to get an auth code, then exchange it for tokens.

    /as/resume signals PingOne that the native flow is complete. PingOne either:
      - Returns a JSON body with authorizeResponse.code (less common), or
      - Issues a 302 redirect to the registered redirect_uri with ?code= in
        the query string (most common).
    Both paths are handled here. allow_redirects=False is essential — without
    it, requests would silently follow the redirect and we would lose the
    Location header that carries the authorization code.

    Only the session cookies are sent to /as/resume. The admin bearer token
    is NOT required here because /as/resume is part of the OAuth 2.0
    authorization endpoint, not the management plane.
    """
    resume_resp = requests.get(
        f"{AUTH_PATH}/{ENV_ID}/as/resume?flowId={flow_id}",
        headers={"Accept": "*/*", "Cookie": cookie_header(session)},
        allow_redirects=False,
    )
    capture_cookies(session, resume_resp)
    log.info("[resume] status code: %s", resume_resp.status_code)

    # Try JSON body first; fall back to the Location redirect URL.
    auth_code = ""
    content_type = resume_resp.headers.get("content-type", "")
    if "json" in content_type:
        try:
            resume_json = resume_resp.json()
            auth_code = (resume_json.get("authorizeResponse") or {}).get("code", "")
        except ValueError:
            pass
    if not auth_code:
        loc = resume_resp.headers.get("location")
        if loc:
            qs = parse_qs(urlparse(loc).query)
            auth_code = (qs.get("code") or [""])[0]
    if not auth_code:
        return error_html("Failed to get authorization code from resume.")

    # Step 4b: Standard authorization_code token exchange using the end-user
    # OIDC app's credentials. The redirect_uri must exactly match the value
    # sent in the authorize request and registered on the PingOne app —
    # PingOne validates all three must agree before issuing tokens.
    token_resp = requests.post(
        f"{AUTH_PATH}/{ENV_ID}/as/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "http://localhost:3000/callback",
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token_json = token_resp.json()
    access_token = token_json.get("access_token")
    if not access_token:
        return error_html(f"Failed to parse access token. Output: {token_json}")

    return dashboard_html(access_token)


if __name__ == "__main__":
    # Verify admin credentials at startup rather than discovering a bad secret
    # mid-login. A startup failure is far easier to diagnose than a mid-flow 401.
    try:
        get_admin_token()
        log.info("Admin token smoke-test passed.")
    except Exception as e:
        raise SystemExit(f"Failed to get admin token at startup: {e}")
    print("MFA Demo starting on http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=False)
