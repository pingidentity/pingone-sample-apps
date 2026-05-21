import os
import base64
import logging
from urllib.parse import urlparse, parse_qs

import requests
from dotenv import load_dotenv
from flask import Flask, request

load_dotenv()

_logo_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'logo.png')
LOGO_SRC = 'data:image/png;base64,' + base64.b64encode(open(_logo_path, 'rb').read()).decode()

ENV_ID = os.getenv("PINGONE_ENV_ID")
CLIENT_ID = os.getenv("PINGONE_CLIENT_ID")
CLIENT_SECRET = os.getenv("PINGONE_CLIENT_SECRET")
AUTH_PATH = (os.getenv("PINGONE_AUTH_PATH") or "").rstrip("/")

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
# Each entry holds the admin bearer token and raw cookie "name=value" strings replayed
# verbatim on later requests — this bypasses strict RFC 6265 path scoping.
SESSION_STORE = {}


def get_admin_token() -> str:
    resp = requests.post(
        f"{AUTH_PATH}/{ADMIN_ENV_ID}/as/token",
        data={"grant_type": "client_credentials"},
        auth=(ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    body = resp.json()
    token = body.get("access_token")
    if not token:
        raise RuntimeError(f"No access_token in response: {body}")
    return token


def capture_cookies(session: dict, resp: requests.Response) -> None:
    """Capture Set-Cookie from a response into session['cookies'] as raw name=value strings."""
    for name, value in resp.cookies.items():
        entry = f"{name}={value}"
        idx = next((i for i, c in enumerate(session["cookies"]) if c.startswith(f"{name}=")), -1)
        if idx >= 0:
            session["cookies"][idx] = entry
        else:
            session["cookies"].append(entry)


def cookie_header(session: dict) -> str:
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
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    try:
        admin_token = get_admin_token()
    except Exception as e:
        return error_html(f"Failed to get admin token: {e}")

    session = {"admin_token": admin_token, "cookies": []}

    # 1. Initialize flow
    auth_url = (
        f"{AUTH_PATH}/{ENV_ID}/as/authorize?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow"
    )
    init_resp = requests.get(auth_url, headers={"Accept": "*/*"}, allow_redirects=False)
    capture_cookies(session, init_resp)
    flow_id = init_resp.json().get("id")
    log.info("[login] authorize flowID: %s", flow_id)

    # 2. Submit credentials
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

    if login_json.get("id"):
        flow_id = login_json["id"]
    SESSION_STORE[flow_id] = session

    status = login_json.get("status")
    if status == "COMPLETED":
        return complete_login_and_render(flow_id, session)
    if status in ("OTP_REQUIRED", "DEVICE_SELECTION_REQUIRED", "MULTI_FACTOR_AUTHENTICATION_REQUIRED"):
        return mfa_html(flow_id)
    return error_html(f"Unexpected login status: {login_json}")


@app.route("/mfa-verify", methods=["POST"])
def mfa_verify():
    flow_id = (request.form.get("flowId") or "").strip()
    otp = (request.form.get("otp") or "").strip()

    session = SESSION_STORE.get(flow_id)
    if not session:
        return error_html("Session expired or lost. Please try logging in again.")

    log.info("[mfa] sending OTP check, flowID=%s", flow_id)
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
    resume_resp = requests.get(
        f"{AUTH_PATH}/{ENV_ID}/as/resume?flowId={flow_id}",
        headers={"Accept": "*/*", "Cookie": cookie_header(session)},
        allow_redirects=False,
    )
    capture_cookies(session, resume_resp)
    log.info("[resume] status code: %s", resume_resp.status_code)

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
    try:
        get_admin_token()
        log.info("Admin token smoke-test passed.")
    except Exception as e:
        raise SystemExit(f"Failed to get admin token at startup: {e}")
    print("MFA Demo starting on http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=False)
