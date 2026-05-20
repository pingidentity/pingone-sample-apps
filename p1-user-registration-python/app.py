import os
import logging
from urllib.parse import urlparse, parse_qs

import requests
from dotenv import load_dotenv
from flask import Flask, request

load_dotenv()

ENV_ID = os.getenv("PINGONE_ENV_ID")
CLIENT_ID = os.getenv("PINGONE_CLIENT_ID")
CLIENT_SECRET = os.getenv("PINGONE_CLIENT_SECRET")
AUTH_PATH = (os.getenv("PINGONE_AUTH_PATH") or "").rstrip("/")

if not all([ENV_ID, CLIENT_ID, CLIENT_SECRET, AUTH_PATH]):
    raise SystemExit("Missing required environment variables. Please check your .env file.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("p1-registration")

# Per-flow cookie store keyed by flowID — raw "name=value" strings replayed verbatim.
FLOW_STORE = {}


def capture_cookies(store: list, resp: requests.Response) -> None:
    for name, value in resp.cookies.items():
        entry = f"{name}={value}"
        idx = next((i for i, c in enumerate(store) if c.startswith(f"{name}=")), -1)
        if idx >= 0:
            store[idx] = entry
        else:
            store.append(entry)


def cookie_header(store: list) -> str:
    return "; ".join(store)


# --- HTML templates ---

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head><title>PingOne Demo</title><style>body{font-family:sans-serif; margin:40px;}</style></head>
<body>
  <h2>Sign Up</h2>
  <form action="/register" method="POST">
    <label>Username:</label><br>
    <input type="text" name="username" required><br><br>
    <label>Email:</label><br>
    <input type="email" name="email" required><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>
    <button type="submit">Register</button>
  </form>
  <br><hr><br>
  <p>Already have an account? <a href="/login-page">Log in here</a></p>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Login</title><style>body{font-family:sans-serif; margin:40px;}</style></head>
<body>
  <h2>Login</h2>
  <form action="/login" method="POST">
    <label>Username:</label><br>
    <input type="text" name="username" required><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>
    <button type="submit">Log In</button>
  </form>
</body>
</html>
"""


def verify_html(flow_id: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
<head><title>Verify Email</title><style>body{{font-family:sans-serif; margin:40px;}}</style></head>
<body>
  <h2>Check Your Email</h2>
  <p>We've sent a 6-digit verification code to your email address.</p>
  <form action="/verify" method="POST">
    <input type="hidden" name="flowId" value="{flow_id}">
    <label>Verification Code:</label><br>
    <input type="text" name="code" required><br><br>
    <button type="submit">Verify &amp; Complete</button>
  </form>
</body>
</html>
"""


SUCCESS_HTML = """
<!DOCTYPE html>
<html>
<head><title>Success!</title><style>body{font-family:sans-serif; margin:40px;}</style></head>
<body>
  <h2 style="color: green;">Registration Complete!</h2>
  <p>Your account has been successfully created and verified via PingOne.</p>
  <a href="/login-page">Click here to Log In</a>
</body>
</html>
"""


def dashboard_html(token: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
<head><title>Dashboard</title><style>body{{font-family:sans-serif; margin:40px;}} pre{{background:#eee; padding:15px;}}</style></head>
<body>
  <h2 style="color: blue;">Welcome to your Dashboard!</h2>
  <p>You have successfully authenticated. Here is your Access Token:</p>
  <pre style="white-space: pre-wrap; word-wrap: break-word;">{token}</pre>
  <a href="/">Log Out (Return to Home)</a>
</body>
</html>
"""


def error_html(msg: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
<head><title>Error</title><style>body{{font-family:sans-serif; margin:40px;}}</style></head>
<body>
  <h2 style="color: red;">Something went wrong</h2>
  <pre>{msg}</pre>
  <a href="/">Try Again</a>
</body>
</html>
"""


app = Flask(__name__)


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/login-page")
def login_page():
    return LOGIN_HTML


@app.route("/register", methods=["POST"])
def register():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""

    cookies = []

    auth_url = (
        f"{AUTH_PATH}/{ENV_ID}/as/authorize?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow"
    )
    init_resp = requests.get(auth_url, headers={"Accept": "*/*"}, allow_redirects=False)
    capture_cookies(cookies, init_resp)
    flow_id = init_resp.json().get("id")
    if not flow_id:
        return error_html(f"Failed to retrieve flowId. Response: {init_resp.text}")

    reg_resp = requests.post(
        f"{AUTH_PATH}/{ENV_ID}/flows/{flow_id}",
        json={"username": username, "email": email, "password": password},
        headers={
            "Content-Type": "application/vnd.pingidentity.user.register+json",
            "Accept": "*/*",
            "Cookie": cookie_header(cookies),
        },
        allow_redirects=False,
    )
    capture_cookies(cookies, reg_resp)
    reg_json = reg_resp.json()
    FLOW_STORE[flow_id] = cookies

    status = reg_json.get("status")
    if status == "VERIFICATION_CODE_REQUIRED":
        return verify_html(flow_id)
    if status == "COMPLETED":
        FLOW_STORE.pop(flow_id, None)
        return SUCCESS_HTML
    return error_html(f"Unexpected registration status: {reg_json}")


@app.route("/verify", methods=["POST"])
def verify():
    flow_id = (request.form.get("flowId") or "").strip()
    code = (request.form.get("code") or "").strip()

    cookies = FLOW_STORE.get(flow_id, [])

    verify_resp = requests.post(
        f"{AUTH_PATH}/{ENV_ID}/flows/{flow_id}",
        json={"verificationCode": code},
        headers={
            "Content-Type": "application/vnd.pingidentity.user.verify+json",
            "Accept": "*/*",
            "Cookie": cookie_header(cookies),
        },
        allow_redirects=False,
    )
    capture_cookies(cookies, verify_resp)
    verify_json = verify_resp.json()

    if verify_json.get("status") == "COMPLETED":
        FLOW_STORE.pop(flow_id, None)
        return SUCCESS_HTML
    return error_html(f"Verification failed. Response: {verify_json}")


@app.route("/login", methods=["POST"])
def login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    cookies = []

    auth_url = (
        f"{AUTH_PATH}/{ENV_ID}/as/authorize?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow"
    )
    init_resp = requests.get(auth_url, headers={"Accept": "*/*"}, allow_redirects=False)
    capture_cookies(cookies, init_resp)
    flow_id = init_resp.json().get("id")
    if not flow_id:
        return error_html(f"Failed to retrieve flowId. Response: {init_resp.text}")

    login_resp = requests.post(
        f"{AUTH_PATH}/{ENV_ID}/flows/{flow_id}",
        json={"username": username, "password": password},
        headers={
            "Content-Type": "application/vnd.pingidentity.usernamePassword.check+json",
            "Accept": "*/*",
            "Cookie": cookie_header(cookies),
        },
        allow_redirects=False,
    )
    capture_cookies(cookies, login_resp)
    login_json = login_resp.json()

    if login_json.get("status") != "COMPLETED":
        return error_html(f"Login failed or requires MFA. Status: {login_json}")

    resume_resp = requests.get(
        f"{AUTH_PATH}/{ENV_ID}/as/resume?flowId={flow_id}",
        headers={"Accept": "*/*", "Cookie": cookie_header(cookies)},
        allow_redirects=False,
    )
    capture_cookies(cookies, resume_resp)

    auth_code = ""
    if "json" in resume_resp.headers.get("content-type", ""):
        try:
            auth_code = (resume_resp.json().get("authorizeResponse") or {}).get("code", "")
        except ValueError:
            pass
    if not auth_code:
        loc = resume_resp.headers.get("location")
        if loc:
            auth_code = (parse_qs(urlparse(loc).query).get("code") or [""])[0]
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
    print("Server starting on http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=False)
