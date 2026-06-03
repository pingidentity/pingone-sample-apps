"""
PingOne User Registration — Python / Flask implementation

This app demonstrates self-service user registration against the PingOne native
authentication API, followed by a standard OIDC sign-on flow for the newly
created user.

How registration differs from sign-on
--------------------------------------
A sign-on flow authenticates a user who already exists in PingOne's directory and
ends with an OAuth 2.0 authorization code that can be exchanged for tokens.
Registration is a pre-authentication step: it creates the user account in PingOne
before any tokens are issued. No admin worker app or management API token is
needed here — the same OIDC application that drives sign-on can also accept
registrations through the native flow API (PINGONE_CLIENT_ID / CLIENT_SECRET).

Registration sub-flow (2–3 steps)
----------------------------------
1. GET  /as/authorize?response_mode=pi.flow
   Initialises a PingOne authentication session. response_mode=pi.flow makes
   PingOne return a JSON body containing a flow ID rather than redirecting the
   browser to a hosted login page. The response also sets session cookies that
   must be replayed on every subsequent call to the same flow.

2. POST /flows/{flow_id}  Content-Type: application/vnd.pingidentity.user.register+json
   Creates the new user. PingOne validates the password against the environment's
   password policy and either:
   - Returns status=COMPLETED immediately (no email verification configured).
   - Returns status=VERIFICATION_CODE_REQUIRED and emails a 6-digit OTP.

3. POST /flows/{flow_id}  Content-Type: application/vnd.pingidentity.user.verify+json
   (Only when step 2 required verification.) Submits the OTP. A
   status=COMPLETED response means the account is fully active.

Sign-on sub-flow (4 steps)
---------------------------
1. GET  /as/authorize?response_mode=pi.flow  (fresh session, independent of any
   prior registration flow)
2. POST /flows/{flow_id}  Content-Type: application/vnd.pingidentity.usernamePassword.check+json
   Validates credentials. status=COMPLETED means PingOne accepted them.
3. GET  /as/resume?flowId={flow_id}
   Bridges the native flow back to the OAuth 2.0 layer. PingOne either issues a
   302 redirect to the callback URI with ?code=... in the Location header, or
   returns a JSON body with authorizeResponse.code. Both cases are handled below.
4. POST /as/token — standard OAuth 2.0 authorization_code token exchange.

Cookie handling
---------------
PingOne sets session cookies (ST, ST-NO-SS) when the /as/authorize flow is
initialised. All subsequent requests to the same flow must replay those cookies
verbatim. The requests library follows redirects and manages a per-Session cookie
jar, but that jar applies RFC 6265 path scoping which silently drops cookies when
the request path differs. This file captures and replays cookies manually using a
plain list of "name=value" strings.
"""

import os
import base64
import logging
from urllib.parse import urlparse, parse_qs

import requests
from dotenv import load_dotenv
from flask import Flask, request

load_dotenv()

# Encode the logo as a data URI so the single-file server doesn't need a static
# asset route. The image is read once at startup.
_logo_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'logo.png')
LOGO_SRC = 'data:image/png;base64,' + base64.b64encode(open(_logo_path, 'rb').read()).decode()

ENV_ID = os.getenv("PINGONE_ENV_ID")
CLIENT_ID = os.getenv("PINGONE_CLIENT_ID")
CLIENT_SECRET = os.getenv("PINGONE_CLIENT_SECRET")
# Strip trailing slash to avoid double-slash in URL construction.
AUTH_PATH = (os.getenv("PINGONE_AUTH_PATH") or "").rstrip("/")

if not all([ENV_ID, CLIENT_ID, CLIENT_SECRET, AUTH_PATH]):
    raise SystemExit("Missing required environment variables. Please check your .env file.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("p1-registration")

# Per-flow cookie store keyed by PingOne flow ID.
#
# Registration may require an email verification step. The OTP arrives on a
# separate HTTP request after the registration request completes, so the PingOne
# session cookies must survive between the /register and /verify Flask routes.
# FLOW_STORE bridges that gap. Entries are removed once the flow reaches COMPLETED
# to avoid unbounded memory growth.
FLOW_STORE = {}


def capture_cookies(store: list, resp: requests.Response) -> None:
    """
    Merge cookies from a requests Response into the store list.

    Each entry in store is a raw "name=value" string. If a cookie with the same
    name already exists in the store it is replaced (upsert), because PingOne
    refreshes its session cookie values on every response — replaying a stale
    value causes a 401 on the next request.
    """
    for name, value in resp.cookies.items():
        entry = f"{name}={value}"
        idx = next((i for i, c in enumerate(store) if c.startswith(f"{name}=")), -1)
        if idx >= 0:
            store[idx] = entry
        else:
            store.append(entry)


def cookie_header(store: list) -> str:
    """
    Join the raw "name=value" strings in store into a Cookie header value.

    Sending cookies manually (rather than via a requests Session cookie jar)
    bypasses RFC 6265 path-scoping that would silently drop cookies when the
    request path differs from the path recorded at capture time.
    """
    return "; ".join(store)


# --- HTML templates ---

INDEX_HTML = f"""
<!DOCTYPE html>
<html>
<head><title>PingOne Demo</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}} button{{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:16px; padding:10px 20px; cursor:pointer;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
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
</div>
</body>
</html>
"""

LOGIN_HTML = f"""
<!DOCTYPE html>
<html>
<head><title>Login</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}} button{{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:16px; padding:10px 20px; cursor:pointer;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Login</h2>
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


def verify_html(flow_id: str) -> str:
    """
    Render the email OTP form, embedding the PingOne flow ID as a hidden field.

    The flow ID must be passed back to the /verify route so it can look up the
    saved cookies and POST to the correct /flows/{id} endpoint.
    """
    return f"""
<!DOCTYPE html>
<html>
<head><title>Verify Email</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}} button{{background:#E1003B; color:#fff; border:none; border-radius:4px; font-size:16px; padding:10px 20px; cursor:pointer;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Check Your Email</h2>
  <p>We've sent a 6-digit verification code to your email address.</p>
  <form action="/verify" method="POST">
    <input type="hidden" name="flowId" value="{flow_id}">
    <label>Verification Code:</label><br>
    <input type="text" name="code" required><br><br>
    <button type="submit">Verify &amp; Complete</button>
  </form>
</div>
</body>
</html>
"""


SUCCESS_HTML = f"""
<!DOCTYPE html>
<html>
<head><title>Success!</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2 style="color:#0a7a0a;">Registration Complete!</h2>
  <p>Your account has been successfully created and verified via PingOne.</p>
  <a href="/login-page">Click here to Log In</a>
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
  <h2 style="color: blue;">Welcome to your Dashboard!</h2>
  <p>You have successfully authenticated. Here is your Access Token:</p>
  <pre style="white-space: pre-wrap; word-wrap: break-word;">{token}</pre>
  <a href="/">Log Out (Return to Home)</a>
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
  <h2 style="color: red;">Something went wrong</h2>
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


@app.route("/login-page")
def login_page():
    return LOGIN_HTML


@app.route("/register", methods=["POST"])
def register():
    """
    Drive the PingOne registration sub-flow.

    Step 1: Initialise the flow via GET /as/authorize?response_mode=pi.flow.
      allow_redirects=False prevents requests from following any 302 automatically.
      Accept: */* is required; the flow API returns a vendor content type that
      would be rejected if Accept were limited to application/json.

    Step 2: Submit the new user's credentials to /flows/{flow_id} with the
      register content type. The response status field determines the next action:
      - VERIFICATION_CODE_REQUIRED: email OTP was sent; save cookies, show OTP form.
      - COMPLETED: no verification configured; account is live immediately.
    """
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    password = request.form.get("password") or ""

    cookies = []

    # Step 1: Initialise the PingOne authentication flow.
    auth_url = (
        f"{AUTH_PATH}/{ENV_ID}/as/authorize?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow"
    )
    init_resp = requests.get(auth_url, headers={"Accept": "*/*"}, allow_redirects=False)
    capture_cookies(cookies, init_resp)
    flow_id = init_resp.json().get("id")
    if not flow_id:
        return error_html(f"Failed to retrieve flowId. Response: {init_resp.text}")

    # Step 2: Register the new user.
    # Content-Type selects the registration operation. Password is validated
    # server-side against the PingOne environment's password policy.
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

    # Persist cookies so the /verify route can resume the same PingOne session.
    FLOW_STORE[flow_id] = cookies

    status = reg_json.get("status")
    if status == "VERIFICATION_CODE_REQUIRED":
        # PingOne sent the OTP; render the form to collect it.
        return verify_html(flow_id)
    if status == "COMPLETED":
        # No verification step — account is active immediately.
        FLOW_STORE.pop(flow_id, None)
        return SUCCESS_HTML
    return error_html(f"Unexpected registration status: {reg_json}")


@app.route("/verify", methods=["POST"])
def verify():
    """
    Submit the email OTP to complete registration.

    The flowId was embedded as a hidden field in the OTP form by the /register
    route. It is used to retrieve the saved PingOne session cookies so this POST
    is correlated with the live flow. Without those cookies PingOne cannot
    identify the pending registration and will return an error.

    Content-Type application/vnd.pingidentity.user.verify+json distinguishes
    this POST (OTP submission) from another user.register request.
    """
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
    """
    Drive the PingOne sign-on sub-flow for an existing user.

    Step 1: Initialise a fresh authentication session (identical to registration
      step 1, but independent — no shared state with a prior registration flow).

    Step 2: Validate credentials via usernamePassword.check+json. status=COMPLETED
      means PingOne accepted the credentials. Any other status (e.g.
      MUST_CHANGE_PASSWORD, MFA_REQUIRED) is not handled in this sample.

    Step 3: Resume the OAuth 2.0 session via GET /as/resume?flowId=...
      PingOne delivers the authorization code in one of two ways:
        - 302 Location header containing ?code=<value>
        - JSON body with authorizeResponse.code
      Both are checked so the app works regardless of PingOne's response format.

    Step 4: Exchange the code at POST /as/token using HTTP Basic auth
      (requests' auth= parameter encodes client_id:client_secret in the
      Authorization header, which is the CLIENT_SECRET_BASIC method).
      The redirect_uri must exactly match the value used in the authorize call
      and the URI registered on the PingOne application.
    """
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    cookies = []

    # Step 1: Initialise a fresh PingOne authentication flow.
    auth_url = (
        f"{AUTH_PATH}/{ENV_ID}/as/authorize?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&response_mode=pi.flow"
    )
    init_resp = requests.get(auth_url, headers={"Accept": "*/*"}, allow_redirects=False)
    capture_cookies(cookies, init_resp)
    flow_id = init_resp.json().get("id")
    if not flow_id:
        return error_html(f"Failed to retrieve flowId. Response: {init_resp.text}")

    # Step 2: Validate the user's credentials.
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

    # Step 3: Resume the OAuth 2.0 session to obtain the authorization code.
    # allow_redirects=False is critical — the code is in the Location header of
    # the 302 response. If requests followed the redirect automatically we would
    # lose it.
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
        # Fall back to the Location header (standard OIDC redirect case).
        loc = resume_resp.headers.get("location")
        if loc:
            auth_code = (parse_qs(urlparse(loc).query).get("code") or [""])[0]
    if not auth_code:
        return error_html("Failed to get authorization code from resume.")

    # Step 4: Exchange the code for tokens.
    # requests' auth= parameter sends client credentials as HTTP Basic, which is
    # the CLIENT_SECRET_BASIC method expected by PingOne's token endpoint.
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
