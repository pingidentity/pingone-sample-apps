"""
PingOne DaVinci Sign-On Flow — Python / Flask

This app demonstrates a three-step DaVinci sign-on flow driven entirely from
the server side. The user submits credentials in a web form; the server drives
the PingOne authorize → DaVinci capability → token exchange sequence and
renders the result.

Overview of the three-step flow:

  1. GET /as/authorize?response_mode=pi.flow
     Instead of redirecting the browser, PingOne returns a JSON envelope
     describing the first DaVinci capability the client must drive.
     The response contains handles (interactionId, interactionToken,
     connectionId, capabilityName, id) that identify both the live flow
     session and the specific connector node that is waiting for input.

  2. POST /davinci/connections/{connectionId}/capabilities/{capabilityName}
     The client submits credentials to the capability URL using the handles
     from step 1 as request headers (interactionId, interactionToken).
     The DaVinci flow validates the credentials and — on a simple sign-on
     flow — returns an authorization code in authorizeResponse.code.

  3. POST /as/token  (standard OAuth 2.0 authorization_code exchange)
     The authorization code is exchanged for an access token using the
     OIDC web app's client_id and client_secret (CLIENT_SECRET_BASIC).

Prerequisites in PingOne:
  - A Web App (OIDC, authorization_code, CLIENT_SECRET_BASIC) with a
    DaVinci flow policy assignment pointing at a sign-on flow.
  - The DaVinci flow must use the API integration method (JSON responses).
  - A test user in the population the flow's PingOne SSO connector targets.
"""
import html
import json
import logging
import os
from dataclasses import dataclass

import requests
from dotenv import load_dotenv
from flask import Flask, request, send_from_directory

load_dotenv()

# ENV_ID — the PingOne environment that owns the OIDC app and DaVinci flow.
ENV_ID = (os.getenv("PINGONE_ENV_ID") or "").strip()
# CLIENT_ID / CLIENT_SECRET — credentials for the OIDC Web App (authorization_code,
# CLIENT_SECRET_BASIC). Used in startFlow (to identify the app) and in token exchange.
CLIENT_ID = (os.getenv("PINGONE_CLIENT_ID") or "").strip()
CLIENT_SECRET = (os.getenv("PINGONE_CLIENT_SECRET") or "").strip()
# AUTH_PATH — regional PingOne auth base URL (no trailing slash).
# North America: https://auth.pingone.com
# Europe:        https://auth.pingone.eu
AUTH_PATH = (os.getenv("PINGONE_AUTH_PATH") or "").rstrip("/")
# REDIRECT_URI — must match the redirect URI registered on the OIDC app.
# PingOne validates that all three (authorize request, token request, app config)
# match before issuing tokens. A non-functional placeholder is fine for this demo.
REDIRECT_URI = (os.getenv("PINGONE_REDIRECT_URI") or "").strip()

if not all([ENV_ID, CLIENT_ID, CLIENT_SECRET, AUTH_PATH, REDIRECT_URI]):
    raise SystemExit("Missing required environment variables. Please check your .env file.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("p1-davinci-signon")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FlowState:
    """Session handles returned by the authorize endpoint.

    interactionId / interactionToken — DaVinci's correlation handles. They tie
    this HTTP request to the in-progress flow session on the server. Both must
    be sent as request headers on the capability POST; omitting either causes
    PingOne to reject the request with a 401.

    connectionId / capabilityName — identify which DaVinci connector node is
    currently waiting for input. The capability URL is built from these two
    values: /davinci/connections/{connectionId}/capabilities/{capabilityName}.

    id — the flow instance ID. It is echoed back in the capability request body
    so DaVinci can locate the right execution context server-side.
    """
    interaction_id: str
    interaction_token: str
    connection_id: str
    capability_name: str
    flow_id: str


@dataclass
class StepResult:
    """Represents the outcome of a single workflow step.

    Fields:
        title     -- human-readable step name shown as the card heading.
        ok        -- True on success; False renders the heading in red.
        detail    -- one-line summary (e.g. "HTTP 201 — id=abc123").
        body      -- pretty-printed JSON response body; shown in a <details> element.
        url       -- "METHOD https://full/url" shown as a monospace badge.
        collapsed -- if True, the <details> element starts closed.
    """
    title: str
    ok: bool = False
    detail: str = ""
    body: str = ""
    url: str = ""
    collapsed: bool = False


# ---------------------------------------------------------------------------
# HTML pages
# ---------------------------------------------------------------------------

INDEX_HTML = """<!DOCTYPE html>
<html>
<head><title>DaVinci Sign-On</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;} button:hover{background:#b8002f;} input{font-size:15px; padding:6px 8px; min-width:280px;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2>DaVinci Sign-On Flow with PingOne Auth</h2>
    <p>Sign in with credentials. The PingOne authorize endpoint hands the request to the assigned DaVinci flow policy; this app drives the flow to completion and exchanges the resulting code for a token.</p>
    <form action="/login" method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        <button type="submit">Sign On</button>
    </form>
</div>
</body>
</html>"""


def dashboard_html(token: str) -> str:
    """Render the success page showing the access token."""
    safe_token = html.escape(token)
    return f"""<!DOCTYPE html>
<html>
<head><title>Signed In</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}} pre{{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2 style="color:#0a7a0a;">Sign-On Successful</h2>
    <p>The DaVinci flow returned an authorization code, which was exchanged for an access token:</p>
    <pre>{safe_token}</pre>
    <a href="/">Sign Out</a>
</div>
</body>
</html>"""


def error_html(msg: str) -> str:
    """Render the error page."""
    safe_msg = html.escape(msg)
    return f"""<!DOCTYPE html>
<html>
<head><title>Error</title><style>body{{font-family:sans-serif; margin:0; background:#f5f5f5;}} pre{{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all;}}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2 style="color:#b00020;">Sign-On Error</h2>
    <pre>{safe_msg}</pre>
    <a href="/">Try Again</a>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# DaVinci flow helpers
# ---------------------------------------------------------------------------

def check_flow_policy_assignment() -> None:
    """Probe the authorize endpoint at startup to confirm a DaVinci flow policy is assigned.

    When response_mode=pi.flow is used with a properly configured app, PingOne
    returns a 200 JSON body containing flow handles. Without a flow policy
    assignment PingOne issues a 302 redirect to its default login page instead,
    which this app cannot handle. Detecting this at startup gives a clear error
    message rather than a cryptic mid-login failure.

    Raises SystemExit with a descriptive message if the check fails.
    """
    auth_url = (
        f"{AUTH_PATH}/{ENV_ID}/as/authorize"
        f"?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}&scope=openid&response_mode=pi.flow"
    )
    try:
        resp = requests.get(
            auth_url,
            headers={"X-Requested-With": "ping-sdk", "Accept": "application/json"},
            allow_redirects=False,
        )
    except Exception as exc:
        raise SystemExit(f"Startup check: authorize probe failed: {exc}") from exc

    if resp.status_code in (302, 303):
        raise SystemExit(
            "Startup check failed: the authorize endpoint redirected instead of returning a DaVinci flow.\n"
            f"  Your OIDC app likely has no flow policy assignment.\n"
            f"  Fix: assign a DaVinci flow policy to app \"{CLIENT_ID}\" in environment \"{ENV_ID}\".\n"
            f"  See README.md -> PingOne configuration for instructions."
        )

    try:
        data = resp.json()
    except Exception:
        data = {}

    if not data.get("interactionId"):
        raise SystemExit(
            f"Startup check failed: the authorize endpoint did not return a DaVinci flow (status {resp.status_code}).\n"
            f"  Check that the OIDC app has a flow policy assignment and that\n"
            f"  PINGONE_CLIENT_ID / PINGONE_ENV_ID / PINGONE_AUTH_PATH are correct.\n"
            f"  Response: {resp.text}"
        )

    log.info("Startup check passed: DaVinci flow policy assignment is present.")


def start_flow() -> FlowState:
    """Call GET /as/authorize?response_mode=pi.flow to initialise a DaVinci flow session.

    response_mode=pi.flow instructs PingOne to return the flow state as a JSON
    body rather than redirecting the browser. The response describes the first
    DaVinci node waiting for client input and contains the session handles
    (interactionId, interactionToken, connectionId, capabilityName, id) needed
    to drive subsequent steps.

    Returns a FlowState with all handles populated.
    Raises RuntimeError on any error.
    """
    auth_url = (
        f"{AUTH_PATH}/{ENV_ID}/as/authorize"
        f"?response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}&scope=openid&response_mode=pi.flow"
    )
    # X-Requested-With: ping-sdk tells PingOne this is a programmatic SDK
    # client. Combined with response_mode=pi.flow it ensures the server returns
    # JSON flow handles rather than an HTML login page.
    resp = requests.get(
        auth_url,
        headers={"X-Requested-With": "ping-sdk", "Accept": "application/json"},
    )

    if resp.status_code >= 400:
        raise RuntimeError(f"authorize returned {resp.status_code}: {resp.text}")

    try:
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(
            f"authorize response was not JSON: {exc} (body: {resp.text})"
        ) from exc

    interaction_id = data.get("interactionId", "")
    interaction_token = data.get("interactionToken", "")
    connection_id = data.get("connectionId", "")
    capability_name = data.get("capabilityName", "")
    flow_id = data.get("id", "")

    if not interaction_id or not connection_id or not capability_name:
        raise RuntimeError(
            f"authorize response missing flow handles: {resp.text}"
        )

    return FlowState(
        interaction_id=interaction_id,
        interaction_token=interaction_token,
        connection_id=connection_id,
        capability_name=capability_name,
        flow_id=flow_id,
    )


def submit_sign_on(state: FlowState, username: str, password: str) -> str:
    """Post credentials to the DaVinci capability URL and return the authorization code.

    The request body shape is the DaVinci runtime envelope:
      - id: the flow instance ID from start_flow, echoed so DaVinci can match
        this request to the correct in-progress execution.
      - eventName: "continue" advances the flow past the current node.
      - parameters.data.actionKey: "SIGNON" selects the sign-on branch of the
        PingOne SSO connector (as opposed to "REGISTER" for self-service signup).
      - parameters.data.formData: the user-supplied field values.

    On success the flow completes and the response contains
    authorizeResponse.code — an authorization code ready for token exchange.

    Raises RuntimeError on any error or if the flow did not return a code.
    """
    # The capability URL encodes which DaVinci connector and node to invoke.
    # connection_id identifies the PingOne SSO connector instance in this flow;
    # capability_name is the specific action within that connector (e.g. userLookup).
    cap_url = (
        f"{AUTH_PATH}/{ENV_ID}/davinci/connections/{state.connection_id}"
        f"/capabilities/{state.capability_name}"
    )
    payload = {
        "id": state.flow_id,
        "eventName": "continue",
        "parameters": {
            "eventType": "submit",
            "data": {
                "actionKey": "SIGNON",
                "formData": {
                    "username": username,
                    "password": password,
                },
            },
        },
    }
    # interactionId and interactionToken are the DaVinci session correlation
    # handles from start_flow. They must be sent as headers (not in the body)
    # on every capability request so DaVinci can locate the live flow session.
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Requested-With": "ping-sdk",
        "interactionId": state.interaction_id,
        "interactionToken": state.interaction_token,
    }
    resp = requests.post(cap_url, json=payload, headers=headers)

    if resp.status_code >= 400:
        raise RuntimeError(f"capability returned {resp.status_code}: {resp.text}")

    try:
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(
            f"capability response was not JSON: {exc} (body: {resp.text})"
        ) from exc

    # authorizeResponse.code is present only when the DaVinci flow has reached
    # its terminal success node. If it is absent the flow needs another step
    # (e.g. MFA) that this sample does not handle.
    authorize_response = data.get("authorizeResponse")
    if not isinstance(authorize_response, dict):
        raise RuntimeError(
            f"flow did not return an authorization code (likely needs another step): {resp.text}"
        )
    code = authorize_response.get("code", "")
    if not code:
        raise RuntimeError(f"authorizeResponse missing code: {resp.text}")
    return code


def exchange_token(code: str) -> str:
    """Perform a standard OAuth 2.0 authorization_code token exchange.

    The redirect_uri must exactly match the value sent in the authorize request
    and the one registered on the PingOne app — PingOne validates all three
    match before issuing tokens. Authentication uses HTTP Basic (CLIENT_SECRET_BASIC):
    the requests library handles base64 encoding via the auth= parameter.

    Returns the access_token string.
    Raises RuntimeError on any error.
    """
    token_url = f"{AUTH_PATH}/{ENV_ID}/as/token"
    resp = requests.post(
        token_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )

    if resp.status_code >= 400:
        raise RuntimeError(f"token endpoint returned {resp.status_code}: {resp.text}")

    try:
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(
            f"token response was not JSON: {exc} (body: {resp.text})"
        ) from exc

    token = data.get("access_token", "")
    if not token:
        raise RuntimeError(f"token response missing access_token: {resp.text}")
    return token


# ---------------------------------------------------------------------------
# Startup check
# ---------------------------------------------------------------------------

check_flow_policy_assignment()

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.route("/logo.png")
def logo():
    return send_from_directory(os.path.dirname(__file__), "logo.png")


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/login", methods=["POST"])
def login():
    """Orchestrate the full three-step sign-on sequence.

    Each step calls a focused helper so the sequence reads top-to-bottom as
    plain English. Any step failure renders an error page immediately.
    """
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    # Step 1: Call the PingOne authorize endpoint with response_mode=pi.flow.
    # This does not authenticate the user yet — it initialises a DaVinci flow
    # session and returns the handles needed to drive it.
    try:
        state = start_flow()
    except Exception as exc:
        return error_html(f"Failed to start flow: {exc}")

    log.info("[signon] flow started id=%s capability=%s", state.flow_id, state.capability_name)

    # Step 2: Submit the user's credentials to the capability that DaVinci is
    # waiting on. For a standard sign-on flow this is the PingOne SSO connector's
    # userLookup/password-check node, and a successful response includes an
    # authorization code in authorizeResponse.code.
    try:
        auth_code = submit_sign_on(state, username, password)
    except Exception as exc:
        return error_html(f"Failed to submit credentials: {exc}")

    log.info("[signon] received authorization code")

    # Step 3: Trade the authorization code for tokens at the standard PingOne
    # token endpoint. This is identical to any other authorization_code exchange.
    try:
        access_token = exchange_token(auth_code)
    except Exception as exc:
        return error_html(f"Failed to exchange token: {exc}")

    return dashboard_html(access_token)


if __name__ == "__main__":
    print("DaVinci Sign-On demo starting on http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=False)
