# OAuth 2.0 Client Credentials (M2M) with PingOne Protect — Python/Flask
#
# What this sample demonstrates:
#   The client_credentials grant is the correct OAuth 2.0 flow when there is
#   no human user involved. A backend service (the "client") authenticates
#   directly with PingOne using its own client_id and client_secret. PingOne
#   returns an access token in the same HTTP response — no browser redirect,
#   no PKCE, no authorization code. The service then uses that token as a
#   Bearer token to call PingOne APIs.
#
# Workflow steps (rendered as cards in the UI):
#   1.  Build token request     — assemble URL and HTTP Basic credentials.
#   2.  Call /as/token          — POST grant_type=client_credentials.
#   3.  Decode access token     — split the JWT, decode header + payload.
#   4.  Fetch JWKS              — retrieve PingOne's public signing keys.
#   5.  Verify signature        — validate the JWT signature (RS256).
#   6.  Validate claims         — check iss, client_id, exp, iat.
#   7a. Risk evaluation (A)     — trusted IP, type=EXTERNAL → LOW/MEDIUM.
#   8a. Management API call (A) — proceeds because risk is low.
#   7b. Risk evaluation (B)     — Tor IP, type=ANONYMOUS → HIGH.
#   8b. Management API call (B) — blocked because risk is HIGH.
#
# PingOne setup required:
#   - A Worker application (Token Endpoint Auth Method = Client Secret Basic).
#   - Roles: Identity Data Read + PingOne Protect (risk evaluation).
#   - A Protect risk policy set with Anonymous Network Detection enabled;
#     HIGH threshold at or below 75. Its UUID goes in PINGONE_RISK_POLICY_SET_ID.

import base64
import hashlib
import html
import json
import logging
import os
import time
from dataclasses import dataclass

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from flask import Flask, request

# Load configuration from .env if present; fall back to process environment.
# python-dotenv does not fail if the file is missing, so container deployments
# that inject variables via the environment work without a .env file.
load_dotenv()

# Embed the logo as a base64 data URI so the single-file app has no external
# static-file dependencies at runtime.
_logo_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'logo.png')
LOGO_SRC = 'data:image/png;base64,' + base64.b64encode(open(_logo_path, 'rb').read()).decode()

# All configuration comes from environment variables.
# AUTH_PATH — base URL of the PingOne auth service, e.g. https://auth.pingone.com
# API_PATH  — base URL of the PingOne management API, e.g. https://api.pingone.com
# Trailing slashes are stripped so we can always safely append /path.
ENV_ID = (os.getenv("PINGONE_ENV_ID") or "").strip()
CLIENT_ID = (os.getenv("PINGONE_CLIENT_ID") or "").strip()
CLIENT_SECRET = (os.getenv("PINGONE_CLIENT_SECRET") or "").strip()
AUTH_PATH = (os.getenv("PINGONE_AUTH_PATH") or "").rstrip("/")
API_PATH = (os.getenv("PINGONE_API_PATH") or "").rstrip("/")
# RISK_POLICY_SET_ID identifies the PingOne Protect policy set. The policy set
# defines which predictors are active (e.g. Anonymous Network Detection,
# Velocity) and the score thresholds that map to LOW / MEDIUM / HIGH.
RISK_POLICY_SET_ID = (os.getenv("PINGONE_RISK_POLICY_SET_ID") or "").strip()

if not all([ENV_ID, CLIENT_ID, CLIENT_SECRET, AUTH_PATH, API_PATH, RISK_POLICY_SET_ID]):
    raise SystemExit("Missing required environment variables. Please check your .env file.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("p1-m2m-client-credentials")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    """Represents one step in the workflow, rendered as a card in the UI.

    Fields:
        title     — human-readable step name displayed as the card heading.
        ok        — True = success (green), False = failure (red).
        detail    — short explanation of what happened; may contain HTML.
        body      — pretty-printed JSON response body shown in a <details>.
        url       — "METHOD https://full/url" shown as a monospace badge.
        collapsed — if True the response <details> starts closed; use this
                    for verbose responses (e.g. JWKS) to keep the page readable.
    """
    title: str
    ok: bool = False
    detail: str = ""
    body: str = ""
    url: str = ""
    collapsed: bool = False


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

PAGE_CSS = """
  body{font-family:sans-serif; margin:0; background:#f5f5f5;}
  h2{margin-top:0;}
  button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;}
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
"""

HEADER_HTML = f"""<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>"""


def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
<title>{html.escape(title)}</title>
<style>{PAGE_CSS}</style>
</head>
<body>
{HEADER_HTML}
<div style="padding:32px 40px;max-width:980px;margin:0 auto;">
{body}
</div>
</body>
</html>"""


def _card_html(step: StepResult) -> str:
    """Render a StepResult as an HTML card.

    detail is rendered as-is (it may contain safe HTML such as <code> tags
    built with html.escape). body is always html.escape'd before insertion
    into the <pre> block so raw API responses cannot break the page.
    """
    badge_class = "ok" if step.ok else "err"
    badge_text = "(ok)" if step.ok else "(failed)"
    parts = [
        '<div class="card">',
        f'  <h3 class="{badge_class}">{html.escape(step.title)} {badge_text}</h3>',
    ]
    if step.url:
        parts.append(f'  <div class="url">{html.escape(step.url)}</div>')
    if step.detail:
        # detail may contain pre-escaped HTML — render as-is
        parts.append(f'  <div>{step.detail}</div>')
    if step.body:
        open_attr = "" if step.collapsed else " open"
        parts.append(
            f'  <details{open_attr}><summary>{"Show response" if step.collapsed else "Hide"}</summary>'
            f'<pre>{html.escape(step.body)}</pre></details>'
        )
    parts.append("</div>")
    return "\n".join(parts)


def _divider_html(title: str) -> str:
    """Render a section divider (dark-red bar) between User A and User B blocks."""
    return f'<div class="divider">{html.escape(title)}</div>'


def _render_claim_checks(errs: dict) -> str:
    """Return an HTML fragment listing claim validation errors, or a success message."""
    if not errs:
        return '<span style="color:#0a7a0a;">All claims valid.</span>'
    items = "".join(
        f"<li><code>{html.escape(k)}</code>: {html.escape(v)}</li>"
        for k, v in errs.items()
    )
    return f'<ul style="color:#b00020;">{items}</ul>'


# ---------------------------------------------------------------------------
# JWT / JWS helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string with or without padding.

    The JWT spec uses base64url without padding, but Python's base64.urlsafe_b64decode
    requires padding. We add the necessary "=" characters before decoding.
    """
    padding_needed = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * padding_needed)


def decode_jwt(token: str):
    """Decode a JWT into (header_dict, payload_dict, error_str).

    Splits the token on "." and base64url-decodes the first two parts.
    Does NOT verify the signature — call verify_jws separately after
    fetching the JWKS. Returns (None, None, error_string) on failure.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, f"not a 3-part JWT: {len(parts)} parts"
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception as exc:
        return None, None, f"decode header: {exc}"
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:
        return None, None, f"decode payload: {exc}"
    return header, payload, None


def _jwk_to_rsa_public_key(jwk: dict):
    """Build a cryptography RSA public key from a JWK dict (n/e components).

    An RSA JWK has two parameters:
      n — the modulus (base64url-encoded big-endian unsigned integer)
      e — the public exponent (base64url-encoded big-endian unsigned integer)
    Both are decoded from base64url and interpreted as big-endian integers to
    construct an RSAPublicNumbers object, from which the public key is derived.
    """
    kty = jwk.get("kty", "")
    if kty != "RSA":
        raise ValueError(f"unsupported kty {kty!r} (RSA only)")
    n_bytes = _b64url_decode(jwk["n"])
    e_bytes = _b64url_decode(jwk["e"])
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    pub = RSAPublicNumbers(e, n).public_key(default_backend())
    return pub


def verify_jws(token: str, header: dict, jwks: dict) -> str:
    """Verify an RS256 JWT signature against a JWKS dict.

    Verification steps:
      1. Read "kid" from the JWT header.
      2. Find the matching key in the JWKS (matched by kid).
      3. Build the RSA public key from the JWK's n and e parameters.
      4. Verify the PKCS#1 v1.5 signature over "{header}.{payload}" using SHA-256.

    Returns an empty string on success, or an error message string on failure.
    Returning a string (rather than raising) makes it convenient to embed the
    error in the card detail without an additional try/except at the call site.
    """
    alg = header.get("alg", "")
    kid = header.get("kid", "")
    if alg != "RS256":
        return f"unsupported alg {alg!r} (this sample verifies RS256 only)"
    keys = jwks.get("keys", [])
    match = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
    if match is None:
        return f"no JWK with kid={kid!r}"
    try:
        pub = _jwk_to_rsa_public_key(match)
    except Exception as exc:
        return str(exc)
    parts = token.split(".")
    # The signed input is the raw ASCII string "{base64url(header)}.{base64url(payload)}"
    # — the same bytes that were transmitted, not the decoded JSON.
    signed_input = (parts[0] + "." + parts[1]).encode()
    try:
        sig = _b64url_decode(parts[2])
    except Exception as exc:
        return f"decode signature: {exc}"
    try:
        pub.verify(sig, signed_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        return f"Signature INVALID: {exc}"
    return ""


def validate_access_claims(claims: dict, expected_issuer: str, expected_client_id: str) -> dict:
    """Validate the claims that must be present and correct in a client_credentials token.

    Returns a dict of {claim_name: error_string} for every failing check.
    An empty dict means all checks passed.

    Key M2M point: PingOne Worker app tokens do not have a "sub" claim because
    there is no authenticated user. The client's identity is in "client_id".
    Validating client_id (not sub) is essential for M2M token consumers.

    exp must be in the future. iat must not be more than 60 seconds in the
    future (tolerates minor clock skew between the token issuer and this server).
    There is no nonce check because nonces are only meaningful in interactive
    flows that involve a browser redirect.
    """
    errs = {}
    iss = claims.get("iss", "")
    if iss != expected_issuer:
        errs["iss"] = f"got {iss!r}, want {expected_issuer!r}"
    cid = claims.get("client_id", "")
    if cid != expected_client_id:
        errs["client_id"] = f"got {cid!r}, want {expected_client_id!r}"
    now = int(time.time())
    exp = claims.get("exp")
    if exp is None:
        errs["exp"] = "missing or non-numeric"
    else:
        try:
            if int(exp) < now:
                errs["exp"] = f"expired (exp={int(exp)}, now={now})"
        except (TypeError, ValueError):
            errs["exp"] = "missing or non-numeric"
    iat = claims.get("iat")
    if iat is not None:
        try:
            if int(iat) > now + 60:
                errs["iat"] = f"in the future (iat={int(iat)}, now={now})"
        except (TypeError, ValueError):
            pass
    return errs


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def pretty(raw: bytes) -> str:
    """Return indented JSON for display, or the raw UTF-8 string on failure.

    Used to format API response bodies before inserting them into <pre> blocks.
    The caller is responsible for html.escape'ing the result before insertion.
    """
    try:
        obj = json.loads(raw)
        return json.dumps(obj, indent=2)
    except Exception:
        return raw.decode("utf-8", errors="replace")


def pretty_any(obj) -> str:
    try:
        return json.dumps(obj, indent=2)
    except Exception:
        return str(obj)


def caller_ip(req) -> str:
    """Return the IP address of the HTTP request initiator.

    In cloud deployments the app runs behind a load balancer or reverse proxy
    that overwrites REMOTE_ADDR with its own IP. The real client IP is
    preserved in X-Forwarded-For. We use this as event.ip in the PingOne
    Protect risk evaluation so network-based predictors (Anonymous Network
    Detection, geo-velocity) operate on the actual caller's address.
    """
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        ip = xff.split(",")[0].strip()
        return ip
    addr = req.remote_addr or ""
    # strip port from IPv4/IPv6 (e.g. "127.0.0.1:12345" or "[::1]:12345")
    addr = addr.strip("[]")
    if ":" in addr:
        # could be host:port or plain IPv6; strip trailing :port if last segment looks like a port
        parts = addr.rsplit(":", 1)
        if parts[-1].isdigit():
            addr = parts[0].strip("[]")
    if addr in ("", "::1"):
        return "127.0.0.1"
    return addr


def extract_risk_result(parsed: dict):
    """Pull the risk level and composite score from a riskEvaluations response.

    The PingOne Protect response has the shape:
      { "result": { "level": "LOW", "score": 12 }, "details": { ... } }

    result.level — the overall verdict: LOW, MEDIUM, or HIGH.
    result.score — the combined numeric score (0–100) from all active predictors.
    The details object contains per-predictor scores and explains which predictor
    drove the outcome.

    Returns ("n/a", "n/a") if the expected fields are absent.
    """
    level = "n/a"
    score = "n/a"
    res = parsed.get("result") if isinstance(parsed, dict) else None
    if isinstance(res, dict):
        l = res.get("level", "")
        if l:
            level = l
        s = res.get("score")
        if s is not None:
            score = str(s)
    return level, score


# ---------------------------------------------------------------------------
# Workflow helpers
# ---------------------------------------------------------------------------

def run_risk_and_gate(access_token: str, risk_url: str, mgmt_url: str,
                      risk_body: dict, risk_step: str, mgmt_step: str,
                      req) -> list:
    """POST a risk evaluation to PingOne Protect, then gate the management API call.

    Enforcement logic:
      LOW / MEDIUM  → the management API call proceeds. The access token is
                      sent as a Bearer token in the Authorization header.
      HIGH          → the management API call is blocked. In a production
                      system this is where you would deny the request, trigger
                      step-up authentication, or alert on-call security teams.

    Returns a list of StepResult objects to be appended to the workflow list.
    """
    cards = []

    # The access token obtained via client_credentials is used as a Bearer
    # token. Both the Protect API and the management API accept the same token
    # because they live in the same PingOne environment.
    resp = requests.post(
        risk_url,
        json=risk_body,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
    )
    risk_raw = resp.content
    risk_status = resp.status_code
    try:
        risk_parsed = resp.json()
    except Exception:
        risk_parsed = {}

    risk_ok = risk_status < 400
    level, score = extract_risk_result(risk_parsed)

    event = risk_body.get("event", {})
    event_ip = event.get("ip", "")
    user_type = (event.get("user") or {}).get("type", "")

    if risk_step == "7b":
        # This evaluation is intentionally crafted to trigger a HIGH score.
        # IP 185.220.101.1 is a well-known Tor exit node. Tor is an anonymizing
        # network that routes traffic through volunteer relays to obscure origin.
        # PingOne Protect's Anonymous Network Detection predictor maintains a
        # database of Tor exit nodes, VPN endpoints, and other anonymizing
        # infrastructure. A score of 80 for this IP exceeds the HIGH threshold
        # of 75, so the overall evaluation returns HIGH.
        risk_detail = (
            f"<strong>This evaluation is intentionally constructed to trigger a HIGH risk score.</strong><br><br>"
            f"The IP <code>{html.escape(event_ip)}</code> is a known Tor exit node. Tor is an anonymizing network commonly associated with "
            f"attempts to obscure origin and bypass geo-controls. PingOne Protect's <strong>Anonymous Network Detection</strong> "
            f"predictor recognizes this IP and scores it at <strong>80</strong> — above the policy set's HIGH threshold of 75 — "
            f"causing the overall evaluation to return HIGH.<br><br>"
            f"<code>user.type</code> is set to <code>ANONYMOUS</code> and a bot-like user agent is supplied to further reflect "
            f"what a real suspicious M2M caller might look like. In production you would populate these fields from "
            f"the actual upstream caller rather than hardcoding them.<br><br>"
            f"SDK signals are omitted — there is no browser SDK in an M2M flow.<br>"
            f"HTTP {risk_status} &middot; level: <code>{html.escape(level)}</code> &middot; score: <code>{html.escape(score)}</code>"
        )
    else:
        risk_detail = (
            f"Event: ip=<code>{html.escape(event_ip)}</code>, user.type=<code>{html.escape(user_type)}</code>.<br>"
            f"PingOne Protect scores the event against the configured risk policy set and returns a risk level (LOW / MEDIUM / HIGH) plus per-predictor details.<br>"
            f"SDK signals are intentionally omitted — there is no browser SDK in an M2M flow.<br>"
            f"HTTP {risk_status} &middot; level: <code>{html.escape(level)}</code> &middot; score: <code>{html.escape(score)}</code>"
        )

    cards.append(StepResult(
        title=f"{risk_step}. PingOne Protect risk evaluation",
        ok=risk_ok,
        url=f"POST {risk_url}",
        detail=risk_detail,
        body=f"request:\n{pretty_any(risk_body)}\n\nresponse:\n{pretty(risk_raw)}",
    ))

    if not risk_ok:
        cards.append(StepResult(
            title=f"{mgmt_step}. Call PingOne Management API",
            ok=False,
            url=f"GET {mgmt_url}",
            detail="Skipped — the risk evaluation step did not succeed.",
        ))
        return cards

    if level.upper() == "HIGH":
        # High-risk callers are blocked. The management API is never contacted.
        cards.append(StepResult(
            title=f"{mgmt_step}. Call PingOne Management API",
            ok=False,
            url=f"GET {mgmt_url}",
            detail=(
                f"<strong>Blocked.</strong> PingOne Protect returned risk level <code>{html.escape(level)}</code> "
                f"(score: <code>{html.escape(score)}</code>). "
                f"Anonymous Network Detection flagged the IP as a known Tor exit node. "
                f"The downstream management API call was <strong>not</strong> made."
            ),
        ))
        return cards

    # Risk is LOW or MEDIUM — proceed with the management API call.
    mgmt_resp = requests.get(mgmt_url, headers={"Authorization": f"Bearer {access_token}"})
    mgmt_raw = mgmt_resp.content
    mgmt_status = mgmt_resp.status_code

    cards.append(StepResult(
        title=f"{mgmt_step}. Call PingOne Management API",
        ok=mgmt_status < 400,
        url=f"GET {mgmt_url}",
        detail=(
            f"Risk level <code>{html.escape(level)}</code> — proceeding. "
            f"The access token is sent as a Bearer token.<br>HTTP {mgmt_status}"
        ),
        body=pretty(mgmt_raw),
    ))
    return cards


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------

# Each item in the workflow list is either:
#   StepResult  — rendered as a card
#   dict with key "divider" — rendered as a section divider (dark-red bar)

def run_workflow(req) -> list:
    """Execute the full M2M + Protect workflow. Returns a mixed list of StepResult / divider dicts."""
    items = []

    # Step 1: Assemble the token request.
    # The token endpoint URL is always {AUTH_PATH}/{ENV_ID}/as/token.
    # Authentication uses HTTP Basic (CLIENT_SECRET_BASIC): the client_id and
    # client_secret are base64-encoded as "client_id:client_secret" and placed
    # in the Authorization header. No data goes in the body except grant_type.
    token_url = f"{AUTH_PATH}/{ENV_ID}/as/token"
    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

    items.append(StepResult(
        title="1. Build token request",
        ok=True,
        url=f"POST {token_url}",
        detail=(
            "The client_credentials grant requires no user interaction. The only inputs are the client's own credentials.<br><br>"
            "Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>"
            "&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>"
            "Form body:<br>&nbsp;&nbsp;<code>grant_type=client_credentials</code>"
        ),
        body=f"client_id:     {CLIENT_ID}\ngrant_type:    client_credentials",
    ))

    # Step 2: Call the token endpoint.
    # A successful response contains access_token (JWT), token_type ("Bearer"),
    # and expires_in (seconds until expiry). There is no refresh_token because
    # re-authentication in client_credentials is trivial — just resend the same
    # request with the same credentials.
    tok_resp = requests.post(
        token_url,
        data={"grant_type": "client_credentials"},
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    tok_raw = tok_resp.content
    tok_status = tok_resp.status_code
    try:
        tok_parsed = tok_resp.json()
    except Exception:
        tok_parsed = {}

    tok_ok = tok_status < 400
    items.append(StepResult(
        title="2. Token endpoint response",
        ok=tok_ok,
        url=f"POST {token_url}",
        detail=(
            f"PingOne validates the client credentials and, if valid, returns an access token. "
            f"No authorization code or redirect is involved — this is the entire grant in one round trip.<br>"
            f"HTTP {tok_status}"
        ),
        body=pretty(tok_raw),
    ))
    if not tok_ok:
        return items

    access_token = tok_parsed.get("access_token", "")

    # Step 3: Decode the access token without verifying the signature.
    # The JWT payload reveals client_id (the M2M client identity — there is no
    # "sub" because there is no user), iss, exp, and scope. Decoding is quick
    # and useful for diagnostics; actual verification happens in step 5.
    header, payload, decode_err = decode_jwt(access_token)
    if decode_err:
        decode_body = ""
        decode_ok = False
    else:
        decode_body = f"header:\n{pretty_any(header)}\n\npayload:\n{pretty_any(payload)}"
        decode_ok = True

    items.append(StepResult(
        title="3. Decode access token",
        ok=decode_ok,
        detail=(
            "The access token is a JWT. Decoding it (without yet verifying the signature) shows the claims PingOne embedded "
            "— notably <code>client_id</code> (the client identity for M2M tokens), <code>iss</code>, <code>exp</code>, "
            "and any scopes granted by the authorization server."
            if not decode_err else html.escape(decode_err)
        ),
        body=decode_body,
    ))

    # Step 4: Fetch the JWKS (JSON Web Key Set).
    # PingOne publishes its public signing keys at /as/jwks. The kid (key ID) in
    # each JWKS entry matches the kid in the JWT header, allowing us to pick the
    # correct key when PingOne rotates its signing keys. In production, cache
    # the JWKS and only re-fetch when a new kid is encountered.
    jwks_url = f"{AUTH_PATH}/{ENV_ID}/as/jwks"
    jwks_resp = requests.get(jwks_url)
    jwks_raw = jwks_resp.content
    jwks_ok = jwks_resp.status_code < 400
    try:
        jwks = jwks_resp.json()
    except Exception:
        jwks = {}

    items.append(StepResult(
        title="4. Fetch JWKS",
        ok=jwks_ok,
        url=f"GET {jwks_url}",
        detail=(
            "Public keys used to verify the access token signature. In production, cache this response "
            "and re-fetch only when a new <code>kid</code> is encountered."
        ),
        body=pretty(jwks_raw),
        collapsed=True,
    ))

    # Step 5: Verify the JWT signature.
    # The signed input is the raw ASCII string "{base64url(header)}.{base64url(payload)}"
    # — the same bytes that were transmitted, not the decoded JSON. Any modification
    # to the token (changing a claim value, reordering keys) invalidates the signature.
    if decode_err:
        verify_err = f"cannot verify — JWT decode failed: {decode_err}"
    else:
        verify_err = verify_jws(access_token, header, jwks)

    alg_val = html.escape(str(header.get("alg", ""))) if header else ""
    kid_val = html.escape(str(header.get("kid", ""))) if header else ""
    if verify_err:
        verify_detail = (
            f"alg: <code>{alg_val}</code>, kid: <code>{kid_val}</code><br>"
            f"{html.escape(verify_err)}"
        )
    else:
        verify_detail = (
            f"alg: <code>{alg_val}</code>, kid: <code>{kid_val}</code><br>"
            f"Signature valid (RS256, key matched by <code>kid</code>)."
        )

    items.append(StepResult(
        title="5. Verify access token signature",
        ok=not bool(verify_err),
        detail=verify_detail,
    ))

    # Step 6: Validate access token claims.
    # Checks: iss matches this environment's AS issuer URL; client_id matches
    # the configured CLIENT_ID (M2M tokens use client_id instead of sub because
    # there is no user subject); exp is in the future; iat is not more than
    # 60 seconds in the future. No nonce check — nonces are only meaningful in
    # interactive flows that involve a browser redirect.
    expected_issuer = f"{AUTH_PATH}/{ENV_ID}/as"
    if payload is not None:
        claims_errs = validate_access_claims(payload, expected_issuer, CLIENT_ID)
    else:
        claims_errs = {"jwt": "could not decode payload"}

    claims_detail = (
        f"Required checks: <code>iss</code> matches <code>{html.escape(expected_issuer)}</code>, "
        f"<code>client_id</code> matches <code>{html.escape(CLIENT_ID)}</code>, "
        f"<code>exp</code> &gt; now, <code>iat</code> not in the future.<br>"
        f"Note: PingOne Worker app tokens use <code>client_id</code> (not <code>sub</code>) to identify the client. "
        f"There is no <code>nonce</code> — no user authentication was involved.<br>"
        f"{_render_claim_checks(claims_errs)}"
    )

    items.append(StepResult(
        title="6. Validate access token claims",
        ok=len(claims_errs) == 0,
        detail=claims_detail,
        body=pretty_any(payload) if payload is not None else "",
    ))

    risk_url = f"{API_PATH}/v1/environments/{ENV_ID}/riskEvaluations"
    mgmt_url = f"{API_PATH}/v1/environments/{ENV_ID}/users"

    # Steps 7a / 8a — User A: trusted caller.
    # Real client IP, user.type=EXTERNAL (a known, identified user on a normal
    # network). PingOne Protect should return LOW or MEDIUM, and the
    # management API call proceeds.
    items.append({"divider": True, "title": "User A — trusted (real IP, type=EXTERNAL)"})

    client_ip = caller_ip(req)
    risk_body_a = {
        "event": {
            "ip": client_ip,
            "flow": {"type": "AUTHENTICATION"},
            "session": {"id": "m2m-demo-session-a"},
            "user": {
                "id": "m2m-user-trusted",
                "type": "EXTERNAL",
                "name": "m2m-user-trusted",
            },
            "browser": {"userAgent": req.headers.get("User-Agent", "")},
            "sharingType": "SHARED",
            "targetResource": {
                "id": "m2m-demo-resource",
                "name": "m2m-demo-resource",
            },
        },
        "riskPolicySet": {"id": RISK_POLICY_SET_ID},
    }
    items.extend(run_risk_and_gate(access_token, risk_url, mgmt_url, risk_body_a, "7a", "8a", req))

    # Steps 7b / 8b — User B: suspicious caller.
    # The event is deliberately crafted to trigger HIGH:
    #   ip:        185.220.101.1 — a Tor exit node. Anonymous Network Detection
    #              scores this IP at 80, exceeding the HIGH threshold of 75.
    #   user.type: ANONYMOUS — the upstream caller's identity is unknown.
    #   userAgent: bot-like string to further reflect a suspicious profile.
    # The management API call is blocked when HIGH is returned.
    items.append({"divider": True, "title": "User B — suspicious (Tor IP, type=ANONYMOUS)"})

    risk_body_b = {
        "event": {
            "ip": "185.220.101.1",  # known Tor exit node — triggers Anonymous Network Detection
            "flow": {"type": "AUTHENTICATION"},
            "session": {"id": "m2m-demo-session-b"},
            "user": {
                "id": "m2m-user-suspicious",
                "type": "ANONYMOUS",
                "name": "m2m-user-suspicious",
            },
            "browser": {"userAgent": "python-requests/2.28.0"},  # bot-like UA
            "sharingType": "SHARED",
            "targetResource": {
                "id": "m2m-demo-resource",
                "name": "m2m-demo-resource",
            },
        },
        "riskPolicySet": {"id": RISK_POLICY_SET_ID},
    }
    items.extend(run_risk_and_gate(access_token, risk_url, mgmt_url, risk_body_b, "7b", "8b", req))

    return items


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

INDEX_BODY = f"""<h2>OAuth 2.0 Client Credentials (M2M) + PingOne Protect</h2>
<p>This sample walks through the OAuth 2.0 <strong>client_credentials</strong> grant. There is no user, no browser redirect, and no PKCE. The client authenticates directly with the PingOne token endpoint using its own credentials, receives an access token, and calls <strong>PingOne Protect</strong> for two risk evaluations:</p>
<ul>
  <li><strong>User A — trusted:</strong> real client IP, <code>type=EXTERNAL</code> — expected to score LOW or MEDIUM, API call proceeds.</li>
  <li><strong>User B — suspicious:</strong> Tor exit node IP (<code>185.220.101.1</code>), <code>type=ANONYMOUS</code> — expected to score HIGH via Anonymous Network Detection, API call blocked.</li>
</ul>
<p>Both paths are rendered side-by-side so you can compare what PingOne Protect returns and see how the application gates the downstream call differently in each case.</p>
<form action="/run" method="POST"><button type="submit">Run Flow</button></form>
<p style="color:#666;font-size:13px;margin-top:30px;">PingOne config required: Worker application with Token Endpoint Auth Method = Client Secret Basic. The Worker app must have roles for Identity Data (read) and PingOne Protect (risk evaluation). A Protect risk policy set must exist with Anonymous Network Detection enabled and scored above the HIGH threshold; its ID goes in <code>PINGONE_RISK_POLICY_SET_ID</code>.</p>"""

app = Flask(__name__)


@app.route("/")
def index():
    return _page("M2M Client Credentials — start", INDEX_BODY)


@app.route("/run", methods=["POST"])
def run():
    items = run_workflow(request)

    parts = []
    for item in items:
        if isinstance(item, dict) and item.get("divider"):
            parts.append(_divider_html(item["title"]))
        else:
            parts.append(_card_html(item))

    body = "\n".join(parts) + '\n<p style="margin-top:20px;"><a href="/">Run again</a></p>'
    return _page("Run — complete", body)


if __name__ == "__main__":
    print("M2M Client Credentials demo on http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=False)
