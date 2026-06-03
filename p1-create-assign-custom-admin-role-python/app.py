"""
PingOne Custom Admin Role Workflow — Python / Flask

PingOne ships with a fixed set of platform (built-in) roles such as
"Organization Admin" and "Application Owner". These roles grant broad access
and cannot be modified through the API. Custom admin roles let you create
narrower, purpose-built roles — for example, an application manager that can
read and update apps but is prevented from creating new ones.

This Flask app drives the full workflow end-to-end:

  1. Obtain an admin bearer token (client_credentials grant) from the PingOne
     token endpoint. The worker app must hold the Organization Admin platform
     role. All management API calls require this Bearer token; Organisation
     Admin is needed because creating custom roles and assigning them is a
     privileged operation.

  2. GET /roles — list all platform (built-in) roles. We read two IDs from
     this response: "Application Owner" (to understand which permission IDs
     are available) and "Organization Admin" (to reference in canBeAssignedBy).

  3. Select a subset of permissions using the service:action:resource format
     (e.g. "applications:read:application"). We take read + update and drop
     create, so holders of the custom role cannot add new applications.

  4. POST /environments/{envID}/roles — create the custom admin role.
     Two fields deserve attention:
       applicableTo    — ["ENVIRONMENT","POPULATION"] lets the role be assigned
                         at environment or population scope.
       canBeAssignedBy — lists platform role IDs whose holders may delegate
                         the custom role. If empty/omitted, no one can assign
                         the role — not even an Organization Admin.

  5. Create a population and a group. The population provides the scope
     boundary; the group is the role-assignment vehicle.

  6. POST /groups/{groupID}/roleAssignments — assign the custom role to the
     group, scoped to the population (scope.type = "POPULATION"). PingOne has
     no standalone "assign group to population" API; scoping is expressed on
     the role assignment itself.

  7. Create a user inside the population and add them to the group. The user
     inherits the custom role through group membership.

  8. GET /users/{userID}/roleAssignments — verify the custom role ID appears
     in the user's effective role assignments.

Prerequisites: a worker app (client_credentials) with Organization Admin.
Set PINGONE_ADMIN_ENV_ID, PINGONE_ADMIN_CLIENT_ID, PINGONE_ADMIN_CLIENT_SECRET,
PINGONE_TARGET_ENV_ID, PINGONE_AUTH_PATH, and PINGONE_API_PATH in .env.
"""
import html
import json
import logging
import os
import base64
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests
from dotenv import load_dotenv
from flask import Flask, request

load_dotenv()

_logo_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'logo.png')
LOGO_SRC = 'data:image/png;base64,' + base64.b64encode(open(_logo_path, 'rb').read()).decode()

# ADMIN_ENV_ID — the environment that contains the worker app used to obtain
# the admin token. Typically your "Administrators" environment.
ADMIN_ENV_ID = (os.getenv("PINGONE_ADMIN_ENV_ID") or "").strip()
# ADMIN_CLIENT_ID / ADMIN_CLIENT_SECRET — credentials for the worker app that
# holds Organization Admin. Used with the client_credentials grant (no user login).
ADMIN_CLIENT_ID = (os.getenv("PINGONE_ADMIN_CLIENT_ID") or "").strip()
ADMIN_CLIENT_SECRET = (os.getenv("PINGONE_ADMIN_CLIENT_SECRET") or "").strip()
# TARGET_ENV_ID — where the custom role, population, group, and test user are
# created. May be the same as ADMIN_ENV_ID or a separate environment.
TARGET_ENV_ID = (os.getenv("PINGONE_TARGET_ENV_ID") or "").strip()
# AUTH_PATH / API_PATH — regional base URLs.
# North America: https://auth.pingone.com / https://api.pingone.com/v1
# Europe:        https://auth.pingone.eu  / https://api.pingone.eu/v1
AUTH_PATH = (os.getenv("PINGONE_AUTH_PATH") or "https://auth.pingone.com").rstrip("/")
API_PATH = (os.getenv("PINGONE_API_PATH") or "https://api.pingone.com/v1").rstrip("/")

if not all([ADMIN_ENV_ID, ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET, TARGET_ENV_ID, AUTH_PATH, API_PATH]):
    raise SystemExit("Missing required environment variables. Please check your .env file.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("p1-custom-admin-role")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    """Represents the outcome of a single workflow step for display in the results page.

    Fields:
        title     -- human-readable step name shown as the card heading.
        ok        -- True on success; False renders the heading in red.
        detail    -- one-line summary (e.g. "HTTP 201 — id=abc123").
        body      -- pretty-printed JSON response body; shown in a <details> element.
        url       -- "METHOD https://full/url" shown as a monospace badge.
        collapsed -- if True, the <details> element starts closed (used for long
                     responses like the full platform-roles list).
    """
    title: str
    ok: bool = False
    detail: str = ""
    body: str = ""
    url: str = ""
    collapsed: bool = False


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

INDEX_HTML = f"""<!DOCTYPE html>
<html>
<head>
<title>PingOne Custom Admin Role Workflow</title>
<style>
  body{{font-family:sans-serif; margin:0; background:#f5f5f5;}}
  button{{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;}}
  pre{{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word;}}
  .step{{margin-top:18px;}}
  .step h3{{margin:0 0 6px 0;}}
  .ok{{color:#0a7a0a;}}
  .err{{color:#b00020;}}
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="{LOGO_SRC}" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:900px;margin:0 auto;">
  <h2>Custom Admin Role Workflow</h2>
  <p>Creates a trimmed-down application admin role, assigns it to a group scoped to a population, registers a user into that population, and verifies the inherited role assignment.</p>
  <form action="/run" method="POST"><button type="submit">Run Workflow</button></form>
</div>
</body>
</html>"""


def _step_html(step: StepResult) -> str:
    badge_class = "ok" if step.ok else "err"
    badge_text = "(ok)" if step.ok else "(failed)"
    parts = [
        f'<div class="step">',
        f'  <h3 class="{badge_class}">{html.escape(step.title)} {badge_text}</h3>',
    ]
    if step.url:
        parts.append(f'  <div class="url">{html.escape(step.url)}</div>')
    if step.detail:
        parts.append(f'  <p>{html.escape(step.detail)}</p>')
    if step.body:
        open_attr = "" if step.collapsed else " open"
        parts.append(
            f'  <details{open_attr}><summary>Response</summary>'
            f'<pre>{html.escape(step.body)}</pre></details>'
        )
    parts.append("</div>")
    return "\n".join(parts)


def results_html(success: bool, steps: list[StepResult]) -> str:
    banner_class = "ok" if success else "err"
    banner_text = "All steps completed successfully." if success else "Workflow halted on error."
    steps_html = "\n".join(_step_html(s) for s in steps)
    return f"""<!DOCTYPE html>
<html>
<head>
<title>Workflow Result</title>
<style>
  body{{font-family:sans-serif; margin:0; background:#f5f5f5;}}
  pre{{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word; margin:0;}}
  .step{{margin-top:18px;}}
  .step h3{{margin:0 0 6px 0;}}
  .ok{{color:#0a7a0a;}}
  .err{{color:#b00020;}}
  .banner{{padding:10px; margin-top:10px; border-radius:4px;}}
  .banner.ok{{background:#e6f7e6;}}
  .banner.err{{background:#fde8ea;}}
  .url{{font-family:monospace; font-size:13px; color:#555; background:#f0f0f0; padding:4px 8px; border-radius:3px; display:inline-block; margin-bottom:6px; word-break:break-all;}}
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
  <h2>Workflow Result</h2>
  <div class="banner {banner_class}">{banner_text}</div>
{steps_html}
  <p><a href="/">Back</a></p>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# PingOne API helpers
# ---------------------------------------------------------------------------

def get_admin_token() -> str:
    """Obtain a short-lived bearer token via the OAuth 2.0 client_credentials grant.

    client_credentials is the correct grant for server-to-server admin operations
    where no end-user is present. The resulting token inherits the platform roles
    assigned to the worker app in PingOne (Organization Admin in this case).

    Authentication uses HTTP Basic (requests' auth= parameter handles the
    base64 encoding of "clientID:clientSecret"). This corresponds to the
    CLIENT_SECRET_BASIC token endpoint authentication method in PingOne.
    """
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


def api_call(
    method: str,
    path: str,
    token: str,
    payload: Optional[Any] = None,
) -> tuple[str, int, bytes, dict]:
    """Issue a JSON request to the PingOne management API with the admin bearer token.

    Returns (full_url, status_code, raw_bytes, parsed_dict).
      full_url    -- the complete request URL for display in step cards.
      status_code -- HTTP status code.
      raw_bytes   -- raw response body; always populated.
      parsed_dict -- json.loads(raw_bytes) on success, or {} if not valid JSON.
                     Always check status_code before trusting parsed content.
    """
    full_url = API_PATH + path
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"

    resp = requests.request(
        method,
        full_url,
        json=payload if payload is not None else None,
        headers=headers,
    )
    raw = resp.content
    try:
        parsed = resp.json()
    except Exception:
        parsed = {}
    return full_url, resp.status_code, raw, parsed


def pretty(raw: bytes) -> str:
    """Return indented JSON for display in the results page.

    Falls back to the raw decoded string if the body is not valid JSON (e.g. a
    plain-text error from PingOne) so the developer still sees the response.
    """
    try:
        obj = json.loads(raw)
        return json.dumps(obj, indent=2)
    except Exception:
        return raw.decode("utf-8", errors="replace")


def find_role_id(parsed: dict, name: str) -> tuple[str, str]:
    """Return (id, name) for the first role in _embedded.roles whose name matches (case-insensitive).

    PingOne wraps list responses in a HAL _embedded envelope. For most tenants
    the default page size covers all platform roles in one request so pagination
    is not handled here.
    """
    embedded = parsed.get("_embedded") or {}
    roles = embedded.get("roles") or []
    for role in roles:
        if isinstance(role, dict) and role.get("name", "").lower() == name.lower():
            return role.get("id", ""), role.get("name", "")
    return "", ""


def response_mentions_role(raw: bytes, role_id: str) -> bool:
    """Return True if role_id appears anywhere in the raw response bytes.

    A plain bytes-contains check is sufficient: the roleAssignments response
    embeds the role object in each assignment, so the role ID always appears
    as a JSON string value when the role is present.
    """
    return role_id.encode() in raw


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------

def run_workflow() -> tuple[bool, list[StepResult]]:
    """Execute the full custom admin role lifecycle.

    Returns (success, steps). Each StepResult in steps captures one API call.
    On failure the function returns immediately so the results page highlights
    exactly which step failed and why.
    """
    steps: list[StepResult] = []

    # Step 0: obtain a bearer token via client_credentials.
    # The worker app must hold Organization Admin — without it, later calls to
    # create custom roles or assign them return 403 Forbidden.
    try:
        token = get_admin_token()
    except Exception as exc:
        steps.append(StepResult(title="Obtain admin access token", ok=False, detail=str(exc)))
        return False, steps
    steps.append(StepResult(
        title="Obtain admin access token",
        ok=True,
        detail="client_credentials grant succeeded.",
    ))

    # Step 1: GET /roles — fetch all platform (built-in) roles.
    # Platform roles are global and read-only; they cannot be created or deleted.
    # We need two IDs from this response:
    #   "Application Owner"  — to understand which permission IDs to reference.
    #   "Organization Admin" — to populate canBeAssignedBy on the custom role.
    # The response is often large, so collapsed=True hides it by default in the UI.
    req_url, status, raw, parsed = api_call("GET", "/roles", token)
    step1 = StepResult(
        title="List platform roles",
        body=pretty(raw),
        url=f"GET {req_url}",
        collapsed=True,
    )
    if status >= 400:
        step1.detail = f"HTTP {status}"
        steps.append(step1)
        return False, steps
    step1.ok = True
    step1.detail = f"HTTP {status}"
    steps.append(step1)

    roles_url = f"GET {req_url}"

    # Locate Application Owner by name. Its permission IDs serve as the template
    # for the custom role we are building.
    app_owner_id, app_owner_name = find_role_id(parsed, "Application Owner")
    if not app_owner_id:
        steps.append(StepResult(
            title="Find Application Owner platform role",
            ok=False,
            detail="Could not find an 'Application Owner' role in this tenant.",
            url=roles_url,
        ))
        return False, steps
    steps.append(StepResult(
        title="Find Application Owner platform role",
        ok=True,
        detail=(
            f"Found \"{app_owner_name}\" (id={app_owner_id}) — "
            "we'll borrow its application permissions and drop the create permission."
        ),
        url=roles_url,
    ))

    # Locate Organization Admin by name. Its ID goes into canBeAssignedBy on the
    # custom role. Without canBeAssignedBy, the custom role is created but no
    # actor — not even an Organization Admin — can assign it to a user or group.
    org_admin_id, _ = find_role_id(parsed, "Organization Admin")
    if not org_admin_id:
        steps.append(StepResult(
            title="Find Organization Admin platform role",
            ok=False,
            detail="Could not find an 'Organization Admin' role — cannot grant delegation authority.",
            url=roles_url,
        ))
        return False, steps
    steps.append(StepResult(
        title="Find Organization Admin platform role",
        ok=True,
        detail=f"Found (id={org_admin_id}) — will add to canBeAssignedBy on the custom role.",
        url=roles_url,
    ))

    # Step 2: choose the permissions to include in the custom role.
    # Permission IDs use the format service:action:resource.
    # We pick read + update and omit "applications:create:application" so holders
    # of the custom role cannot add new applications — only view and edit them.
    selected = [
        {"id": "applications:read:application"},
        {"id": "applications:update:application"},
    ]
    selected_summary = json.dumps(selected, indent=2)
    steps.append(StepResult(
        title="Select read/update application permissions",
        ok=True,
        detail="Using applications:read:application + applications:update:application (dropping create).",
        body=selected_summary,
        url=roles_url,
    ))

    # Step 3: create the custom admin role.
    # Custom roles are scoped to an environment: POST /environments/{envID}/roles.
    # This endpoint is separate from GET /roles (which lists read-only platform roles).
    #
    # Key payload fields:
    #   applicableTo    — controls whether the role can be assigned at ENVIRONMENT
    #                     scope, POPULATION scope, or both. Including both gives
    #                     administrators the flexibility to choose at assignment time.
    #   canBeAssignedBy — lists platform role IDs whose holders may delegate this
    #                     custom role. If empty or omitted, no one can assign the
    #                     role — not even an Organization Admin.
    role_suffix = int(time.time())
    custom_role_payload = {
        "name": f"App Manager (Read/Update) {role_suffix}",
        "description": "Trimmed-down Application Owner: can read and update applications but cannot create them.",
        "applicableTo": ["ENVIRONMENT", "POPULATION"],
        "permissions": selected,
        "canBeAssignedBy": [{"id": org_admin_id}],
    }
    req_url, status, raw, parsed = api_call(
        "POST", f"/environments/{TARGET_ENV_ID}/roles", token, custom_role_payload
    )
    step3 = StepResult(
        title="Create custom admin role",
        body=pretty(raw),
        detail=f"HTTP {status}",
        url=f"POST {req_url}",
    )
    if status >= 400:
        steps.append(step3)
        return False, steps
    custom_role_id = parsed.get("id", "")
    if not custom_role_id:
        step3.detail = "Role created but response contained no id."
        steps.append(step3)
        return False, steps
    step3.ok = True
    step3.detail = f"HTTP {status} — custom role id={custom_role_id}"
    steps.append(step3)

    # Step 4: create a population to act as the role-assignment scope boundary.
    # Users in this population will be subject to the custom role when it is
    # assigned at POPULATION scope; users in other populations are unaffected.
    pop_payload = {
        "name": f"App Management Scope {role_suffix}",
        "description": "Population that scopes the trimmed-down App Manager role.",
    }
    req_url, status, raw, parsed = api_call(
        "POST", f"/environments/{TARGET_ENV_ID}/populations", token, pop_payload
    )
    step4 = StepResult(
        title="Create population",
        body=pretty(raw),
        detail=f"HTTP {status}",
        url=f"POST {req_url}",
    )
    if status >= 400:
        steps.append(step4)
        return False, steps
    population_id = parsed.get("id", "")
    if not population_id:
        step4.detail = "Population created but response contained no id."
        steps.append(step4)
        return False, steps
    step4.ok = True
    step4.detail = f"HTTP {status} — population id={population_id}"
    steps.append(step4)

    # Step 5: create a group to act as the role-assignment vehicle.
    # Assigning a role to a group means adding/removing group members is the
    # only operation needed to grant/revoke the role — no per-user API calls.
    group_payload = {
        "name": f"App Managers {role_suffix}",
        "description": "Group that receives the trimmed-down App Manager role.",
    }
    req_url, status, raw, parsed = api_call(
        "POST", f"/environments/{TARGET_ENV_ID}/groups", token, group_payload
    )
    step5 = StepResult(
        title="Create group",
        body=pretty(raw),
        detail=f"HTTP {status}",
        url=f"POST {req_url}",
    )
    if status >= 400:
        steps.append(step5)
        return False, steps
    group_id = parsed.get("id", "")
    if not group_id:
        step5.detail = "Group created but response contained no id."
        steps.append(step5)
        return False, steps
    step5.ok = True
    step5.detail = f"HTTP {status} — group id={group_id}"
    steps.append(step5)

    # Step 6: assign the custom role to the group, scoped to the population.
    # PingOne has no standalone "assign group to population" endpoint; the scope
    # is expressed on the role assignment itself via scope.type = "POPULATION".
    # Group members inherit the custom role within this population boundary only.
    group_role_payload = {
        "role": {"id": custom_role_id},
        "scope": {
            "id": population_id,
            "type": "POPULATION",  # must be uppercase
        },
    }
    req_url, status, raw, parsed = api_call(
        "POST",
        f"/environments/{TARGET_ENV_ID}/groups/{group_id}/roleAssignments",
        token,
        group_role_payload,
    )
    step6 = StepResult(
        title="Assign custom role to group, scoped to population",
        body=pretty(raw),
        detail=f"HTTP {status}",
        url=f"POST {req_url}",
    )
    if status >= 400:
        steps.append(step6)
        return False, steps
    step6.ok = True
    steps.append(step6)

    # Step 7: create a user inside the population.
    # Placing the user in the same population as the role-assignment scope
    # ensures group membership in step 8 activates the scoped custom role.
    # The population field requires a reference object {"id": "..."} — not a
    # plain string ID.
    user_payload = {
        "username": f"app-manager-test-{role_suffix}",
        "email": f"app-manager-test-{role_suffix}@example.com",
        "population": {"id": population_id},
        "name": {
            "given": "App",
            "family": "Manager",
        },
    }
    req_url, status, raw, parsed = api_call(
        "POST", f"/environments/{TARGET_ENV_ID}/users", token, user_payload
    )
    step7 = StepResult(
        title="Register a new user into the population",
        body=pretty(raw),
        detail=f"HTTP {status}",
        url=f"POST {req_url}",
    )
    if status >= 400:
        steps.append(step7)
        return False, steps
    user_id = parsed.get("id", "")
    if not user_id:
        step7.detail = "User created but response contained no id."
        steps.append(step7)
        return False, steps
    step7.ok = True
    step7.detail = f"HTTP {status} — user id={user_id}"
    steps.append(step7)

    # Step 8: add the user to the group so the role propagates to them.
    # PingOne returns 201 Created with a body, or 204 No Content — both are
    # success statuses, so we only fail on 4xx/5xx.
    req_url, _, raw, _ = api_call(
        "POST",
        f"/environments/{TARGET_ENV_ID}/users/{user_id}/memberOfGroups",
        token,
        {"id": group_id},
    )
    step8 = StepResult(
        title="Add user to the group",
        body=pretty(raw),
        url=f"POST {req_url}",
    )
    step8.ok = True
    step8.detail = "User added to group; role assignment now applies via group membership."
    steps.append(step8)

    # Step 9: verify the user's effective role assignments.
    # GET /users/{id}/roleAssignments returns both directly-assigned roles and
    # those inherited through group membership. We do a plain bytes-contains
    # check for the custom role ID. If absent, propagation may still be in
    # progress — the step is marked failed with an explanatory message.
    req_url, status, raw, _ = api_call(
        "GET",
        f"/environments/{TARGET_ENV_ID}/users/{user_id}/roleAssignments",
        token,
    )
    step9 = StepResult(
        title="Verify user role assignments",
        body=pretty(raw),
        detail=f"HTTP {status}",
        url=f"GET {req_url}",
    )
    if status >= 400:
        steps.append(step9)
        return False, steps
    if not response_mentions_role(raw, custom_role_id):
        step9.ok = False
        step9.detail = (
            f"HTTP {status} — user does not yet appear to have the custom role; "
            "check the raw response below. Role assignments via groups may require a brief propagation delay."
        )
        steps.append(step9)
        return False, steps
    step9.ok = True
    step9.detail = f"HTTP {status} — user's role assignments include the custom role (inherited via group)."
    steps.append(step9)

    return True, steps


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/run", methods=["POST"])
def run():
    success, steps = run_workflow()
    return results_html(success, steps)


if __name__ == "__main__":
    print("Custom Admin Role workflow on http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=False)
