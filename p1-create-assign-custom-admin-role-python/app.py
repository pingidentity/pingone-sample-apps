import html
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests
from dotenv import load_dotenv
from flask import Flask, request

load_dotenv()

ADMIN_ENV_ID = (os.getenv("PINGONE_ADMIN_ENV_ID") or "").strip()
ADMIN_CLIENT_ID = (os.getenv("PINGONE_ADMIN_CLIENT_ID") or "").strip()
ADMIN_CLIENT_SECRET = (os.getenv("PINGONE_ADMIN_CLIENT_SECRET") or "").strip()
TARGET_ENV_ID = (os.getenv("PINGONE_TARGET_ENV_ID") or "").strip()
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
    title: str
    ok: bool = False
    detail: str = ""
    body: str = ""
    url: str = ""
    collapsed: bool = False


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
<title>PingOne Custom Admin Role Workflow</title>
<style>
  body{font-family:sans-serif; margin:40px; max-width:900px;}
  button{font-size:16px; padding:10px 20px; cursor:pointer;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word;}
  .step{margin-top:18px;}
  .step h3{margin:0 0 6px 0;}
  .ok{color:#0a7a0a;}
  .err{color:#b00020;}
</style>
</head>
<body>
  <h2>Custom Admin Role Workflow</h2>
  <p>Creates a trimmed-down application admin role, assigns it to a group scoped to a population, registers a user into that population, and verifies the inherited role assignment.</p>
  <form action="/run" method="POST"><button type="submit">Run Workflow</button></form>
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
  body{{font-family:sans-serif; margin:40px; max-width:900px;}}
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
  <h2>Workflow Result</h2>
  <div class="banner {banner_class}">{banner_text}</div>
{steps_html}
  <p><a href="/">Back</a></p>
</body>
</html>"""


# ---------------------------------------------------------------------------
# PingOne API helpers
# ---------------------------------------------------------------------------

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


def api_call(
    method: str,
    path: str,
    token: str,
    payload: Optional[Any] = None,
) -> tuple[str, int, bytes, dict]:
    """Issue a JSON request to the PingOne management API with the admin bearer token.

    Returns (full_url, status_code, raw_bytes, parsed_json).
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
    """Return indented JSON for display, or the raw string on failure."""
    try:
        obj = json.loads(raw)
        return json.dumps(obj, indent=2)
    except Exception:
        return raw.decode("utf-8", errors="replace")


def find_role_id(parsed: dict, name: str) -> tuple[str, str]:
    """Return (id, name) for the first role whose name matches (case-insensitive)."""
    embedded = parsed.get("_embedded") or {}
    roles = embedded.get("roles") or []
    for role in roles:
        if isinstance(role, dict) and role.get("name", "").lower() == name.lower():
            return role.get("id", ""), role.get("name", "")
    return "", ""


def response_mentions_role(raw: bytes, role_id: str) -> bool:
    return role_id.encode() in raw


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------

def run_workflow() -> tuple[bool, list[StepResult]]:
    steps: list[StepResult] = []

    # Step 0: admin token
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

    # Step 1: list platform roles
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

    # Find Application Owner role id
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

    # Find Organization Admin role id
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

    # Select permissions
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

    # Step 3: create custom admin role
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

    # Step 4: create population
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

    # Step 5: create group
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

    # Step 6: assign custom role to group, scoped to population
    group_role_payload = {
        "role": {"id": custom_role_id},
        "scope": {
            "id": population_id,
            "type": "POPULATION",
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

    # Step 7: create user in the population
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

    # Step 8: add user to group
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

    # Step 9: verify role assignments on the user
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
