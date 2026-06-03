// Package main demonstrates the PingOne custom admin role workflow.
//
// PingOne ships with a fixed set of platform (built-in) roles such as
// "Organization Admin" and "Application Owner". These roles grant broad
// access and cannot be modified. Custom admin roles let you create
// narrower, purpose-built roles — for example, an application manager
// that can read and update apps but is prevented from creating new ones.
//
// This workflow walks through the full lifecycle end-to-end:
//
//  1. Obtain an admin access token (client_credentials grant) using a
//     worker app that holds the Organization Admin platform role. All
//     management API calls require a bearer token; Organization Admin
//     is specifically required because creating custom roles and assigning
//     them to groups and users is a privileged operation.
//
//  2. List platform roles (GET /roles) to obtain the numeric IDs of the
//     "Application Owner" and "Organization Admin" platform roles. These
//     IDs are used as references in later steps — Application Owner shows
//     which permission IDs are available, and Organization Admin is
//     referenced in the canBeAssignedBy field of the new custom role.
//
//  3. Select a subset of Application Owner permissions. PingOne admin-role
//     permission IDs use the format service:action:resource (for example,
//     "applications:read:application"). We pick only read + update,
//     intentionally omitting "applications:create:application" so that
//     holders of the custom role cannot add new applications.
//
//  4. Create the custom admin role (POST /environments/{envID}/roles).
//     Two fields here deserve special attention:
//       - applicableTo: declares whether the role can be scoped to an
//         ENVIRONMENT, a POPULATION, or both. Scoping to POPULATION lets
//         an administrator restrict the role to a subset of users.
//       - canBeAssignedBy: lists which platform roles are allowed to
//         delegate this custom role. If this array is empty or omitted,
//         even an Organization Admin cannot assign the custom role to
//         anyone — the role exists but is permanently unassignable.
//
//  5. Create a population and a group. The population will be the scope
//     boundary — users inside it can be managed by whoever holds the
//     custom role. The group is the role-assignment vehicle: assigning a
//     role to a group propagates the role to every member automatically.
//
//  6. Assign the custom role to the group, scoped to the population
//     (POST /environments/{envID}/groups/{groupID}/roleAssignments).
//     PingOne has no separate "assign group to population" API; the
//     scope is expressed on the role assignment itself via scope.type=POPULATION.
//
//  7. Create a user in the population and add them to the group. The user
//     inherits the custom role through group membership.
//
//  8. Verify: fetch the user's role assignments and confirm the custom
//     role ID appears in the response. Role propagation via groups is
//     usually immediate but may take a moment on heavily loaded tenants.
//
// Prerequisites:
//   - A PingOne worker app (client_credentials) with the Organization Admin
//     platform role assigned. The admin environment is typically the one
//     that contains the worker app; the target environment is where the
//     custom role and users are created (they can be the same environment).
//   - PINGONE_ADMIN_ENV_ID, PINGONE_ADMIN_CLIENT_ID, PINGONE_ADMIN_CLIENT_SECRET,
//     PINGONE_TARGET_ENV_ID, PINGONE_AUTH_PATH, and PINGONE_API_PATH must all
//     be set (via .env or the system environment).
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

//go:embed logo.png
var logoPNG []byte

var (
	// adminEnvID is the environment that contains the worker app used to obtain
	// the admin bearer token. This is often the "Administrators" environment in
	// your PingOne organisation.
	adminEnvID string
	// adminClientID / adminClientSecret are the credentials of the worker app
	// that holds the Organization Admin role. The client_credentials grant is
	// used because this is a server-to-server call with no interactive login.
	adminClientID     string
	adminClientSecret string
	// targetEnvID is the environment where the custom role, population, group,
	// and user are created. It may be the same as adminEnvID or a separate
	// development/staging environment.
	targetEnvID string
	// authPath is the base URL for the PingOne authentication API, e.g.
	// https://auth.pingone.com (North America) or https://auth.pingone.eu (Europe).
	authPath string
	// apiPath is the base URL for the PingOne management API, e.g.
	// https://api.pingone.com/v1.
	apiPath string
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Falling back to system environment variables.")
	}

	adminEnvID = os.Getenv("PINGONE_ADMIN_ENV_ID")
	adminClientID = os.Getenv("PINGONE_ADMIN_CLIENT_ID")
	adminClientSecret = os.Getenv("PINGONE_ADMIN_CLIENT_SECRET")
	targetEnvID = os.Getenv("PINGONE_TARGET_ENV_ID")
	authPath = strings.TrimRight(os.Getenv("PINGONE_AUTH_PATH"), "/")
	apiPath = strings.TrimRight(os.Getenv("PINGONE_API_PATH"), "/")

	if adminEnvID == "" || adminClientID == "" || adminClientSecret == "" || targetEnvID == "" || authPath == "" || apiPath == "" {
		log.Fatal("Missing required environment variables. Please check your .env file.")
	}

	http.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(logoPNG)
	})
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/run", handleRun)

	fmt.Println("Custom Admin Role workflow on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

// --- HTML ---

const indexHTML = `
<!DOCTYPE html>
<html>
<head>
<title>PingOne Custom Admin Role Workflow</title>
<style>
  body{font-family:sans-serif; margin:0; background:#f5f5f5;}
  button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;}
  button:hover{background:#b8002f;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word;}
  .step{margin-top:18px;}
  .step h3{margin:0 0 6px 0;}
  .ok{color:#0a7a0a;}
  .err{color:#b00020;}
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
  <h2>Custom Admin Role Workflow</h2>
  <p>Creates a trimmed-down application admin role, assigns it to a group scoped to a population, registers a user into that population, and verifies the inherited role assignment.</p>
  <form action="/run" method="POST"><button type="submit">Run Workflow</button></form>
</div>
</body>
</html>`

const resultsHTML = `
<!DOCTYPE html>
<html>
<head>
<title>Workflow Result</title>
<style>
  body{font-family:sans-serif; margin:0; background:#f5f5f5;}
  button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;}
  button:hover{background:#b8002f;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word; margin:0;}
  .step{margin-top:18px; padding:14px 16px; border:1px solid #ddd; border-radius:4px; background:#fff;}
  .step h3{margin:0 0 6px 0;}
  .ok{color:#0a7a0a;}
  .err{color:#b00020;}
  .banner{padding:10px; margin-top:10px; border-radius:4px;}
  .banner.ok{background:#e6f7e6;}
  .banner.err{background:#fde8ea;}
  .url{font-family:monospace; font-size:13px; color:#555; background:#f0f0f0; padding:4px 8px; border-radius:3px; display:inline-block; margin-bottom:6px; word-break:break-all;}
  details{margin-top:6px;}
  summary{cursor:pointer; font-size:13px; color:#444; user-select:none; padding:2px 0;}
  details pre{margin-top:4px;}
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
  <h2>Workflow Result</h2>
  {{if .Success}}<div class="banner ok">All steps completed successfully.</div>{{else}}<div class="banner err">Workflow halted on error.</div>{{end}}
  {{range .Steps}}
    <div class="step">
      <h3 class="{{if .OK}}ok{{else}}err{{end}}">{{.Title}} {{if .OK}}(ok){{else}}(failed){{end}}</h3>
      {{if .URL}}<div class="url">{{.URL}}</div>{{end}}
      {{if .Detail}}<p>{{.Detail}}</p>{{end}}
      {{if .Body}}{{if .Collapsed}}<details><summary>Response</summary><pre>{{.Body}}</pre></details>{{else}}<details open><summary>Response</summary><pre>{{.Body}}</pre></details>{{end}}{{end}}
    </div>
  {{end}}
  <p><a href="/">Back</a></p>
</div>
</body>
</html>`

// --- HTTP handlers ---

// stepResult represents the outcome of a single workflow step for display in
// the results page.
//
//   - Title: human-readable step name shown as the card heading.
//   - OK: true when the step succeeded; false renders the heading in red.
//   - Detail: one-line summary (e.g. "HTTP 201 — id=abc123").
//   - Body: pretty-printed JSON response body; rendered inside a <details>
//     element so the user can expand/collapse it.
//   - URL: the full "METHOD https://..." request URL shown as a monospace
//     badge beneath the heading — useful for cross-referencing against
//     the PingOne API docs or Postman.
//   - Collapsed: when true, the response <details> starts closed; used for
//     verbose responses (e.g. the full platform-roles list) that are only
//     needed for debugging.
type stepResult struct {
	Title     string
	OK        bool
	Detail    string
	Body      string
	URL       string
	Collapsed bool
}

// pageData is the data model passed to the Go html/template when rendering the
// results page. html/template auto-escapes all string values, so Body and Detail
// are safe to render even if they contain angle brackets from JSON responses.
type pageData struct {
	Success bool
	Steps   []stepResult
}

func handleIndex(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, indexHTML)
}

func handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data := runWorkflow()
	tmpl, err := template.New("results").Parse(resultsHTML)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tmpl.Execute(w, data)
}

// --- PingOne API helpers ---

// getAdminToken obtains a short-lived bearer token from the PingOne token
// endpoint using the OAuth 2.0 client_credentials grant.
//
// client_credentials is the correct grant type for server-to-server calls
// where no end-user is involved — the worker app authenticates directly with
// its client_id and client_secret. The resulting token inherits the platform
// roles assigned to the worker app in PingOne (in this case Organization Admin).
//
// Authentication uses HTTP Basic: the client_id and client_secret are
// base64-encoded as "client_id:client_secret" in the Authorization header.
// This is the CLIENT_SECRET_BASIC token endpoint auth method in PingOne.
func getAdminToken() (string, error) {
	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/as/token", authPath, adminEnvID), strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(adminClientID, adminClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var j map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&j)
	token, ok := j["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access_token: %v", j)
	}
	return token, nil
}

// apiCall issues a JSON request to the PingOne management API authenticated
// with the admin bearer token.
//
// Returns (fullURL, httpStatus, rawBody, parsedJSON, error).
// rawBody is always populated so the caller can display it verbatim;
// parsedJSON is populated only when the response is valid JSON — callers
// should never assume it is non-nil on a successful status code.
func apiCall(method, path, token string, payload interface{}) (string, int, []byte, map[string]interface{}, error) {
	fullURL := apiPath + path
	var bodyReader io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		bodyReader = bytes.NewBuffer(b)
	}
	req, _ := http.NewRequest(method, fullURL, bodyReader)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fullURL, 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var parsed map[string]interface{}
	_ = json.Unmarshal(raw, &parsed)
	return fullURL, resp.StatusCode, raw, parsed, nil
}

// pretty returns indented JSON for display in the results page.
// If the bytes are not valid JSON (e.g. a plain-text error body from the API)
// the raw string is returned unchanged so the developer still sees the response.
func pretty(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// --- Workflow ---

// runWorkflow executes the full custom admin role lifecycle and returns a
// pageData value containing one stepResult per API call. Each step is
// self-contained: on failure the function returns immediately so the results
// page clearly highlights exactly which step failed and why.
func runWorkflow() pageData {
	steps := []stepResult{}

	// Step 0: obtain a bearer token from the PingOne token endpoint.
	// We use the client_credentials grant because this is a server-to-server
	// admin operation — no user is logging in. The worker app must hold the
	// Organization Admin platform role; without it, subsequent calls to create
	// custom roles or assign them will return 403 Forbidden.
	token, err := getAdminToken()
	if err != nil {
		steps = append(steps, stepResult{Title: "Obtain admin access token", OK: false, Detail: err.Error()})
		return pageData{Success: false, Steps: steps}
	}
	steps = append(steps, stepResult{Title: "Obtain admin access token", OK: true, Detail: "client_credentials grant succeeded."})

	// Step 1: GET /roles — list all platform (built-in) roles.
	// Platform roles are global and read-only; they cannot be created or deleted
	// through the API. We fetch them here to obtain the IDs of two specific roles:
	//   - "Application Owner": so we can reference its permission IDs when
	//     building the custom role's permission set.
	//   - "Organization Admin": so we can add it to canBeAssignedBy, which
	//     authorises Organisation Admin holders to delegate the custom role.
	// The response is collapsed in the UI because the full role list is long.
	reqURL, status, raw, parsed, err := apiCall("GET", "/roles", token, nil)
	step1 := stepResult{Title: "List platform roles", Body: pretty(raw), URL: "GET " + reqURL, Collapsed: true}
	if err != nil || status >= 400 {
		step1.Detail = fmt.Sprintf("HTTP %d", status)
		if err != nil {
			step1.Detail = err.Error()
		}
		steps = append(steps, step1)
		return pageData{Success: false, Steps: steps}
	}
	step1.OK = true
	step1.Detail = fmt.Sprintf("HTTP %d", status)
	steps = append(steps, step1)

	rolesURL := "GET " + reqURL

	// Locate the Application Owner platform role by name.
	// We use its ID only for display; the permission IDs we copy are well-known
	// string constants (service:action:resource format) that do not require the
	// role ID itself.
	appOwnerID, appOwnerName := findRoleID(parsed, "Application Owner")
	if appOwnerID == "" {
		steps = append(steps, stepResult{Title: "Find Application Owner platform role", OK: false, Detail: "Could not find an 'Application Owner' role in this tenant.", URL: rolesURL})
		return pageData{Success: false, Steps: steps}
	}
	steps = append(steps, stepResult{Title: "Find Application Owner platform role", OK: true, Detail: fmt.Sprintf("Found %q (id=%s) — we'll borrow its application permissions and drop the create permission.", appOwnerName, appOwnerID), URL: rolesURL})

	// Locate the Organization Admin platform role by name.
	// Its ID is required in the canBeAssignedBy field of the custom role we are
	// about to create. canBeAssignedBy controls which actors are permitted to
	// delegate (assign) the custom role. If this array is left empty or omitted,
	// no one — not even an Organization Admin — can ever assign the custom role
	// to a user or group. The role would exist but be permanently unusable.
	orgAdminID, _ := findRoleID(parsed, "Organization Admin")
	if orgAdminID == "" {
		steps = append(steps, stepResult{Title: "Find Organization Admin platform role", OK: false, Detail: "Could not find an 'Organization Admin' role — cannot grant delegation authority.", URL: rolesURL})
		return pageData{Success: false, Steps: steps}
	}
	steps = append(steps, stepResult{Title: "Find Organization Admin platform role", OK: true, Detail: fmt.Sprintf("Found (id=%s) — will add to canBeAssignedBy on the custom role.", orgAdminID), URL: rolesURL})

	// Step 2: Choose the permission IDs to include in the custom role.
	// PingOne admin-role permission IDs use the format service:action:resource,
	// for example "applications:read:application". We select read + update
	// and intentionally omit "applications:create:application" so the role
	// cannot be used to add new applications — only to view and edit existing ones.
	selected := []map[string]string{
		{"id": "applications:read:application"},
		{"id": "applications:update:application"},
	}
	selectedSummary, _ := json.MarshalIndent(selected, "", "  ")
	steps = append(steps, stepResult{Title: "Select read/update application permissions", OK: true, Detail: "Using applications:read:application + applications:update:application (dropping create).", Body: string(selectedSummary), URL: rolesURL})

	// Step 3: create the custom admin role.
	// Custom roles live under a specific environment: POST /environments/{envID}/roles.
	// Note that GET /roles (used above) returns only read-only platform roles;
	// the custom roles endpoint is scoped to an environment.
	//
	// Key payload fields:
	//   - applicableTo: ["ENVIRONMENT", "POPULATION"] means the role can be
	//     assigned at environment scope (affects all populations) or narrowed
	//     to a single population. We include both so callers can choose.
	//   - canBeAssignedBy: references the Organization Admin role ID. Without
	//     this, the role is created successfully but cannot be assigned to anyone.
	roleSuffix := time.Now().Unix()
	_ = appOwnerID // retained for display in the prior step; not needed in this payload
	customRolePayload := map[string]interface{}{
		"name":            fmt.Sprintf("App Manager (Read/Update) %d", roleSuffix),
		"description":     "Trimmed-down Application Owner: can read and update applications but cannot create them.",
		"applicableTo":    []string{"ENVIRONMENT", "POPULATION"},
		"permissions":     selected,
		"canBeAssignedBy": []map[string]string{{"id": orgAdminID}},
	}
	reqURL, status, raw, parsed, err = apiCall("POST", "/environments/"+targetEnvID+"/roles", token, customRolePayload)
	step3 := stepResult{Title: "Create custom admin role", Body: pretty(raw), Detail: fmt.Sprintf("HTTP %d", status), URL: "POST " + reqURL}
	if err != nil || status >= 400 {
		if err != nil {
			step3.Detail = err.Error()
		}
		steps = append(steps, step3)
		return pageData{Success: false, Steps: steps}
	}
	customRoleID, _ := parsed["id"].(string)
	if customRoleID == "" {
		step3.Detail = "Role created but response contained no id."
		steps = append(steps, step3)
		return pageData{Success: false, Steps: steps}
	}
	step3.OK = true
	step3.Detail = fmt.Sprintf("HTTP %d — custom role id=%s", status, customRoleID)
	steps = append(steps, step3)

	// Step 4: create a population in the target environment.
	// A population is a logical container for users. We create one here so the
	// role assignment in step 6 can be scoped to it — users in this population
	// will be managed under the custom role, while users in other populations
	// are unaffected.
	popPayload := map[string]interface{}{
		"name":        fmt.Sprintf("App Management Scope %d", roleSuffix),
		"description": "Population that scopes the trimmed-down App Manager role.",
	}
	reqURL, status, raw, parsed, err = apiCall("POST", "/environments/"+targetEnvID+"/populations", token, popPayload)
	step4 := stepResult{Title: "Create population", Body: pretty(raw), Detail: fmt.Sprintf("HTTP %d", status), URL: "POST " + reqURL}
	if err != nil || status >= 400 {
		if err != nil {
			step4.Detail = err.Error()
		}
		steps = append(steps, step4)
		return pageData{Success: false, Steps: steps}
	}
	populationID, _ := parsed["id"].(string)
	if populationID == "" {
		step4.Detail = "Population created but response contained no id."
		steps = append(steps, step4)
		return pageData{Success: false, Steps: steps}
	}
	step4.OK = true
	step4.Detail = fmt.Sprintf("HTTP %d — population id=%s", status, populationID)
	steps = append(steps, step4)

	// Step 5: create a group in the target environment.
	// Groups are the recommended way to assign admin roles at scale: assign the
	// role once to the group, then manage membership. Adding or removing a user
	// from the group automatically grants or revokes the role without requiring
	// individual role-assignment API calls.
	groupPayload := map[string]interface{}{
		"name":        fmt.Sprintf("App Managers %d", roleSuffix),
		"description": "Group that receives the trimmed-down App Manager role.",
	}
	reqURL, status, raw, parsed, err = apiCall("POST", "/environments/"+targetEnvID+"/groups", token, groupPayload)
	step5 := stepResult{Title: "Create group", Body: pretty(raw), Detail: fmt.Sprintf("HTTP %d", status), URL: "POST " + reqURL}
	if err != nil || status >= 400 {
		if err != nil {
			step5.Detail = err.Error()
		}
		steps = append(steps, step5)
		return pageData{Success: false, Steps: steps}
	}
	groupID, _ := parsed["id"].(string)
	if groupID == "" {
		step5.Detail = "Group created but response contained no id."
		steps = append(steps, step5)
		return pageData{Success: false, Steps: steps}
	}
	step5.OK = true
	step5.Detail = fmt.Sprintf("HTTP %d — group id=%s", status, groupID)
	steps = append(steps, step5)

	// Step 6: assign the custom role to the group, scoped to the population.
	// PingOne does not have a standalone "assign group to population" concept.
	// Instead, the scope is expressed on the role assignment itself:
	//   scope.id   — the population ID
	//   scope.type — "POPULATION" (must be uppercase)
	// Members of the group will hold the custom role within the specified
	// population boundary only. Users in other populations are unaffected.
	groupRolePayload := map[string]interface{}{
		"role": map[string]string{"id": customRoleID},
		"scope": map[string]string{
			"id":   populationID,
			"type": "POPULATION",
		},
	}
	reqURL, status, raw, parsed, err = apiCall("POST", "/environments/"+targetEnvID+"/groups/"+groupID+"/roleAssignments", token, groupRolePayload)
	step6 := stepResult{Title: "Assign custom role to group, scoped to population", Body: pretty(raw), Detail: fmt.Sprintf("HTTP %d", status), URL: "POST " + reqURL}
	if err != nil || status >= 400 {
		if err != nil {
			step6.Detail = err.Error()
		}
		steps = append(steps, step6)
		return pageData{Success: false, Steps: steps}
	}
	step6.OK = true
	steps = append(steps, step6)

	// Step 7: create a user inside the population.
	// Placing the user in the same population as the role-assignment scope
	// ensures the group membership in step 8 activates the role for this user.
	// The population field in the create-user body is a reference object, not
	// a plain string — PingOne requires the {"id": "..."} wrapper form.
	userPayload := map[string]interface{}{
		"username":   fmt.Sprintf("app-manager-test-%d", roleSuffix),
		"email":      fmt.Sprintf("app-manager-test-%d@example.com", roleSuffix),
		"population": map[string]string{"id": populationID},
		"name": map[string]string{
			"given":  "App",
			"family": "Manager",
		},
	}
	reqURL, status, raw, parsed, err = apiCall("POST", "/environments/"+targetEnvID+"/users", token, userPayload)
	step7 := stepResult{Title: "Register a new user into the population", Body: pretty(raw), Detail: fmt.Sprintf("HTTP %d", status), URL: "POST " + reqURL}
	if err != nil || status >= 400 {
		if err != nil {
			step7.Detail = err.Error()
		}
		steps = append(steps, step7)
		return pageData{Success: false, Steps: steps}
	}
	userID, _ := parsed["id"].(string)
	if userID == "" {
		step7.Detail = "User created but response contained no id."
		steps = append(steps, step7)
		return pageData{Success: false, Steps: steps}
	}
	step7.OK = true
	step7.Detail = fmt.Sprintf("HTTP %d — user id=%s", status, userID)
	steps = append(steps, step7)

	// Step 8: add the user to the group so the role assignment propagates to them.
	// The POST body is just the group ID reference; PingOne looks up the group's
	// role assignments and applies them to this user.
	// PingOne returns 201 Created (with a body) or 204 No Content — both are success.
	reqURL, _, raw, _, err = apiCall("POST", "/environments/"+targetEnvID+"/users/"+userID+"/memberOfGroups", token,
		map[string]string{"id": groupID})
	step8 := stepResult{Title: "Add user to the group", Body: pretty(raw), URL: "POST " + reqURL}
	if err != nil {
		step8.Detail = err.Error()
		steps = append(steps, step8)
		return pageData{Success: false, Steps: steps}
	}
	step8.OK = true
	step8.Detail = "User added to group; role assignment now applies via group membership."
	steps = append(steps, step8)

	// Step 9: verify the user's effective role assignments.
	// GET /users/{userID}/roleAssignments returns both directly-assigned roles
	// and roles inherited through group membership. We do a simple string search
	// for the custom role ID to confirm propagation occurred. If it is absent,
	// the step is marked failed with a note about potential propagation delay —
	// on some tenants, group-based role inheritance can take a few seconds.
	reqURL, status, raw, _, err = apiCall("GET", "/environments/"+targetEnvID+"/users/"+userID+"/roleAssignments", token, nil)
	step9 := stepResult{Title: "Verify user role assignments", Body: pretty(raw), Detail: fmt.Sprintf("HTTP %d", status), URL: "GET " + reqURL}
	if err != nil || status >= 400 {
		if err != nil {
			step9.Detail = err.Error()
		}
		steps = append(steps, step9)
		return pageData{Success: false, Steps: steps}
	}
	if !responseMentionsRole(raw, customRoleID) {
		step9.OK = false
		step9.Detail = fmt.Sprintf("HTTP %d — user does not yet appear to have the custom role; check the raw response below. Role assignments via groups may require a brief propagation delay.", status)
		steps = append(steps, step9)
		return pageData{Success: false, Steps: steps}
	}
	step9.OK = true
	step9.Detail = fmt.Sprintf("HTTP %d — user's role assignments include the custom role (inherited via group).", status)
	steps = append(steps, step9)

	return pageData{Success: true, Steps: steps}
}

// --- helpers ---

// findRoleID searches the _embedded.roles array returned by GET /roles for a
// role whose name matches the given string (case-insensitive). It returns the
// role's ID and canonical name, or empty strings if no match is found.
//
// PingOne paginates role lists using HAL _embedded envelopes. For most tenants
// the default page size is large enough to include all platform roles in a
// single response, so pagination is not handled here.
func findRoleID(parsed map[string]interface{}, name string) (string, string) {
	embedded, _ := parsed["_embedded"].(map[string]interface{})
	roles, _ := embedded["roles"].([]interface{})
	for _, r := range roles {
		role, _ := r.(map[string]interface{})
		if n, _ := role["name"].(string); strings.EqualFold(n, name) {
			id, _ := role["id"].(string)
			return id, n
		}
	}
	return "", ""
}

// responseMentionsRole returns true if the raw API response bytes contain the
// given role ID. This is used to verify that a user's role assignments include
// the custom role after group membership is established.
//
// A plain string-contains check is intentional: the full roleAssignments
// response embeds the role object inside each assignment, so the ID always
// appears as a JSON string value if the role is present.
func responseMentionsRole(raw []byte, roleID string) bool {
	return strings.Contains(string(raw), roleID)
}
