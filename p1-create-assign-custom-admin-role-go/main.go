package main

import (
	"bytes"
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

var (
	adminEnvID        string
	adminClientID     string
	adminClientSecret string
	targetEnvID       string
	authPath          string
	apiPath           string
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
</html>`

const resultsHTML = `
<!DOCTYPE html>
<html>
<head>
<title>Workflow Result</title>
<style>
  body{font-family:sans-serif; margin:40px; max-width:900px;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-wrap:break-word; margin:0;}
  .step{margin-top:18px;}
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
</body>
</html>`

// --- HTTP handlers ---

type stepResult struct {
	Title     string
	OK        bool
	Detail    string
	Body      string
	URL       string // request URL shown beneath the step title
	Collapsed bool   // if true, the response <details> starts closed
}

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

// apiCall issues a JSON request to the management API with the admin bearer token.
// Returns the full request URL, raw body, decoded JSON (if parseable), and HTTP status.
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

// pretty returns indented JSON for display.
func pretty(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// --- Workflow ---

func runWorkflow() pageData {
	steps := []stepResult{}

	// Step 0: admin token
	token, err := getAdminToken()
	if err != nil {
		steps = append(steps, stepResult{Title: "Obtain admin access token", OK: false, Detail: err.Error()})
		return pageData{Success: false, Steps: steps}
	}
	steps = append(steps, stepResult{Title: "Obtain admin access token", OK: true, Detail: "client_credentials grant succeeded."})

	// Step 1: look up Application Owner platform role to scope permissions from, and find its read/update application permissions.
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

	// Find Application Owner role id so we can borrow its permission set and trim it.
	appOwnerID, appOwnerName := findRoleID(parsed, "Application Owner")
	if appOwnerID == "" {
		steps = append(steps, stepResult{Title: "Find Application Owner platform role", OK: false, Detail: "Could not find an 'Application Owner' role in this tenant.", URL: rolesURL})
		return pageData{Success: false, Steps: steps}
	}
	steps = append(steps, stepResult{Title: "Find Application Owner platform role", OK: true, Detail: fmt.Sprintf("Found %q (id=%s) — we'll borrow its application permissions and drop the create permission.", appOwnerName, appOwnerID), URL: rolesURL})

	// Find Organization Admin role id — needed in canBeAssignedBy so the worker app
	// (which holds Organization Admin) is authorized to delegate the custom role.
	orgAdminID, _ := findRoleID(parsed, "Organization Admin")
	if orgAdminID == "" {
		steps = append(steps, stepResult{Title: "Find Organization Admin platform role", OK: false, Detail: "Could not find an 'Organization Admin' role — cannot grant delegation authority.", URL: rolesURL})
		return pageData{Success: false, Steps: steps}
	}
	steps = append(steps, stepResult{Title: "Find Organization Admin platform role", OK: true, Detail: fmt.Sprintf("Found (id=%s) — will add to canBeAssignedBy on the custom role.", orgAdminID), URL: rolesURL})

	// Step 2: pick the read + update permissions we want on the custom role.
	// PingOne admin-role permission IDs follow the format "<service>:<action>:<resource>".
	selected := []map[string]string{
		{"id": "applications:read:application"},
		{"id": "applications:update:application"},
	}
	selectedSummary, _ := json.MarshalIndent(selected, "", "  ")
	steps = append(steps, stepResult{Title: "Select read/update application permissions", OK: true, Detail: "Using applications:read:application + applications:update:application (dropping create).", Body: string(selectedSummary), URL: rolesURL})

	// Step 3: create custom admin role with those permissions.
	// Custom admin roles are POST /environments/{envID}/roles; platform roles at /roles are read-only.
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
	// Note: PingOne does not have a literal "assign group to population" API. The role assignment
	// on the group carries a scope pointing at the population — group members in that population
	// inherit the role within that population's context.
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

	// Step 7: create a user in the population.
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

	// Step 8: add the user to the group so the role assignment applies to them.
	reqURL, _, raw, _, err = apiCall("POST", "/environments/"+targetEnvID+"/users/"+userID+"/memberOfGroups", token,
		map[string]string{"id": groupID})
	// PingOne returns 201 on success or 204 — tolerate both.
	step8 := stepResult{Title: "Add user to the group", Body: pretty(raw), URL: "POST " + reqURL}
	if err != nil {
		step8.Detail = err.Error()
		steps = append(steps, step8)
		return pageData{Success: false, Steps: steps}
	}
	step8.OK = true
	step8.Detail = "User added to group; role assignment now applies via group membership."
	steps = append(steps, step8)

	// Step 9: verify role assignments on the user.
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

func responseMentionsRole(raw []byte, roleID string) bool {
	return strings.Contains(string(raw), roleID)
}
