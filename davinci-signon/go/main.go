// Package main implements a DaVinci Sign-On Flow with PingOne Auth.
//
// Overview of the three-step flow:
//
//  1. GET /as/authorize?response_mode=pi.flow
//     Instead of redirecting the browser, PingOne returns a JSON envelope
//     describing the first DaVinci capability the client must drive.
//     The response contains handles (interactionId, interactionToken,
//     connectionId, capabilityName, id) that identify both the live flow
//     session and the specific connector node that is waiting for input.
//
//  2. POST /davinci/connections/{connectionId}/capabilities/{capabilityName}
//     The client submits credentials to the capability URL using the handles
//     from step 1 as request headers (interactionId, interactionToken).
//     The DaVinci flow validates the credentials and — on a simple sign-on
//     flow — returns an authorization code in authorizeResponse.code.
//
//  3. POST /as/token  (standard OAuth 2.0 authorization_code exchange)
//     The authorization code is exchanged for an access token using the
//     OIDC web app's client_id and client_secret (CLIENT_SECRET_BASIC).
//
// Prerequisites in PingOne:
//   - A Web App (OIDC, authorization_code, CLIENT_SECRET_BASIC) with a
//     DaVinci flow policy assignment pointing at a sign-on flow.
//   - The DaVinci flow must use the API integration method (JSON responses).
//   - A test user in the population the flow's PingOne SSO connector targets.
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

	"github.com/joho/godotenv"
)

//go:embed logo.png
var logoPNG []byte

var (
	envID        string
	clientID     string
	clientSecret string
	authPath     string
	redirectURI  string
)

// flowState holds the session handles returned by the authorize endpoint and
// carried forward on every subsequent capability request.
//
// interactionId / interactionToken — DaVinci's correlation handles. They tie
// this HTTP request to the in-progress flow session on the server. Both must
// be sent as request headers on the capability POST; omitting either causes
// PingOne to reject the request with a 401.
//
// connectionId / capabilityName — identify which DaVinci connector node is
// currently waiting for input. The capability URL is built from these two
// values: /davinci/connections/{connectionId}/capabilities/{capabilityName}.
//
// id — the flow instance ID. It is echoed back in the capability request body
// so DaVinci can locate the right execution context server-side.
type flowState struct {
	InteractionID    string
	InteractionToken string
	ConnectionID     string
	CapabilityName   string
	ID               string
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Falling back to system environment variables.")
	}

	envID = os.Getenv("PINGONE_ENV_ID")
	clientID = os.Getenv("PINGONE_CLIENT_ID")
	clientSecret = os.Getenv("PINGONE_CLIENT_SECRET")
	authPath = strings.TrimRight(os.Getenv("PINGONE_AUTH_PATH"), "/")
	redirectURI = os.Getenv("PINGONE_REDIRECT_URI")

	if envID == "" || clientID == "" || clientSecret == "" || authPath == "" || redirectURI == "" {
		log.Fatal("Missing required environment variables. Please check your .env file.")
	}

	// Verify the OIDC app has a DaVinci flow policy assigned before accepting
	// traffic. Without the assignment the authorize endpoint redirects to the
	// default login page instead of returning JSON flow handles, which would
	// surface as a confusing mid-login error rather than a clear startup message.
	if err := checkFlowPolicyAssignment(); err != nil {
		log.Fatalf("Startup check failed: %v", err)
	}

	http.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(logoPNG)
	})
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)

	fmt.Println("DaVinci Sign-On demo starting on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

// --- HTML Templates ---

const indexHTML = `
<!DOCTYPE html>
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
</html>`

const dashboardHTML = `
<!DOCTYPE html>
<html>
<head><title>Signed In</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2 style="color:#0a7a0a;">Sign-On Successful</h2>
    <p>The DaVinci flow returned an authorization code, which was exchanged for an access token:</p>
    <pre>{{.Token}}</pre>
    <a href="/">Sign Out</a>
</div>
</body>
</html>`

const errorHTML = `
<!DOCTYPE html>
<html>
<head><title>Error</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2 style="color:#b00020;">Sign-On Error</h2>
    <pre>{{.Error}}</pre>
    <a href="/">Try Again</a>
</div>
</body>
</html>`

// --- HTTP Handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, indexHTML)
}

// handleLogin orchestrates the full three-step sign-on sequence in response
// to a form POST from the login page. Each step calls a focused helper so the
// sequence reads top-to-bottom as plain English.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// Step 1: Call the PingOne authorize endpoint with response_mode=pi.flow.
	// This does not authenticate the user yet — it initialises a DaVinci flow
	// session and returns the handles needed to drive it.
	state, err := startFlow()
	if err != nil {
		renderError(w, "Failed to start flow: "+err.Error())
		return
	}
	log.Printf("[signon] flow started id=%s capability=%s", state.ID, state.CapabilityName)

	// Step 2: Submit the user's credentials to the capability that DaVinci is
	// waiting on. For a standard sign-on flow this is the PingOne SSO connector's
	// userLookup/password-check node, and a successful response includes an
	// authorization code in authorizeResponse.code.
	authCode, err := submitSignOn(state, username, password)
	if err != nil {
		renderError(w, "Failed to submit credentials: "+err.Error())
		return
	}
	log.Printf("[signon] received authorization code")

	// Step 3: Trade the authorization code for tokens at the standard PingOne
	// token endpoint. This is identical to any other authorization_code exchange.
	token, err := exchangeToken(authCode)
	if err != nil {
		renderError(w, "Failed to exchange token: "+err.Error())
		return
	}

	tmpl, _ := template.New("dashboard").Parse(dashboardHTML)
	tmpl.Execute(w, struct{ Token string }{Token: token})
}

// checkFlowPolicyAssignment probes the authorize endpoint at startup to confirm
// the OIDC app has a DaVinci flow policy assigned.
//
// When response_mode=pi.flow is used with a properly configured app, PingOne
// returns a 200 JSON body containing flow handles. Without a flow policy
// assignment PingOne issues a 302 redirect to its default login page instead,
// which this app cannot handle. Detecting this at startup gives a clear error
// message rather than a cryptic mid-login failure.
func checkFlowPolicyAssignment() error {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid")
	q.Set("response_mode", "pi.flow")

	authURL := fmt.Sprintf("%s/%s/as/authorize?%s", authPath, envID, q.Encode())
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return fmt.Errorf("could not build authorize request: %w", err)
	}
	req.Header.Set("X-Requested-With", "ping-sdk")
	req.Header.Set("Accept", "application/json")

	// Disable redirect-following so a 302 is returned to us rather than
	// silently followed to the login page.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("authorize probe failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		return fmt.Errorf(
			"the authorize endpoint redirected instead of returning a DaVinci flow.\n"+
				"  Your OIDC app likely has no flow policy assignment.\n"+
				"  Fix: assign a DaVinci flow policy to app %q in environment %q.\n"+
				"  See README.md → PingOne configuration for instructions.",
			clientID, envID,
		)
	}

	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil || asString(data["interactionId"]) == "" {
		return fmt.Errorf(
			"the authorize endpoint did not return a DaVinci flow (status %d).\n"+
				"  Check that the OIDC app has a flow policy assignment and that\n"+
				"  PINGONE_CLIENT_ID / PINGONE_ENV_ID / PINGONE_AUTH_PATH are correct.\n"+
				"  Response: %s",
			resp.StatusCode, string(body),
		)
	}

	log.Println("Startup check passed: DaVinci flow policy assignment is present.")
	return nil
}

// startFlow calls GET /as/authorize?response_mode=pi.flow to initialise a
// DaVinci flow session.
//
// response_mode=pi.flow instructs PingOne to return the flow state as a JSON
// body rather than redirecting the browser. The response describes the first
// DaVinci node waiting for client input and contains the session handles
// (interactionId, interactionToken, connectionId, capabilityName, id) needed
// to drive subsequent steps.
func startFlow() (*flowState, error) {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid")
	q.Set("response_mode", "pi.flow")

	authURL := fmt.Sprintf("%s/%s/as/authorize?%s", authPath, envID, q.Encode())
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return nil, err
	}
	// X-Requested-With: ping-sdk tells PingOne this is a programmatic SDK
	// client. Combined with response_mode=pi.flow it ensures the server returns
	// JSON flow handles rather than an HTML login page.
	req.Header.Set("X-Requested-With", "ping-sdk")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("authorize returned %d: %s", resp.StatusCode, string(body))
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("authorize response was not JSON: %w (body: %s)", err, string(body))
	}

	state := &flowState{
		InteractionID:    asString(data["interactionId"]),
		InteractionToken: asString(data["interactionToken"]),
		ConnectionID:     asString(data["connectionId"]),
		CapabilityName:   asString(data["capabilityName"]),
		ID:               asString(data["id"]),
	}
	if state.InteractionID == "" || state.ConnectionID == "" || state.CapabilityName == "" {
		return nil, fmt.Errorf("authorize response missing flow handles: %s", string(body))
	}
	return state, nil
}

// submitSignOn posts credentials to the DaVinci capability URL constructed
// from the flow handles returned in step 1.
//
// The request body shape is the DaVinci runtime envelope:
//   - id: the flow instance ID from startFlow, echoed so DaVinci can match
//     this request to the correct in-progress execution.
//   - eventName: "continue" advances the flow past the current node.
//   - parameters.data.actionKey: "SIGNON" selects the sign-on branch of the
//     PingOne SSO connector (as opposed to "REGISTER" for self-service signup).
//   - parameters.data.formData: the user-supplied field values. For a basic
//     sign-on flow the connector expects "username" and "password".
//
// On success the flow completes and the response contains
// authorizeResponse.code — an authorization code ready for token exchange.
func submitSignOn(state *flowState, username, password string) (string, error) {
	payload := map[string]interface{}{
		"id":        state.ID,
		"eventName": "continue",
		"parameters": map[string]interface{}{
			"eventType": "submit",
			"data": map[string]interface{}{
				"actionKey": "SIGNON",
				"formData": map[string]string{
					"username": username,
					"password": password,
				},
			},
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	// The capability URL encodes which DaVinci connector and node to invoke.
	// connectionId identifies the PingOne SSO connector instance in this flow;
	// capabilityName is the specific action within that connector (e.g. userLookup).
	capURL := fmt.Sprintf("%s/%s/davinci/connections/%s/capabilities/%s",
		authPath, envID, state.ConnectionID, state.CapabilityName)
	req, err := http.NewRequest("POST", capURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "ping-sdk")
	// interactionId and interactionToken are the DaVinci session correlation
	// handles from startFlow. They must be sent as headers (not in the body)
	// on every capability request so DaVinci can locate the live flow session.
	req.Header.Set("interactionId", state.InteractionID)
	req.Header.Set("interactionToken", state.InteractionToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("capability returned %d: %s", resp.StatusCode, string(body))
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("capability response was not JSON: %w (body: %s)", err, string(body))
	}

	// authorizeResponse.code is present only when the DaVinci flow has reached
	// its terminal success node. If it is absent the flow needs another step
	// (e.g. MFA) that this sample does not handle.
	authResp, ok := data["authorizeResponse"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("flow did not return an authorization code (likely needs another step): %s", string(body))
	}
	code := asString(authResp["code"])
	if code == "" {
		return "", fmt.Errorf("authorizeResponse missing code: %s", string(body))
	}
	return code, nil
}

// exchangeToken performs a standard OAuth 2.0 authorization_code token
// exchange at the PingOne token endpoint.
//
// The redirect_uri must exactly match the value sent in the authorize request
// and the one registered on the PingOne app — PingOne validates all three
// match before issuing tokens. Authentication uses HTTP Basic (CLIENT_SECRET_BASIC):
// the client_id and client_secret are base64-encoded in the Authorization header.
func exchangeToken(code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("scope", "openid")

	tokenURL := fmt.Sprintf("%s/%s/as/token", authPath, envID)
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("token response was not JSON: %w (body: %s)", err, string(body))
	}
	token := asString(data["access_token"])
	if token == "" {
		return "", fmt.Errorf("token response missing access_token: %s", string(body))
	}
	return token, nil
}

func renderError(w http.ResponseWriter, msg string) {
	tmpl, _ := template.New("error").Parse(errorHTML)
	tmpl.Execute(w, struct{ Error string }{Error: msg})
}

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
