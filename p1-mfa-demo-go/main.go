// Package main implements a PingOne native Flows MFA demo.
//
// Overview of the four-step flow:
//
//  1. GET /as/authorize?response_mode=pi.flow
//     Initialises a PingOne Flow session. Because response_mode=pi.flow is
//     used, PingOne returns a JSON body containing a flow ID rather than
//     redirecting the browser. The flow ID is the correlation handle for all
//     subsequent /flows/{id} calls. PingOne also sets session cookies (ST,
//     ST-NO-SS) in the response — these must be captured and replayed on
//     every later call or PingOne will reject the request.
//
//  2. POST /flows/{flowID}  with Content-Type: application/vnd.pingidentity.usernamePassword.check+json
//     Submits the user's username and password to the active flow. The
//     response status field drives the next step:
//       "COMPLETED"                            — no MFA required, proceed to resume
//       "OTP_REQUIRED" / "DEVICE_SELECTION_REQUIRED" /
//       "MULTI_FACTOR_AUTHENTICATION_REQUIRED" — an OTP has been sent; prompt the user
//
//  3. POST /flows/{flowID}  with Content-Type: application/vnd.pingidentity.otp.check+json
//     (only when MFA is required) Submits the one-time passcode. On success
//     the response status becomes "COMPLETED".
//
//  4. GET /as/resume?flowId={flowID}
//     Signals PingOne that the native flow is complete. PingOne either
//     returns a JSON body with authorizeResponse.code or issues a 302
//     redirect to the registered redirect_uri with ?code= in the query
//     string. Both paths are handled here. The code is then exchanged at
//     POST /as/token for an access token (standard authorization_code grant).
//
// Why two PingOne apps?
//
//   The /flows/{id} API is a management-plane API that requires an admin
//   bearer token — session cookies alone are insufficient. A "worker app"
//   (client_credentials grant) in your PingOne admin environment provides
//   that token. A separate end-user OIDC app drives the actual flow and
//   issues the final tokens to the user.
//
// Prerequisites in PingOne:
//   - An end-user OIDC web app with authorization_code grant, CLIENT_SECRET_BASIC,
//     and an MFA policy that requires email OTP for the target user population.
//   - An admin worker app (client_credentials) with Identity Data Admin or
//     equivalent role, used solely to obtain the management API bearer token.
//   - A test user enrolled with an email MFA device.
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
	// envID / clientID / clientSecret are the end-user OIDC app credentials.
	// They drive the flow and are used only to exchange the final auth code
	// for tokens at POST /as/token.
	envID        string
	clientID     string
	clientSecret string
	authPath     string

	// adminEnvID / adminClientID / adminClientSecret are the worker app
	// credentials used to obtain a management-plane bearer token. PingOne
	// requires a bearer token on every /flows/{id} call in addition to the
	// session cookies — without it the API returns 401 even when cookies are
	// present.
	adminEnvID        string
	adminClientID     string
	adminClientSecret string

	// sessionStore maps a flowID to the in-progress flow session so that the
	// admin bearer token and captured cookies can be retrieved when the user
	// posts their OTP on a second HTTP request. A production app would use
	// Redis or a database; here a plain map is sufficient for a single-process
	// demo.
	sessionStore = make(map[string]*flowSession)
)

// flowSession holds the server-side state for one in-progress PingOne flow.
//
// adminToken — the management-plane bearer token from the worker app. It
// must be sent as "Authorization: Bearer <token>" on every POST to
// /flows/{id}. Tokens are short-lived (typically 1 hour); for simplicity
// this demo fetches a fresh token at the start of each login attempt.
//
// cookies — the raw Set-Cookie values captured from PingOne responses
// (primarily ST and ST-NO-SS). PingOne binds the flow execution context to
// these cookies, so they must be replayed verbatim on every subsequent
// request. Using a standard http.CookieJar is unreliable here because RFC
// 6265 path scoping silently drops cookies whose Path attribute does not
// match the request path. Manual capture-and-replay is the safe approach.
type flowSession struct {
	adminToken string
	cookies    []*http.Cookie
}

// capture merges Set-Cookie values from a PingOne response into the session.
// If a cookie with the same name is already present it is replaced (PingOne
// may issue updated ST values across flow steps), otherwise the cookie is
// appended.
func (s *flowSession) capture(resp *http.Response) {
	for _, cookie := range resp.Cookies() {
		updated := false
		for i, c := range s.cookies {
			if c.Name == cookie.Name {
				s.cookies[i] = cookie
				updated = true
				break
			}
		}
		if !updated {
			s.cookies = append(s.cookies, cookie)
		}
	}
}

// applyFlow sets the admin Bearer token and all captured session cookies on
// a request destined for the /flows/ API. Both are required on every call:
//   - Authorization: Bearer <adminToken> — authorises the management-plane call
//   - Cookie: ST=...; ST-NO-SS=... — ties the request to the active flow session
//
// Omitting either header results in a 401 from PingOne even if the other is
// present.
func (s *flowSession) applyFlow(req *http.Request) {
	if s.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.adminToken)
	}
	for _, cookie := range s.cookies {
		req.AddCookie(cookie)
	}
}

// noRedirectClient returns an HTTP client that does not follow redirects.
// PingOne's /as/resume endpoint returns either a JSON body or a 302 redirect
// depending on the flow configuration. The standard Go HTTP client would
// silently follow the redirect and lose the Location header. By returning
// http.ErrUseLastResponse we get the 302 response back intact and can
// extract the authorization code from the Location URL ourselves.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// getAdminToken fetches a short-lived access token from the admin worker
// app using the OAuth 2.0 client_credentials grant.
//
// The admin worker app lives in a separate PingOne environment (the
// "admin environment") from the end-user app. This is a common pattern when
// the admin environment is shared across many target environments and the
// worker app is granted a cross-environment role assignment. The token
// returned here is used on all /flows/{id} management API calls.
func getAdminToken() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/%s/as/token", authPath, adminEnvID),
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// CLIENT_SECRET_BASIC: client_id and client_secret base64-encoded in the
	// Authorization header. This is the most widely supported authentication
	// method for machine-to-machine token requests.
	req.SetBasicAuth(adminClientID, adminClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access_token in response: %v", result)
	}
	return token, nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Falling back to system environment variables.")
	}

	envID = os.Getenv("PINGONE_ENV_ID")
	clientID = os.Getenv("PINGONE_CLIENT_ID")
	clientSecret = os.Getenv("PINGONE_CLIENT_SECRET")
	authPath = strings.TrimRight(os.Getenv("PINGONE_AUTH_PATH"), "/")

	adminEnvID = os.Getenv("PINGONE_ADMIN_ENV_ID")
	adminClientID = os.Getenv("PINGONE_ADMIN_CLIENT_ID")
	adminClientSecret = os.Getenv("PINGONE_ADMIN_CLIENT_SECRET")

	if envID == "" || clientID == "" || authPath == "" || clientSecret == "" {
		log.Fatal("Missing required environment variables. Please check your .env file.")
	}
	if adminEnvID == "" || adminClientID == "" || adminClientSecret == "" {
		log.Fatal("Missing admin worker app credentials (PINGONE_ADMIN_ENV_ID, PINGONE_ADMIN_CLIENT_ID, PINGONE_ADMIN_CLIENT_SECRET).")
	}

	// Verify the admin credentials are valid before accepting traffic. If the
	// worker app's client_id / secret are wrong, every subsequent flow call
	// will fail with a 401, which surfaces as a confusing mid-login error.
	// Failing fast at startup gives a clear error message immediately.
	if _, err := getAdminToken(); err != nil {
		log.Fatalf("Failed to get admin token at startup: %v", err)
	}
	log.Println("Admin token smoke-test passed.")

	http.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(logoPNG)
	})
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/mfa-verify", handleMFAVerify)

	fmt.Println("MFA Demo starting on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

// --- HTML Templates ---

const indexHTML = `
<!DOCTYPE html>
<html>
<head><title>Login</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;} button:hover{background:#b8002f;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
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
</html>`

const mfaHTML = `
<!DOCTYPE html>
<html>
<head><title>MFA Required</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;} button:hover{background:#b8002f;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2>Two-Factor Authentication</h2>
    <p>Please enter the verification code sent to your email.</p>
    <form action="/mfa-verify" method="POST">
        <input type="hidden" name="flowId" value="{{.FlowID}}">
        <label>MFA Code:</label><br>
        <input type="text" name="otp" required><br><br>
        <button type="submit">Verify</button>
    </form>
</div>
</body>
</html>`

const dashboardHTML = `
<!DOCTYPE html>
<html>
<head><title>Dashboard</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2 style="color:#0a7a0a;">Login Successful!</h2>
    <p>You have securely authenticated. Here is your Access Token:</p>
    <pre>{{.Token}}</pre>
    <a href="/">Log Out</a>
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
    <h2 style="color:#b00020;">Authentication Error</h2>
    <pre>{{.Error}}</pre>
    <a href="/">Try Again</a>
</div>
</body>
</html>`

// --- HTTP Handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, indexHTML)
}

// handleLogin drives steps 1 and 2 of the flow: initialise the PingOne Flow
// session and submit the user's credentials. Depending on the flow status
// returned by PingOne it either:
//   - Renders the MFA page (OTP_REQUIRED, DEVICE_SELECTION_REQUIRED, or
//     MULTI_FACTOR_AUTHENTICATION_REQUIRED) and stores the session keyed by
//     flowID so it can be retrieved when the OTP arrives.
//   - Calls completeLoginAndRender directly if the flow status is already
//     COMPLETED (no MFA policy applies to this user).
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// Fetch a fresh admin token for this login attempt. The token is kept in
	// the flowSession so it can be reused for the OTP check in handleMFAVerify.
	adminToken, err := getAdminToken()
	if err != nil {
		renderError(w, "Failed to get admin token: "+err.Error())
		return
	}

	client := noRedirectClient()
	session := &flowSession{adminToken: adminToken}

	// Step 1: Initialise the PingOne Flow session.
	//
	// response_mode=pi.flow instructs PingOne to return the initial flow state
	// as JSON instead of issuing a browser redirect. The response body contains
	// an "id" field — the flow ID used on all subsequent /flows/{id} calls.
	//
	// Accept: */* is required because PingOne may return a vendor content type
	// (application/vnd.pingidentity.*+json). Sending Accept: application/json
	// alone causes a 406 Not Acceptable on some flow configurations.
	authURL := fmt.Sprintf(
		"%s/%s/as/authorize?response_type=code&client_id=%s&redirect_uri=http://localhost:3000/callback&scope=openid%%20profile&response_mode=pi.flow",
		authPath, envID, clientID,
	)
	reqInit, _ := http.NewRequest("GET", authURL, nil)
	reqInit.Header.Set("Accept", "*/*")

	resp, err := client.Do(reqInit)
	if err != nil {
		renderError(w, "Failed to initialize flow: "+err.Error())
		return
	}
	defer resp.Body.Close()
	// Capture any cookies PingOne sets on the authorize response. These are
	// typically ST and ST-NO-SS and must accompany every later /flows/ call.
	session.capture(resp)

	var flowData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&flowData)
	flowID, _ := flowData["id"].(string)
	log.Printf("[login] authorize flowID: %s", flowID)

	// Step 2: Submit the username and password to the active flow.
	//
	// The Content-Type is a PingOne vendor type that tells the flow engine
	// which action to perform. Using application/json here would result in a
	// 415 Unsupported Media Type.
	//
	// Both the admin Bearer token and the session cookies from step 1 must be
	// present — see applyFlow for details.
	payloadBytes, _ := json.Marshal(map[string]string{"username": username, "password": password})
	reqLogin, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/flows/%s", authPath, envID, flowID), bytes.NewBuffer(payloadBytes))
	reqLogin.Header.Set("Content-Type", "application/vnd.pingidentity.usernamePassword.check+json")
	reqLogin.Header.Set("Accept", "*/*")
	session.applyFlow(reqLogin)

	loginResp, err := client.Do(reqLogin)
	if err != nil {
		renderError(w, "Failed to submit credentials: "+err.Error())
		return
	}
	defer loginResp.Body.Close()
	session.capture(loginResp)

	var loginResult map[string]interface{}
	json.NewDecoder(loginResp.Body).Decode(&loginResult)
	log.Printf("[login] credentials result status=%v id=%v", loginResult["status"], loginResult["id"])

	// PingOne may return an updated flow ID after the credential check (for
	// example when the flow transitions to a new state). Always use the latest
	// ID so subsequent calls target the correct flow state.
	if newID, ok := loginResult["id"].(string); ok && newID != "" {
		flowID = newID
	}
	status, _ := loginResult["status"].(string)

	// Persist the session under the current flowID so handleMFAVerify can
	// retrieve the admin token and cookies when the OTP arrives.
	sessionStore[flowID] = session

	// Route based on the flow status returned by PingOne:
	//   COMPLETED — credentials were accepted and no MFA is required for this
	//               user (or no MFA policy is assigned). Proceed directly to
	//               the resume/token exchange step.
	//   OTP_REQUIRED / DEVICE_SELECTION_REQUIRED /
	//   MULTI_FACTOR_AUTHENTICATION_REQUIRED — PingOne has sent an OTP to the
	//               user's registered device. Show the MFA form and wait.
	if status == "COMPLETED" {
		completeLoginAndRender(w, flowID, session, client)
		return
	}
	if status == "OTP_REQUIRED" || status == "DEVICE_SELECTION_REQUIRED" || status == "MULTI_FACTOR_AUTHENTICATION_REQUIRED" {
		tmpl, _ := template.New("mfa").Parse(mfaHTML)
		tmpl.Execute(w, struct{ FlowID string }{FlowID: flowID})
		return
	}

	renderError(w, fmt.Sprintf("Unexpected login status: %v", loginResult))
}

// handleMFAVerify drives step 3 of the flow: submit the OTP to PingOne and,
// on success, advance to the resume/token exchange step.
//
// The flowID posted by the MFA form is used to look up the in-progress
// flowSession, which carries the admin bearer token and cookies needed to
// authenticate the /flows/{id} call.
func handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	flowID := strings.TrimSpace(r.FormValue("flowId"))
	otp := strings.TrimSpace(r.FormValue("otp"))

	session, ok := sessionStore[flowID]
	if !ok {
		renderError(w, "Session expired or lost. Please try logging in again.")
		return
	}

	client := noRedirectClient()

	// Step 3: Submit the OTP to the active flow.
	//
	// The vendor Content-Type application/vnd.pingidentity.otp.check+json
	// tells the flow engine to validate the OTP against the user's enrolled
	// MFA device. The same Accept: */* and dual-auth (Bearer + cookies) rules
	// that applied to the credential check apply here as well.
	payloadBytes, _ := json.Marshal(map[string]string{"otp": otp})
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/flows/%s", authPath, envID, flowID), bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/vnd.pingidentity.otp.check+json")
	req.Header.Set("Accept", "*/*")
	session.applyFlow(req)

	log.Printf("[mfa] sending OTP check, flowID=%s", flowID)

	mfaResp, err := client.Do(req)
	if err != nil {
		renderError(w, "Failed to submit MFA code: "+err.Error())
		return
	}
	defer mfaResp.Body.Close()
	session.capture(mfaResp)

	var mfaResult map[string]interface{}
	json.NewDecoder(mfaResp.Body).Decode(&mfaResult)
	log.Printf("[mfa] result: %v", mfaResult)

	// PingOne may issue a new flow ID after the OTP check. Update the session
	// store so any future requests (e.g. a retry) use the latest ID.
	if newID, ok := mfaResult["id"].(string); ok && newID != "" && newID != flowID {
		sessionStore[newID] = session
		delete(sessionStore, flowID)
		flowID = newID
	}

	if status, _ := mfaResult["status"].(string); status == "COMPLETED" {
		// OTP validated — clean up the session entry and proceed to exchange
		// the completed flow for an authorization code and then tokens.
		delete(sessionStore, flowID)
		completeLoginAndRender(w, flowID, session, client)
		return
	}

	renderError(w, fmt.Sprintf("MFA Failed. Response: %v", mfaResult))
}

// --- Helper Functions ---

// completeLoginAndRender drives step 4: call GET /as/resume?flowId={id} to
// signal PingOne that the native flow is complete, extract the resulting
// authorization code, and exchange it for tokens.
//
// The /as/resume endpoint behaves differently depending on the OIDC app
// configuration:
//   - If the app's redirect_uri handling is server-side, PingOne may return
//     a JSON body containing authorizeResponse.code.
//   - More commonly, PingOne issues a 302 redirect to the registered
//     redirect_uri with ?code=<value> appended. The no-redirect HTTP client
//     is used so the Location header is returned to this code rather than
//     followed automatically.
//
// Only the session cookies are required on the resume call — no admin bearer
// token is needed because /as/resume is part of the OAuth 2.0 authorization
// endpoint, not the management API.
func completeLoginAndRender(w http.ResponseWriter, flowID string, session *flowSession, client *http.Client) {
	reqResume, _ := http.NewRequest("GET", fmt.Sprintf("%s/%s/as/resume?flowId=%s", authPath, envID, flowID), nil)
	reqResume.Header.Set("Accept", "*/*")
	// The ST / ST-NO-SS cookies established during the flow must accompany
	// the resume call so PingOne can locate and complete the session. The
	// admin bearer token is NOT sent here — /as/resume is an authorization
	// endpoint, not the management plane.
	for _, cookie := range session.cookies {
		reqResume.AddCookie(cookie)
	}

	resumeResp, err := client.Do(reqResume)
	if err != nil {
		renderError(w, "Failed to call resume: "+err.Error())
		return
	}
	defer resumeResp.Body.Close()
	session.capture(resumeResp)

	log.Printf("[resume] status code: %d", resumeResp.StatusCode)

	var resumeResult map[string]interface{}
	json.NewDecoder(resumeResp.Body).Decode(&resumeResult)
	log.Printf("[resume] result: %v", resumeResult)

	// Extract the authorization code. Try the JSON body first; fall back to
	// the Location header's query string if PingOne issued a redirect instead.
	authCode := ""
	if authResp, ok := resumeResult["authorizeResponse"].(map[string]interface{}); ok {
		authCode, _ = authResp["code"].(string)
	}
	if authCode == "" {
		if loc := resumeResp.Header.Get("Location"); loc != "" {
			if u, err := url.Parse(loc); err == nil {
				authCode = u.Query().Get("code")
			}
		}
	}

	if authCode == "" {
		renderError(w, fmt.Sprintf("Failed to get authorization code. Response: %v", resumeResult))
		return
	}

	// Step 4b: Exchange the authorization code for tokens at the standard
	// PingOne token endpoint (authorization_code grant). This call uses the
	// end-user OIDC app's client_id and client_secret via HTTP Basic auth.
	//
	// The redirect_uri must exactly match what was sent in the authorize
	// request and what is registered on the app — PingOne validates all three
	// must agree before issuing tokens.
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("redirect_uri", "http://localhost:3000/callback")

	reqToken, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/as/token", authPath, envID), strings.NewReader(data.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqToken.SetBasicAuth(clientID, clientSecret)

	tokenResp, err := client.Do(reqToken)
	if err != nil {
		renderError(w, "Failed to get token: "+err.Error())
		return
	}
	defer tokenResp.Body.Close()

	bodyBytes, _ := io.ReadAll(tokenResp.Body)
	var tokenResult map[string]interface{}
	json.Unmarshal(bodyBytes, &tokenResult)

	accessToken, ok := tokenResult["access_token"].(string)
	if !ok {
		renderError(w, fmt.Sprintf("Failed to parse access token. Output: %s", string(bodyBytes)))
		return
	}

	tmpl, _ := template.New("dashboard").Parse(dashboardHTML)
	tmpl.Execute(w, struct{ Token string }{Token: accessToken})
}

func renderError(w http.ResponseWriter, errMsg string) {
	tmpl, _ := template.New("error").Parse(errorHTML)
	tmpl.Execute(w, struct{ Error string }{Error: errMsg})
}
