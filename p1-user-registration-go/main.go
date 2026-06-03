// Package main implements a self-service user registration flow against the
// PingOne native authentication API, followed by a standard sign-on flow that
// lets the newly created user immediately log in.
//
// How registration differs from sign-on
//
// A sign-on flow (see p1-davinci-signon-go) authenticates an existing user and
// ends with an authorization code that can be exchanged for tokens. Registration
// is a pre-authentication step: it creates the user account in PingOne before
// any tokens exist. No admin worker app is needed here because the native
// authentication API accepts registrations from end-user OIDC apps — the same
// app that drives sign-on.
//
// Overview of the registration sub-flow (3 steps):
//
//  1. GET /as/authorize?response_mode=pi.flow
//     Initialises a PingOne authentication session. response_mode=pi.flow makes
//     PingOne return JSON (with a flow ID) instead of redirecting the browser.
//     The response also sets PingOne session cookies that must be replayed on
//     every subsequent request to the same flow.
//
//  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.user.register+json
//     Submits the new user's username, email, and password. PingOne either
//     completes the registration immediately (status=COMPLETED) or — if the
//     environment has email verification enabled — returns
//     status=VERIFICATION_CODE_REQUIRED and sends a 6-digit OTP to the user's
//     email address.
//
//  3. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.user.verify+json
//     (Only when step 2 required verification.) Submits the OTP. On success
//     PingOne returns status=COMPLETED, the account is live, and the flow ends.
//
// Overview of the sign-on sub-flow (4 steps):
//
//  1. GET /as/authorize?response_mode=pi.flow
//     Same as registration step 1 — starts a fresh authentication session.
//
//  2. POST /flows/{flowID}  Content-Type: application/vnd.pingidentity.usernamePassword.check+json
//     Validates the user's credentials against PingOne's directory.
//     A status=COMPLETED response means the flow considers the user authenticated.
//
//  3. GET /as/resume?flowId={flowID}
//     Bridges the native flow back to the OAuth 2.0 layer. PingOne either
//     redirects to the callback with ?code=... or (in JSON mode) returns
//     authorizeResponse.code directly. Both cases are handled.
//
//  4. POST /as/token  (standard OAuth 2.0 authorization_code exchange)
//     Trades the code for an access token using HTTP Basic auth
//     (client_id:client_secret).
//
// Cookie handling
//
// PingOne issues session cookies (ST, ST-NO-SS) when the /as/authorize flow is
// initialised. These must be replayed verbatim on every subsequent call to the
// same flow, including the /flows/{id} and /as/resume calls. The standard
// http.Client cookie jar silently drops cookies whose path doesn't match the
// request path (RFC 6265), so this app captures and replays cookies manually.
//
// Prerequisites in PingOne:
//   - An OIDC web application with grant type authorization_code.
//   - Registration enabled on the application's sign-on policy (or no policy
//     required — the native API accepts registrations by default).
//   - Email verification is optional; this app handles both cases.
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

	// flowStore is a per-flow cookie cache keyed by PingOne flow ID.
	//
	// When a registration starts, /as/authorize sets session cookies that PingOne
	// uses to correlate all subsequent requests to the same flow. If the user must
	// verify their email the browser submits the OTP on a separate HTTP request —
	// potentially seconds later — so the cookies must survive between the /register
	// handler and the /verify handler. flowStore bridges that gap.
	//
	// Keys are removed after the flow completes (COMPLETED) to avoid unbounded growth.
	flowStore = make(map[string][]string)
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Falling back to system environment variables.")
	}

	envID = os.Getenv("PINGONE_ENV_ID")
	clientID = os.Getenv("PINGONE_CLIENT_ID")
	clientSecret = os.Getenv("PINGONE_CLIENT_SECRET")
	authPath = strings.TrimRight(os.Getenv("PINGONE_AUTH_PATH"), "/")

	if envID == "" || clientID == "" || clientSecret == "" || authPath == "" {
		log.Fatal("Missing required environment variables. Please check your .env file.")
	}

	http.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(logoPNG)
	})
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/verify", handleVerify)
	http.HandleFunc("/login-page", handleLoginPage)
	http.HandleFunc("/login", handleLogin)

	fmt.Println("Server starting on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

// --- cookie helpers ---

// captureCookies merges the Set-Cookie headers from resp into store, updating
// an existing entry if the same cookie name was already stored. Merging rather
// than appending is important because PingOne refreshes its session cookies on
// every response — replaying an old value causes a 401 on the next request.
func captureCookies(store []string, resp *http.Response) []string {
	for _, cookie := range resp.Cookies() {
		entry := cookie.Name + "=" + cookie.Value
		found := false
		for i, existing := range store {
			if strings.HasPrefix(existing, cookie.Name+"=") {
				store[i] = entry
				found = true
				break
			}
		}
		if !found {
			store = append(store, entry)
		}
	}
	return store
}

// cookieHeader joins the raw "name=value" strings in store into a single Cookie
// header value. Joining manually (rather than letting http.Client manage the jar)
// bypasses RFC 6265 path-scoping rules that would silently drop cookies whose
// path doesn't match the current request path.
func cookieHeader(store []string) string {
	return strings.Join(store, "; ")
}

// --- HTML templates ---

const indexHTML = `
<!DOCTYPE html>
<html>
<head><title>PingOne Demo</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;} button:hover{background:#b8002f;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
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
</html>`

const loginHTML = `
<!DOCTYPE html>
<html>
<head><title>Login</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;} button:hover{background:#b8002f;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
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
</html>`

const verifyHTML = `
<!DOCTYPE html>
<html>
<head><title>Verify Email</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;} button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;} button:hover{background:#b8002f;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2>Check Your Email</h2>
    <p>We've sent a 6-digit verification code to your email address.</p>
    <form action="/verify" method="POST">
        <input type="hidden" name="flowId" value="{{.FlowID}}">
        <label>Verification Code:</label><br>
        <input type="text" name="code" required><br><br>
        <button type="submit">Verify &amp; Complete</button>
    </form>
</div>
</body>
</html>`

const successHTML = `
<!DOCTYPE html>
<html>
<head><title>Success!</title><style>body{font-family:sans-serif; margin:0; background:#f5f5f5;}</style></head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
    <h2 style="color:#0a7a0a;">Registration Complete!</h2>
    <p>Your account has been successfully created and verified via PingOne.</p>
    <a href="/login-page">Click here to Log In</a>
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
    <h2>Welcome to your Dashboard!</h2>
    <p>You have successfully authenticated. Here is your Access Token:</p>
    <pre>{{.Token}}</pre>
    <a href="/">Log Out (Return to Home)</a>
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
    <h2 style="color:#b00020;">Something went wrong</h2>
    <pre>{{.Error}}</pre>
    <a href="/">Try Again</a>
</div>
</body>
</html>`

// --- HTTP handlers ---

// noRedirectClient returns an http.Client that never follows redirects.
//
// PingOne uses 302 redirects as part of the OAuth 2.0 flow (e.g. the /as/resume
// step redirects to the registered redirect_uri with ?code=...). If the Go HTTP
// client followed the redirect automatically we would lose both the Location
// header (which carries the auth code) and any Set-Cookie headers on the 302
// response. By returning http.ErrUseLastResponse we receive the redirect
// response itself so we can extract those values manually.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func handleIndex(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, indexHTML)
}

func handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, loginHTML)
}

// handleRegister drives the two-step registration sub-flow:
//
//  1. Initialise a PingOne flow session via GET /as/authorize?response_mode=pi.flow.
//  2. Submit the user's details via POST /flows/{id} with the register content type.
//
// If the environment requires email verification PingOne responds with
// status=VERIFICATION_CODE_REQUIRED. The handler then renders the OTP form and
// stores the in-progress flow cookies in flowStore so handleVerify can pick up
// the session when the user submits the code.
//
// If verification is not required PingOne returns status=COMPLETED immediately
// and the account is live — no further steps needed.
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	client := noRedirectClient()
	cookies := []string{}

	// Step 1: Initialise the PingOne authentication flow.
	//
	// response_mode=pi.flow tells PingOne to return a JSON body with a flow ID
	// instead of redirecting the browser to a hosted login page. The JSON also
	// signals which operations are allowed on this flow (e.g. registration).
	//
	// Accept: */* is required because the flow API returns a PingOne vendor
	// content type (application/vnd.pingidentity.*+json). Sending
	// Accept: application/json causes a 406.
	authURL := fmt.Sprintf(
		"%s/%s/as/authorize?response_type=code&client_id=%s&redirect_uri=http://localhost:3000/callback&scope=openid%%20profile&response_mode=pi.flow",
		authPath, envID, clientID,
	)
	reqInit, _ := http.NewRequest("GET", authURL, nil)
	reqInit.Header.Set("Accept", "*/*")

	initResp, err := client.Do(reqInit)
	if err != nil {
		renderError(w, "Failed to initialize flow: "+err.Error())
		return
	}
	defer initResp.Body.Close()
	cookies = captureCookies(cookies, initResp)

	var flowData map[string]interface{}
	json.NewDecoder(initResp.Body).Decode(&flowData)
	flowID, ok := flowData["id"].(string)
	if !ok {
		renderError(w, fmt.Sprintf("Failed to retrieve flowId. Response: %v", flowData))
		return
	}

	// Step 2: Submit the registration request.
	//
	// The Content-Type header tells PingOne which operation to perform on the
	// flow. Using application/vnd.pingidentity.user.register+json routes the
	// request to the registration handler. The body carries the new user's
	// credentials; password is validated against the environment's password
	// policy before the account is created.
	regBody, _ := json.Marshal(map[string]string{
		"username": username,
		"email":    email,
		"password": password,
	})
	reqReg, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/flows/%s", authPath, envID, flowID), bytes.NewBuffer(regBody))
	reqReg.Header.Set("Content-Type", "application/vnd.pingidentity.user.register+json")
	reqReg.Header.Set("Accept", "*/*")
	reqReg.Header.Set("Cookie", cookieHeader(cookies))

	regResp, err := client.Do(reqReg)
	if err != nil {
		renderError(w, "Failed to submit registration: "+err.Error())
		return
	}
	defer regResp.Body.Close()
	cookies = captureCookies(cookies, regResp)

	var regResult map[string]interface{}
	json.NewDecoder(regResp.Body).Decode(&regResult)

	// Persist the in-progress flow cookies so the /verify handler can reuse
	// the same PingOne session when the user submits their OTP. The entry is
	// removed once the flow reaches COMPLETED.
	flowStore[flowID] = cookies

	// VERIFICATION_CODE_REQUIRED means the environment has email verification
	// turned on. PingOne has already sent the OTP; we just need to collect it.
	if status, _ := regResult["status"].(string); status == "VERIFICATION_CODE_REQUIRED" {
		tmpl, _ := template.New("verify").Parse(verifyHTML)
		tmpl.Execute(w, struct{ FlowID string }{FlowID: flowID})
		return
	}
	// COMPLETED means verification is disabled — the account is ready to use.
	if status, _ := regResult["status"].(string); status == "COMPLETED" {
		delete(flowStore, flowID)
		fmt.Fprint(w, successHTML)
		return
	}

	renderError(w, fmt.Sprintf("Unexpected registration status: %v", regResult))
}

// handleVerify processes the OTP submitted on the email verification screen.
//
// PingOne keeps the registration flow alive until the user provides a valid
// verification code. This handler retrieves the flow cookies saved during
// handleRegister and posts the OTP to the same /flows/{id} endpoint with the
// verify content type. A status=COMPLETED response means the account has been
// fully activated.
func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	flowID := strings.TrimSpace(r.FormValue("flowId"))
	code := strings.TrimSpace(r.FormValue("code"))

	// Retrieve the cookies that were stored when the registration step ran.
	// Without them PingOne cannot correlate this request with the live flow
	// session and will return an error.
	cookies := flowStore[flowID]
	client := noRedirectClient()

	// The Content-Type application/vnd.pingidentity.user.verify+json signals
	// that this POST carries a verification code, not another registration attempt.
	verifyBody, _ := json.Marshal(map[string]string{"verificationCode": code})
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/flows/%s", authPath, envID, flowID), bytes.NewBuffer(verifyBody))
	req.Header.Set("Content-Type", "application/vnd.pingidentity.user.verify+json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cookie", cookieHeader(cookies))

	verifyResp, err := client.Do(req)
	if err != nil {
		renderError(w, "Failed to submit verification code: "+err.Error())
		return
	}
	defer verifyResp.Body.Close()

	var verifyResult map[string]interface{}
	json.NewDecoder(verifyResp.Body).Decode(&verifyResult)

	if status, _ := verifyResult["status"].(string); status == "COMPLETED" {
		delete(flowStore, flowID)
		fmt.Fprint(w, successHTML)
		return
	}

	renderError(w, fmt.Sprintf("Verification failed. Response: %v", verifyResult))
}

// handleLogin drives the four-step sign-on sub-flow for a user who already has
// an account (either just registered, or returning).
//
// The flow is identical in structure to the registration sub-flow up through
// step 1 (initialise session), but uses the usernamePassword.check content type
// in step 2 rather than user.register. Steps 3 and 4 (resume + token exchange)
// are unique to sign-on and have no equivalent in registration.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login-page", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	client := noRedirectClient()
	cookies := []string{}

	// Step 1: Initialise a fresh authentication session (same as in registration).
	// This produces a new flow ID and a new set of session cookies — it is not
	// related to any previous registration flow.
	authURL := fmt.Sprintf(
		"%s/%s/as/authorize?response_type=code&client_id=%s&redirect_uri=http://localhost:3000/callback&scope=openid%%20profile&response_mode=pi.flow",
		authPath, envID, clientID,
	)
	reqInit, _ := http.NewRequest("GET", authURL, nil)
	reqInit.Header.Set("Accept", "*/*")

	initResp, err := client.Do(reqInit)
	if err != nil {
		renderError(w, "Login failed to initialize flow: "+err.Error())
		return
	}
	defer initResp.Body.Close()
	cookies = captureCookies(cookies, initResp)

	var flowData map[string]interface{}
	json.NewDecoder(initResp.Body).Decode(&flowData)
	flowID, ok := flowData["id"].(string)
	if !ok {
		renderError(w, fmt.Sprintf("Login failed to retrieve flowId. Response: %v", flowData))
		return
	}

	// Step 2: Validate the user's credentials.
	//
	// Content-Type application/vnd.pingidentity.usernamePassword.check+json
	// tells PingOne to perform a username + password check against its directory
	// (as opposed to registering a new user or verifying an OTP).
	// status=COMPLETED means authentication passed. Any other status (e.g.
	// MUST_CHANGE_PASSWORD, MFA_REQUIRED) indicates additional steps that this
	// sample does not implement.
	loginBody, _ := json.Marshal(map[string]string{"username": username, "password": password})
	reqLogin, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/flows/%s", authPath, envID, flowID), bytes.NewBuffer(loginBody))
	reqLogin.Header.Set("Content-Type", "application/vnd.pingidentity.usernamePassword.check+json")
	reqLogin.Header.Set("Accept", "*/*")
	reqLogin.Header.Set("Cookie", cookieHeader(cookies))

	loginResp, err := client.Do(reqLogin)
	if err != nil {
		renderError(w, "Failed to submit credentials: "+err.Error())
		return
	}
	defer loginResp.Body.Close()
	cookies = captureCookies(cookies, loginResp)

	var loginResult map[string]interface{}
	json.NewDecoder(loginResp.Body).Decode(&loginResult)

	if status, _ := loginResult["status"].(string); status != "COMPLETED" {
		renderError(w, fmt.Sprintf("Login failed or requires MFA. Status: %v", loginResult))
		return
	}

	// Step 3: Resume the OAuth 2.0 session to get an authorization code.
	//
	// After the native flow signals COMPLETED, the browser needs to cross back
	// into the OAuth layer. GET /as/resume?flowId=... does that bridge. PingOne
	// may respond with:
	//   - A 302 redirect to the registered redirect_uri with ?code=... in the
	//     Location header (the standard OIDC redirect).
	//   - A JSON body containing authorizeResponse.code (when the client signals
	//     it can handle JSON responses).
	// Both formats are checked below so the app works regardless of which one
	// PingOne sends.
	reqResume, _ := http.NewRequest("GET", fmt.Sprintf("%s/%s/as/resume?flowId=%s", authPath, envID, flowID), nil)
	reqResume.Header.Set("Accept", "*/*")
	reqResume.Header.Set("Cookie", cookieHeader(cookies))

	resumeResp, err := client.Do(reqResume)
	if err != nil {
		renderError(w, "Failed to resume flow: "+err.Error())
		return
	}
	defer resumeResp.Body.Close()
	cookies = captureCookies(cookies, resumeResp)

	authCode := ""
	contentType := resumeResp.Header.Get("Content-Type")
	if strings.Contains(contentType, "json") {
		var resumeResult map[string]interface{}
		json.NewDecoder(resumeResp.Body).Decode(&resumeResult)
		if authResp, ok := resumeResult["authorizeResponse"].(map[string]interface{}); ok {
			authCode, _ = authResp["code"].(string)
		}
	}
	if authCode == "" {
		// The code was not in the JSON body — check the Location header of a
		// redirect response instead.
		if loc := resumeResp.Header.Get("Location"); loc != "" {
			if u, err := url.Parse(loc); err == nil {
				authCode = u.Query().Get("code")
			}
		}
	}
	if authCode == "" {
		renderError(w, "Failed to get authorization code from resume.")
		return
	}

	// Step 4: Exchange the authorization code for an access token.
	//
	// This is a standard OAuth 2.0 authorization_code grant. The redirect_uri
	// must exactly match the value used in the authorize call above and the one
	// registered on the PingOne application — PingOne validates all three
	// before issuing tokens. Authentication uses HTTP Basic (CLIENT_SECRET_BASIC):
	// client_id and client_secret are base64-encoded in the Authorization header.
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("redirect_uri", "http://localhost:3000/callback")

	reqToken, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/as/token", authPath, envID), strings.NewReader(data.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqToken.SetBasicAuth(clientID, clientSecret)

	tokenResp, err := client.Do(reqToken)
	if err != nil {
		renderError(w, "Failed to exchange token: "+err.Error())
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
