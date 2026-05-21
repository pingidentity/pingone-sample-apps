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

	adminEnvID        string
	adminClientID     string
	adminClientSecret string

	sessionStore = make(map[string]*flowSession)
)

// flowSession tracks the admin bearer token and any cookies across the flow.
type flowSession struct {
	adminToken string
	cookies    []*http.Cookie
}

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

// applyFlow sets the admin Bearer token and session cookies on a /flows/ API request.
// PingOne binds flow state to session cookies (ST, ST-NO-SS) set by earlier responses,
// and the bearer token authorizes the API call itself.
func (s *flowSession) applyFlow(req *http.Request) {
	if s.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.adminToken)
	}
	for _, cookie := range s.cookies {
		req.AddCookie(cookie)
	}
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// getAdminToken fetches a client_credentials access token using the admin worker app.
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

	// Smoke-test the admin credentials at startup.
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

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	adminToken, err := getAdminToken()
	if err != nil {
		renderError(w, "Failed to get admin token: "+err.Error())
		return
	}

	client := noRedirectClient()
	session := &flowSession{adminToken: adminToken}

	// 1. Initialize flow — response_mode=pi.flow returns JSON directly, no auth needed.
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
	session.capture(resp)

	var flowData map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&flowData)
	flowID, _ := flowData["id"].(string)
	log.Printf("[login] authorize flowID: %s", flowID)

	// 2. Submit credentials — requires admin Bearer token (matches Postman collection auth).
	// Accept: */* because PingOne returns a vendor content type (application/vnd.pingidentity.*+json).
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

	if newID, ok := loginResult["id"].(string); ok && newID != "" {
		flowID = newID
	}
	status, _ := loginResult["status"].(string)

	sessionStore[flowID] = session

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

	// OTP check — requires admin Bearer token (matches Postman collection auth).
	// Accept: */* because PingOne returns a vendor content type (application/vnd.pingidentity.*+json).
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

	if newID, ok := mfaResult["id"].(string); ok && newID != "" && newID != flowID {
		sessionStore[newID] = session
		delete(sessionStore, flowID)
		flowID = newID
	}

	if status, _ := mfaResult["status"].(string); status == "COMPLETED" {
		delete(sessionStore, flowID)
		completeLoginAndRender(w, flowID, session, client)
		return
	}

	renderError(w, fmt.Sprintf("MFA Failed. Response: %v", mfaResult))
}

// --- Helper Functions ---

func completeLoginAndRender(w http.ResponseWriter, flowID string, session *flowSession, client *http.Client) {
	reqResume, _ := http.NewRequest("GET", fmt.Sprintf("%s/%s/as/resume?flowId=%s", authPath, envID, flowID), nil)
	reqResume.Header.Set("Accept", "*/*")
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
