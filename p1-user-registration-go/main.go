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

	// Per-flow cookie store keyed by flowID.
	// Holds raw "name=value" cookie strings captured from PingOne responses so we can replay them
	// verbatim across requests, bypassing strict RFC 6265 path scoping.
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

	// 1. Initialize flow
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

	// 2. Submit registration
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

	// Persist cookies under the flowID so /verify can find them.
	flowStore[flowID] = cookies

	if status, _ := regResult["status"].(string); status == "VERIFICATION_CODE_REQUIRED" {
		tmpl, _ := template.New("verify").Parse(verifyHTML)
		tmpl.Execute(w, struct{ FlowID string }{FlowID: flowID})
		return
	}
	if status, _ := regResult["status"].(string); status == "COMPLETED" {
		delete(flowStore, flowID)
		fmt.Fprint(w, successHTML)
		return
	}

	renderError(w, fmt.Sprintf("Unexpected registration status: %v", regResult))
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	flowID := strings.TrimSpace(r.FormValue("flowId"))
	code := strings.TrimSpace(r.FormValue("code"))

	cookies := flowStore[flowID]
	client := noRedirectClient()

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

	// 1. Initialize login flow
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

	// 2. Submit credentials
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

	// 3. Resume to get authorization code
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

	// 4. Exchange code for token
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
