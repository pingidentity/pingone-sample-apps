// Package main demonstrates a browser-based PingOne login flow driven by the
// PingOne Go SDK inside a lightweight web server.
//
// This sample shows how to integrate the Authorization Code grant into a
// server-rendered web application. The web server itself acts as the OAuth
// client: when a user clicks the login button the server initiates the flow on
// their behalf, handles the token exchange, and then makes an authenticated API
// call to prove the token works — all within a single HTTP request to /fetch.
//
// Flow overview:
//
//  1. Server startup — the SDK is configured once with the app's client_id,
//     environment ID, loopback redirect URI (port 7464), and OIDC scopes.
//     A single shared *config.Configuration and *pingone.APIClient are stored
//     in package-level variables so every request handler can reach them
//     without re-initialising the SDK.
//
//  2. GET /fetch — handleFetch calls GetAccessToken, which opens the system
//     browser at PingOne's /as/authorize endpoint and starts a temporary
//     localhost listener on port 7464. After the user authenticates, PingOne
//     redirects to http://localhost:7464/callback with an authorization code.
//     The SDK captures the code, performs the /as/token exchange (with PKCE),
//     caches the resulting tokens, and returns the access token string.
//
//  3. GET /as/userinfo — the access token is forwarded to the OIDC UserInfo
//     endpoint as a Bearer token. The response contains the authenticated
//     user's OIDC claims (sub, name, preferred_username, etc.) which are
//     rendered back to the browser as formatted JSON.
//
// Prerequisites in PingOne:
//   - A Native/SPA or Web App with the Authorization Code grant enabled.
//   - http://localhost:7464/callback registered as an allowed redirect URI.
//   - The test user must belong to the app's target population.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/pingidentity/pingone-go-client/config"
	"github.com/pingidentity/pingone-go-client/oauth2"
	"github.com/pingidentity/pingone-go-client/pingone"
)

// apiClient and serviceCfg are package-level variables so both the main
// setup function and the HTTP handler functions can share the same
// initialised SDK state. Storing them globally avoids re-creating the
// SDK configuration (and its token cache) on every HTTP request.
var (
	apiClient  *pingone.APIClient
	serviceCfg *config.Configuration
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found, relying on system environment variables.")
	}

	clientID := os.Getenv("PINGONE_CLIENT_ID")
	envIDStr := os.Getenv("PINGONE_ENVIRONMENT_ID")

	if clientID == "" || envIDStr == "" {
		log.Fatal("ERROR: PINGONE_CLIENT_ID or PINGONE_ENVIRONMENT_ID is empty.")
	}

	// Build the SDK configuration once at startup. Key decisions:
	//
	//   WithStorageName — names the local token cache. A stable, unique name
	//   means the SDK reuses a valid cached token across server restarts
	//   without prompting the user to log in again.
	//
	//   WithGrantType — selects the Authorization Code grant. This is the
	//   interactive, browser-redirect-based flow; the SDK manages the PKCE
	//   code verifier/challenge pair automatically.
	//
	//   WithAuthorizationCodeRedirectURI — the SDK starts a short-lived HTTP
	//   listener on localhost:7464/callback to receive the authorization code
	//   after the user authenticates. This URI must be registered on the
	//   PingOne app exactly; even a trailing-slash difference causes
	//   PingOne to reject the request with redirect_uri_mismatch.
	//
	//   WithAuthorizationCodeScopes — "openid" enables the ID token and
	//   the UserInfo endpoint. "profile" additionally unlocks name and
	//   preferred_username in the UserInfo response.
	serviceCfg = config.NewConfiguration()
	serviceCfg.WithStorageName("PingOneWebPOC_v4")
	serviceCfg.WithGrantType(oauth2.GrantTypeAuthorizationCode)
	serviceCfg.WithAuthorizationCodeClientID(clientID)
	serviceCfg.WithEnvironmentID(envIDStr)
	serviceCfg.WithRootDomain("pingone.com")

	redirectURI := config.AuthorizationCodeRedirectURI{
		Port: "7464",
		Path: "/callback",
	}
	serviceCfg.WithAuthorizationCodeRedirectURI(redirectURI)
	serviceCfg.WithAuthorizationCodeScopes([]string{"openid", "profile"})

	// NewAPIClient wires the SDK's internal HTTP transports and validates the
	// configuration. It must be called before any GetAccessToken call — the SDK
	// does not lazily initialise its internals, and skipping this step causes
	// the first token request to fail with an uninitialised-state error.
	p1Config := pingone.NewConfiguration(serviceCfg)
	var err error
	apiClient, err = pingone.NewAPIClient(p1Config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/fetch", handleFetch)

	fmt.Println("Web login flow demo running at http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

// handleHome renders the landing page with a button that links to /fetch.
// Keeping the home page stateless means users can navigate back here to
// start a fresh session without needing a dedicated logout endpoint.
func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
		<div style="font-family: sans-serif; padding: 40px; text-align: center;">
			<h1>PingOne Login Flow Demo</h1>
			<p>Click below to trigger the SDK Authorization Code flow and fetch your User Profile.</p>
			<a href="/fetch"><button style="padding: 15px 30px; font-size: 16px; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 5px;">Sign In &amp; Fetch Profile</button></a>
		</div>
	`)
}

// handleFetch drives the two-step sequence: obtain an access token via the
// Authorization Code flow, then call the OIDC UserInfo endpoint to retrieve
// the authenticated user's claims.
func handleFetch(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// GetAccessToken checks the local cache first. If a valid token is cached
	// (e.g. from a previous request in the same server session) it is returned
	// immediately without opening the browser again. If the cache is empty or
	// the token has expired, the SDK initiates the browser-based Authorization
	// Code flow and blocks until the user completes authentication.
	tokenString, err := serviceCfg.GetAccessToken(ctx)
	if err != nil {
		log.Printf("Failed to get token: %v", err)
		http.Error(w, "Failed to get access token. Check your terminal for details.", 500)
		return
	}

	// Read the environment ID again here in case this handler is ever extracted
	// into its own function in future — keeping data access local makes the
	// dependency explicit rather than relying on a package-level variable.
	envID := os.Getenv("PINGONE_ENVIRONMENT_ID")
	userInfoURL := fmt.Sprintf("https://auth.pingone.com/%s/as/userinfo", envID)

	// The UserInfo endpoint requires the access token in the Authorization
	// header as a Bearer token. Sending the token as a query parameter or in
	// the request body is not supported by the PingOne UserInfo endpoint.
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		http.Error(w, "Failed to create HTTP request.", 500)
		return
	}
	req.Header.Add("Authorization", "Bearer "+tokenString)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		log.Printf("UserInfo HTTP Error: %v, Status Code: %d", err, resp.StatusCode)
		http.Error(w, "Failed to fetch user info from PingOne.", 500)
		return
	}
	defer resp.Body.Close()

	userInfoBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response from PingOne.", 500)
		return
	}

	// Attempt to pretty-print the JSON so individual claims are readable in
	// the browser. If the response body is not valid JSON (e.g. an unexpected
	// error format) fall back to rendering the raw bytes so nothing is hidden.
	var prettyUserInfo string
	var parsedUser map[string]interface{}
	if err := json.Unmarshal(userInfoBytes, &parsedUser); err == nil {
		formatted, _ := json.MarshalIndent(parsedUser, "", "  ")
		prettyUserInfo = string(formatted)
	} else {
		prettyUserInfo = string(userInfoBytes)
	}

	fmt.Fprintf(w, `
		<div style="font-family: sans-serif; padding: 40px;">
			<h1 style="color: #28a745;">Profile Retrieved!</h1>
			<h3>Your PingOne UserInfo Data:</h3>
			<pre style="background: #f4f4f4; padding: 20px; border-radius: 8px; overflow-x: auto; font-size: 14px; border: 1px solid #ddd;">%s</pre>
			<hr style="margin-top: 30px;">
			<a href="/">Start Over</a>
		</div>
	`, prettyUserInfo)
}