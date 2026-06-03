// Package main demonstrates a CLI-based OAuth 2.0 Authorization Code login
// using the PingOne Go SDK.
//
// Flow overview:
//
//  1. SDK configuration — supply the OIDC app's client_id, environment ID,
//     redirect URI (localhost loopback), and desired OIDC scopes to the SDK.
//
//  2. Authorization Code grant with PKCE — calling GetAccessToken launches
//     the system browser at PingOne's /as/authorize endpoint and starts a
//     temporary localhost HTTP listener on the configured redirect port.
//     After the user authenticates in the browser, PingOne redirects back
//     with an authorization code appended to the callback URL. The SDK
//     intercepts that code, exchanges it for tokens at /as/token, and caches
//     the result under the configured storage name. Subsequent calls to
//     GetAccessToken return the cached token until it expires.
//
//  3. GET /as/userinfo — the access token is sent as a Bearer token to the
//     OIDC UserInfo endpoint to retrieve the authenticated user's claims
//     (sub, name, email, etc.). The exact claims returned depend on which
//     scopes were approved; requesting "openid profile" typically yields the
//     user's name and preferred_username.
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

func main() {
	// Load credentials from .env if present; fall back to system environment
	// variables so the sample works in CI environments without a file.
	godotenv.Load()
	clientID := os.Getenv("PINGONE_CLIENT_ID")
	envID := os.Getenv("PINGONE_ENVIRONMENT_ID")

	if clientID == "" || envID == "" {
		log.Fatal("ERROR: Missing PINGONE_CLIENT_ID or PINGONE_ENVIRONMENT_ID in .env file.")
	}

	fmt.Println("Starting PingOne CLI Login...")

	// Build the SDK configuration. Each WithXxx call sets one aspect of the
	// OAuth 2.0 Authorization Code flow:
	//
	//   WithStorageName — a unique key for the SDK's local token cache. Using
	//   a distinct name here prevents this CLI app's cached token from being
	//   accidentally shared with other apps running on the same machine.
	//
	//   WithGrantType — selects the Authorization Code grant, which is the
	//   browser-redirect-based flow suitable for user-facing CLI tools.
	//
	//   WithAuthorizationCodeRedirectURI — the SDK spins up a local HTTP
	//   listener on this port to receive the authorization code after the
	//   user authenticates. Port 7464 must match the redirect URI registered
	//   on the PingOne app; if it doesn't, PingOne returns a redirect_uri_mismatch
	//   error before the user can log in.
	//
	//   WithAuthorizationCodeScopes — "openid" is required for PingOne to
	//   issue an ID token and for the UserInfo endpoint to be accessible.
	//   "profile" unlocks name and preferred_username claims in the UserInfo
	//   response.
	serviceCfg := config.NewConfiguration()
	serviceCfg.WithStorageName("PingOneCLI_Vault")
	serviceCfg.WithGrantType(oauth2.GrantTypeAuthorizationCode)
	serviceCfg.WithAuthorizationCodeClientID(clientID)
	serviceCfg.WithEnvironmentID(envID)
	serviceCfg.WithRootDomain("pingone.com")

	serviceCfg.WithAuthorizationCodeRedirectURI(config.AuthorizationCodeRedirectURI{
		Port: "7464",
		Path: "/callback",
	})
	serviceCfg.WithAuthorizationCodeScopes([]string{"openid", "profile"})

	// NewAPIClient wires together the SDK's internal HTTP transports and
	// validates the configuration. It must be called before GetAccessToken
	// even if the returned client object is not used directly in this sample.
	p1Config := pingone.NewConfiguration(serviceCfg)
	if _, err := pingone.NewAPIClient(p1Config); err != nil {
		log.Fatalf("Failed to initialize SDK: %v", err)
	}

	// GetAccessToken drives the full Authorization Code + PKCE flow:
	// it opens the system browser, waits for the callback on the loopback
	// listener, exchanges the code for tokens, and returns the access token
	// as a string. On subsequent calls it returns the cached token if still
	// valid, so the user is not prompted to log in again unnecessarily.
	fmt.Println("Authenticating... (your browser will open for sign-in)")
	tokenString, err := serviceCfg.GetAccessToken(context.Background())
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	fmt.Println("Authentication successful. Fetching user profile from PingOne...")

	// Call the OIDC UserInfo endpoint to retrieve the authenticated user's
	// claims. The access token obtained above must be sent in the Authorization
	// header as a Bearer token — cookie-based session auth is not accepted here.
	userInfoURL := fmt.Sprintf("https://auth.pingone.com/%s/as/userinfo", envID)
	req, _ := http.NewRequest("GET", userInfoURL, nil)
	req.Header.Add("Authorization", "Bearer "+tokenString)

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		log.Fatalf("Failed to fetch profile. HTTP Status: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// Unmarshal and pretty-print the UserInfo JSON so each claim is readable
	// in the terminal output. The exact fields depend on the approved scopes
	// and the user's populated attributes in PingOne.
	body, _ := io.ReadAll(resp.Body)
	var parsedJSON map[string]interface{}
	json.Unmarshal(body, &parsedJSON)
	prettyJSON, _ := json.MarshalIndent(parsedJSON, "", "  ")

	fmt.Printf("\n--- USER PROFILE ---\n%s\n--------------------\n", string(prettyJSON))
}