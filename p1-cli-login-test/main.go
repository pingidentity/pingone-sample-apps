// Package main is a self-contained test harness for the PingOne CLI login flow.
// It exercises the same Authorization Code + PKCE sequence as p1-cli-login but
// uses a separate token-cache storage name so its cached credentials do not
// interfere with other running samples.
//
// This variant is intended for verifying the end-to-end login path in isolation:
// run it against a freshly configured PingOne app to confirm that the app's
// redirect URI, scopes, and token caching are all working before embedding the
// same configuration in a larger project.
//
// Flow overview:
//
//  1. SDK configuration — the OIDC app's client_id, environment ID, loopback
//     redirect URI, and OIDC scopes are passed to the SDK.
//
//  2. Authorization Code grant with PKCE — GetAccessToken opens the system
//     browser at PingOne's /as/authorize endpoint, then listens on the
//     configured loopback port for PingOne's callback carrying the
//     authorization code. The SDK exchanges the code for tokens at /as/token
//     and caches them under a dedicated storage name.
//
//  3. GET /as/userinfo — the access token is attached as a Bearer token and
//     the UserInfo endpoint returns the authenticated user's OIDC claims,
//     confirming that the token is valid and the approved scopes include the
//     requested identity data.
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
	// variables so this test harness works in CI without a local file.
	godotenv.Load()
	clientID := os.Getenv("PINGONE_CLIENT_ID")
	envID := os.Getenv("PINGONE_ENVIRONMENT_ID")

	if clientID == "" || envID == "" {
		log.Fatal("ERROR: Missing PINGONE_CLIENT_ID or PINGONE_ENVIRONMENT_ID in .env file.")
	}

	fmt.Println("Starting PingOne CLI Login (test harness)...")

	// Build the SDK configuration. Each WithXxx call controls one part of the
	// Authorization Code flow:
	//
	//   WithStorageName — names the local token cache used by this instance.
	//   Using a unique name ("PingOneCLI_Vault_Test") keeps tokens for this
	//   test harness separate from any other app's cached credentials on the
	//   same machine, which prevents stale tokens from a different app from
	//   masking authentication failures during testing.
	//
	//   WithGrantType — selects the Authorization Code grant. This is the
	//   interactive, browser-based grant type appropriate for confirming that
	//   PingOne's sign-in page is reachable and that the app's configuration
	//   (redirect URIs, scopes, signing keys) is correct.
	//
	//   WithAuthorizationCodeRedirectURI — the SDK starts a local HTTP listener
	//   on this port/path to receive the callback from PingOne after sign-in.
	//   Port 7464 must match the value registered on the PingOne app; a
	//   mismatch causes PingOne to return a redirect_uri_mismatch error before
	//   the user ever completes authentication.
	//
	//   WithAuthorizationCodeScopes — "openid" is required to access the
	//   UserInfo endpoint. "profile" additionally unlocks name and
	//   preferred_username, useful for confirming which user authenticated.
	serviceCfg := config.NewConfiguration()
	serviceCfg.WithStorageName("PingOneCLI_Vault_Test")
	serviceCfg.WithGrantType(oauth2.GrantTypeAuthorizationCode)
	serviceCfg.WithAuthorizationCodeClientID(clientID)
	serviceCfg.WithEnvironmentID(envID)
	serviceCfg.WithRootDomain("pingone.com")

	serviceCfg.WithAuthorizationCodeRedirectURI(config.AuthorizationCodeRedirectURI{
		Port: "7464",
		Path: "/callback",
	})
	serviceCfg.WithAuthorizationCodeScopes([]string{"openid", "profile"})

	// NewAPIClient initialises the SDK's internal HTTP transport and validates
	// the configuration. It must be called before GetAccessToken regardless of
	// whether the returned client is used directly; skipping it leaves internal
	// state uninitialised, which causes GetAccessToken to fail at runtime.
	p1Config := pingone.NewConfiguration(serviceCfg)
	if _, err := pingone.NewAPIClient(p1Config); err != nil {
		log.Fatalf("Failed to initialize SDK: %v", err)
	}

	// GetAccessToken performs the browser-based Authorization Code + PKCE
	// exchange and returns the raw access token string. The PKCE code verifier
	// and challenge are generated and verified by the SDK; the caller does not
	// need to manage them. On success the token is cached; re-running this
	// harness without clearing the cache will return the cached token rather
	// than opening the browser a second time.
	fmt.Println("Authenticating... (your browser will open for sign-in)")
	tokenString, err := serviceCfg.GetAccessToken(context.Background())
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	fmt.Println("Authentication successful. Fetching user profile from PingOne...")

	// Call the OIDC UserInfo endpoint with the access token to retrieve the
	// user's claims. A successful 200 response confirms the token is valid and
	// the "openid" scope was granted. The user's sub (subject) claim is always
	// present; name and preferred_username appear only when the "profile" scope
	// was approved.
	userInfoURL := fmt.Sprintf("https://auth.pingone.com/%s/as/userinfo", envID)
	req, _ := http.NewRequest("GET", userInfoURL, nil)
	req.Header.Add("Authorization", "Bearer "+tokenString)

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		log.Fatalf("Failed to fetch profile. HTTP Status: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// Pretty-print the UserInfo JSON so each claim is visible individually.
	// Review the output to confirm the expected user signed in and that the
	// profile attributes (name, email) are populated as required.
	body, _ := io.ReadAll(resp.Body)
	var parsedJSON map[string]interface{}
	json.Unmarshal(body, &parsedJSON)
	prettyJSON, _ := json.MarshalIndent(parsedJSON, "", "  ")

	fmt.Printf("\n--- USER PROFILE ---\n%s\n--------------------\n", string(prettyJSON))
}