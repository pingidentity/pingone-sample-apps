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

// 1. Make both the client and the configuration globally accessible
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
		log.Fatal("🛑 ERROR: PINGONE_CLIENT_ID or PINGONE_ENVIRONMENT_ID is empty.")
	}

	// 2. Initialize the global configuration variable
	serviceCfg = config.NewConfiguration()
	serviceCfg.WithStorageName("PingOneWebPOC_v4") // Keeps our clean cache state
	serviceCfg.WithGrantType(oauth2.GrantTypeAuthorizationCode)

	serviceCfg.WithAuthorizationCodeClientID(clientID)
	serviceCfg.WithEnvironmentID(envIDStr)
	serviceCfg.WithRootDomain("pingone.com")

	redirectURI := config.AuthorizationCodeRedirectURI{
		Port: "7464",
		Path: "/callback",
	}
	serviceCfg.WithAuthorizationCodeRedirectURI(redirectURI)

	// Requesting OIDC scopes to get the user's identity data
	serviceCfg.WithAuthorizationCodeScopes([]string{"openid", "profile"})

	// 3. Initialize the Client
	p1Config := pingone.NewConfiguration(serviceCfg)
	var err error
	apiClient, err = pingone.NewAPIClient(p1Config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// 4. Setup Web Server Handlers
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/fetch", handleFetch)

	fmt.Println("🚀 Web POC running at http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
		<div style="font-family: sans-serif; padding: 40px; text-align: center;">
			<h1>PingOne Web POC (2026 Beta)</h1>
			<p>Click below to trigger the SDK Auth Flow and fetch your User Profile.</p>
			<a href="/fetch"><button style="padding: 15px 30px; font-size: 16px; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 5px;">Run SDK Auth & Fetch Profile</button></a>
		</div>
	`)
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// 1. Ask the SDK configuration for the Access Token
	tokenString, err := serviceCfg.GetAccessToken(ctx)
	if err != nil {
		log.Printf("Failed to get token: %v", err)
		http.Error(w, "Failed to get access token. Check your terminal for details.", 500)
		return
	}

	// 2. Build the UserInfo URL using your Environment ID
	envID := os.Getenv("PINGONE_ENVIRONMENT_ID")
	userInfoURL := fmt.Sprintf("https://auth.pingone.com/%s/as/userinfo", envID)

	// 3. Make the HTTP GET Call with the Bearer Token
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

	// 4. Read the response body
	userInfoBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response from PingOne.", 500)
		return
	}

	// 5. Pretty-print the JSON response
	var prettyUserInfo string
	var parsedUser map[string]interface{}
	if err := json.Unmarshal(userInfoBytes, &parsedUser); err == nil {
		formatted, _ := json.MarshalIndent(parsedUser, "", "  ")
		prettyUserInfo = string(formatted)
	} else {
		prettyUserInfo = string(userInfoBytes)
	}

	// 6. Render the Profile directly to the browser!
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