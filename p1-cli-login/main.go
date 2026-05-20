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
	// 1. Load credentials
	godotenv.Load()
	clientID := os.Getenv("PINGONE_CLIENT_ID")
	envID := os.Getenv("PINGONE_ENVIRONMENT_ID")

	if clientID == "" || envID == "" {
		log.Fatal("🛑 ERROR: Missing PINGONE_CLIENT_ID or PINGONE_ENVIRONMENT_ID in .env file.")
	}

	fmt.Println("🚀 Starting PingOne CLI Login...")

	// 2. Configure the SDK
	serviceCfg := config.NewConfiguration()
	serviceCfg.WithStorageName("PingOneCLI_Vault") // New cache just for the CLI
	serviceCfg.WithGrantType(oauth2.GrantTypeAuthorizationCode)
	serviceCfg.WithAuthorizationCodeClientID(clientID)
	serviceCfg.WithEnvironmentID(envID)
	serviceCfg.WithRootDomain("pingone.com")

	serviceCfg.WithAuthorizationCodeRedirectURI(config.AuthorizationCodeRedirectURI{
		Port: "7464",
		Path: "/callback",
	})
	serviceCfg.WithAuthorizationCodeScopes([]string{"openid", "profile"})

	// Initialize the Client (required by SDK architecture)
	p1Config := pingone.NewConfiguration(serviceCfg)
	if _, err := pingone.NewAPIClient(p1Config); err != nil {
		log.Fatalf("Failed to initialize SDK: %v", err)
	}

	// 3. Trigger the Auth Flow!
	fmt.Println("⏳ Authenticating... (Check your browser if it opens)")
	tokenString, err := serviceCfg.GetAccessToken(context.Background())
	if err != nil {
		log.Fatalf("❌ Authentication failed: %v", err)
	}

	fmt.Println("✅ Authentication Successful!")
	fmt.Println("📡 Fetching User Profile from PingOne...")

	// 4. Fetch the User Profile via HTTP
	userInfoURL := fmt.Sprintf("https://auth.pingone.com/%s/as/userinfo", envID)
	req, _ := http.NewRequest("GET", userInfoURL, nil)
	req.Header.Add("Authorization", "Bearer "+tokenString)

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		log.Fatalf("❌ Failed to fetch profile. HTTP Status: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// 5. Read and format the JSON response
	body, _ := io.ReadAll(resp.Body)
	var parsedJSON map[string]interface{}
	json.Unmarshal(body, &parsedJSON)
	prettyJSON, _ := json.MarshalIndent(parsedJSON, "", "  ")

	// 6. Print the result directly to the terminal
	fmt.Printf("\n--- 👤 USER PROFILE ---\n%s\n-----------------------\n", string(prettyJSON))
}