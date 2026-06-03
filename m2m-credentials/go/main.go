// Package main implements the OAuth 2.0 Client Credentials grant (M2M) with
// PingOne Protect risk evaluation.
//
// # What "machine-to-machine" means
//
// The client_credentials grant is used when there is no human user involved.
// A backend service (the "client") authenticates directly with PingOne using
// its own client_id and client_secret to obtain an access token. There is no
// browser redirect, no PKCE, and no authorization code — the token is returned
// in the same HTTP response as the authentication request.
//
// This grant type is the right choice whenever:
//   - You are calling PingOne management APIs from a server process.
//   - The action is on behalf of the service itself, not a specific user.
//   - You need to automate provisioning, reporting, or policy enforcement.
//
// # Workflow steps
//
// The sample walks through these steps and renders each one as a visible card
// so you can inspect every request and response:
//
//  1. Build token request — assemble the token endpoint URL and credentials.
//  2. Call /as/token — POST grant_type=client_credentials with HTTP Basic auth.
//  3. Decode access token — split the JWT and decode the header and payload.
//  4. Fetch JWKS — retrieve the public keys PingOne uses to sign tokens.
//  5. Verify token signature — validate the JWT signature against the JWKS.
//  6. Validate claims — check iss, client_id, exp, and iat.
//  7a/b. PingOne Protect risk evaluation — call the riskEvaluations API twice:
//        once with a trusted IP (User A) and once with a Tor exit node (User B).
//  8a/b. Call PingOne Management API — list users if risk is LOW/MEDIUM; block
//        the call if Protect returned HIGH.
//
// # PingOne configuration required
//
// A PingOne "Worker" application (type=WORKER) with:
//   - Token Endpoint Auth Method = Client Secret Basic
//   - Roles: Identity Data Read (to call the users API) and PingOne Protect
//     (to call the riskEvaluations API)
//
// A PingOne Protect risk policy set with Anonymous Network Detection enabled
// and the HIGH threshold set at or below 75. Its ID goes in
// PINGONE_RISK_POLICY_SET_ID.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

//go:embed logo.png
var logoPNG []byte

// envID is the PingOne environment UUID. All API URLs are scoped to an
// environment — it appears as a path segment in every request.
var (
	envID        string
	clientID     string
	clientSecret string
	authPath     string // base URL of the PingOne auth service, e.g. https://auth.pingone.com
	apiPath      string // base URL of the PingOne management API, e.g. https://api.pingone.com
	// riskPolicySetID identifies the PingOne Protect risk policy set to evaluate
	// events against. The policy set defines which predictors are active and what
	// score thresholds map to LOW / MEDIUM / HIGH outcomes.
	riskPolicySetID string
)

func main() {
	// godotenv reads .env from the current directory if it exists. If it does
	// not exist (e.g. in a container where vars are injected) we fall back to
	// the process environment without failing.
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Falling back to system environment variables.")
	}

	envID = os.Getenv("PINGONE_ENV_ID")
	clientID = os.Getenv("PINGONE_CLIENT_ID")
	clientSecret = os.Getenv("PINGONE_CLIENT_SECRET")
	// TrimRight removes any trailing slash so we can always append /path safely.
	authPath = strings.TrimRight(os.Getenv("PINGONE_AUTH_PATH"), "/")
	apiPath = strings.TrimRight(os.Getenv("PINGONE_API_PATH"), "/")
	riskPolicySetID = os.Getenv("PINGONE_RISK_POLICY_SET_ID")

	if envID == "" || clientID == "" || clientSecret == "" || authPath == "" || apiPath == "" || riskPolicySetID == "" {
		log.Fatal("Missing required environment variables. Please check your .env file.")
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/run", handleRun)
	http.HandleFunc("/logo.png", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(logoPNG)
	})

	fmt.Println("M2M Client Credentials demo on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

// --- HTTP handlers ---

func handleIndex(w http.ResponseWriter, _ *http.Request) {
	render(w, "M2M Client Credentials — start", `
<h2>OAuth 2.0 Client Credentials (M2M) + PingOne Protect</h2>
<p>This sample walks through the OAuth 2.0 <strong>client_credentials</strong> grant. There is no user, no browser redirect, and no PKCE. The client authenticates directly with the PingOne token endpoint using its own credentials, receives an access token, and calls <strong>PingOne Protect</strong> for two risk evaluations:</p>
<ul>
  <li><strong>User A — trusted:</strong> real client IP, <code>type=EXTERNAL</code> — expected to score LOW or MEDIUM, API call proceeds.</li>
  <li><strong>User B — suspicious:</strong> Tor exit node IP (<code>185.220.101.1</code>), <code>type=ANONYMOUS</code> — expected to score HIGH via Anonymous Network Detection, API call blocked.</li>
</ul>
<p>Both paths are rendered side-by-side so you can compare what PingOne Protect returns and see how the application gates the downstream call differently in each case.</p>
<form action="/run" method="POST"><button type="submit">Run Flow</button></form>
<p style="color:#666;font-size:13px;margin-top:30px;">PingOne config required: Worker application with Token Endpoint Auth Method = Client Secret Basic. The Worker app must have roles for Identity Data (read) and PingOne Protect (risk evaluation). A Protect risk policy set must exist with Anonymous Network Detection enabled and scored above the HIGH threshold; its ID goes in <code>PINGONE_RISK_POLICY_SET_ID</code>.</p>
`)
}

// handleRun orchestrates the full M2M + Protect workflow in response to a
// form POST. Each numbered step below corresponds to a visible card in the
// rendered output so developers can follow the protocol one round-trip at a
// time.
func handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	cards := []card{}

	// Step 1: Assemble the token request details.
	// The token endpoint URL is always:
	//   {authPath}/{envID}/as/token
	// Authentication uses HTTP Basic: the client_id and client_secret are
	// concatenated with ":" and base64-encoded into the Authorization header.
	// This is called CLIENT_SECRET_BASIC in OAuth terminology. An alternative
	// is CLIENT_SECRET_POST (credentials in the body), but PingOne Worker apps
	// default to Basic and it keeps the body clean.
	tokenURL := fmt.Sprintf("%s/%s/as/token", authPath, envID)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	basic := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))

	cards = append(cards, card{
		Title: "1. Build token request",
		OK:    true,
		URL:   "POST " + tokenURL,
		Detail: template.HTML(`The client_credentials grant requires no user interaction. The only inputs are the client's own credentials.<br><br>` +
			`Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>` +
			`Form body:<br>&nbsp;&nbsp;<code>grant_type=client_credentials</code>`),
		Body: fmt.Sprintf("client_id:     %s\ngrant_type:    client_credentials", clientID),
	})

	// Step 2: Call the token endpoint.
	// The response contains an access_token (JWT), token_type ("Bearer"),
	// expires_in (seconds until expiry), and scope (space-separated list of
	// granted scopes). There is no refresh_token in client_credentials flows
	// because re-authentication is trivial — just re-send the same request.
	tokReq, _ := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.Header.Set("Authorization", "Basic "+basic)
	tokResp, tokErr := http.DefaultClient.Do(tokReq)
	var tokRaw []byte
	var tokParsed map[string]interface{}
	tokStatus := 0
	if tokErr == nil {
		defer tokResp.Body.Close()
		tokRaw, _ = io.ReadAll(tokResp.Body)
		_ = json.Unmarshal(tokRaw, &tokParsed)
		tokStatus = tokResp.StatusCode
	}

	tokOK := tokErr == nil && tokStatus < 400
	cards = append(cards, card{
		Title: "2. Token endpoint response",
		OK:    tokOK,
		URL:   "POST " + tokenURL,
		Detail: template.HTML(fmt.Sprintf(
			`PingOne validates the client credentials and, if valid, returns an access token. No authorization code or redirect is involved — this is the entire grant in one round trip.<br>HTTP %d`,
			tokStatus,
		)),
		Body: prettyJSONOrRaw(tokRaw),
	})
	if !tokOK {
		render(w, "Run — token request failed", renderCards(cards)+`<p><a href="/">Start over</a></p>`)
		return
	}

	accessToken, _ := tokParsed["access_token"].(string)

	// Step 3: Decode the access token header and payload.
	// PingOne issues JWTs (JSON Web Tokens). A JWT has three base64url-encoded
	// parts separated by ".": header.payload.signature. Decoding the header
	// reveals the signing algorithm (alg) and key ID (kid); the payload
	// contains the actual claims such as iss, exp, and client_id. Decoding
	// does not verify the signature — that is the purpose of step 5.
	header, payload, _, decodeErr := decodeJWT(accessToken)
	cards = append(cards, card{
		Title:  "3. Decode access token",
		OK:     decodeErr == nil,
		Detail: "The access token is a JWT. Decoding it (without yet verifying the signature) shows the claims PingOne embedded — notably <code>client_id</code> (the client identity for M2M tokens), <code>iss</code>, <code>exp</code>, and any scopes granted by the authorization server.",
		Body:   fmt.Sprintf("header:\n%s\n\npayload:\n%s", prettyAny(header), prettyAny(payload)),
	})

	// Step 4: Fetch the JWKS (JSON Web Key Set).
	// The JWKS endpoint publishes the RSA public keys PingOne uses to sign
	// tokens. Each key has a "kid" (key ID) that matches the "kid" in the JWT
	// header, allowing the verifier to pick the right key when multiple keys
	// are in rotation. In production, you should cache the JWKS and only
	// re-fetch when you encounter a "kid" you have not seen before.
	jwksURL := fmt.Sprintf("%s/%s/as/jwks", authPath, envID)
	jwksResp, jwksErr := http.Get(jwksURL)
	var jwksRaw []byte
	var jwks map[string]interface{}
	if jwksErr == nil {
		defer jwksResp.Body.Close()
		jwksRaw, _ = io.ReadAll(jwksResp.Body)
		_ = json.Unmarshal(jwksRaw, &jwks)
	}
	cards = append(cards, card{
		Title:     "4. Fetch JWKS",
		OK:        jwksErr == nil,
		URL:       "GET " + jwksURL,
		Detail:    "Public keys used to verify the access token signature. In production, cache this response and re-fetch only when a new <code>kid</code> is encountered.",
		Body:      prettyJSONOrRaw(jwksRaw),
		Collapsed: true,
	})

	// Step 5: Verify the JWT signature.
	// We use the RS256 algorithm (RSA + SHA-256). The signed input is the
	// raw string "{base64url(header)}.{base64url(payload)}" — the same bytes
	// that were transmitted, not the decoded JSON. The signature covers exactly
	// these bytes, so any tampering with the token (even reordering JSON keys)
	// would invalidate it.
	verifyErr := verifyJWS(accessToken, header, jwks)
	cards = append(cards, card{
		Title: "5. Verify access token signature",
		OK:    verifyErr == nil,
		Detail: template.HTML(fmt.Sprintf(
			"alg: <code>%v</code>, kid: <code>%v</code><br>%s",
			header["alg"], header["kid"],
			ifThenElse(verifyErr == nil, "Signature valid (RS256, key matched by <code>kid</code>).", template.HTMLEscapeString("Signature INVALID: "+errString(verifyErr))),
		)),
	})

	// Step 6: Validate the access token claims.
	// Even a valid signature is not enough — the claims must also be checked:
	//   iss:       must match the PingOne AS issuer for this environment.
	//   client_id: PingOne Worker app tokens carry the client ID here (not in
	//              "sub" — the subject claim is absent in M2M tokens because
	//              there is no authenticated user).
	//   exp:       the token must not be expired.
	//   iat:       the issued-at time should not be in the future (clock skew
	//              of up to 60 seconds is tolerated).
	// There is intentionally no "nonce" check because nonces are only
	// meaningful in interactive flows that involve a browser redirect.
	expectedIssuer := fmt.Sprintf("%s/%s/as", authPath, envID)
	claimsErrs := validateAccessClaims(payload, expectedIssuer, clientID)
	cards = append(cards, card{
		Title: "6. Validate access token claims",
		OK:    len(claimsErrs) == 0,
		Detail: template.HTML(fmt.Sprintf(
			`Required checks: <code>iss</code> matches <code>%s</code>, <code>client_id</code> matches <code>%s</code>, <code>exp</code> &gt; now, <code>iat</code> not in the future.<br>Note: PingOne Worker app tokens use <code>client_id</code> (not <code>sub</code>) to identify the client. There is no <code>nonce</code> — no user authentication was involved.<br>%s`,
			template.HTMLEscapeString(expectedIssuer),
			template.HTMLEscapeString(clientID),
			renderClaimChecks(claimsErrs),
		)),
		Body: prettyAny(payload),
	})

	riskURL := fmt.Sprintf("%s/v1/environments/%s/riskEvaluations", apiPath, envID)
	mgmtURL := fmt.Sprintf("%s/v1/environments/%s/users", apiPath, envID)

	// Steps 7a / 8a — User A: trusted caller.
	// The risk evaluation event is populated with the real IP address of the
	// browser that triggered this request and user.type=EXTERNAL. EXTERNAL
	// indicates a known, authenticated user operating from a normal network.
	// PingOne Protect is expected to return LOW or MEDIUM, allowing the
	// downstream management API call to proceed.
	cards = append(cards, card{Divider: true, Title: "User A — trusted (real IP, type=EXTERNAL)"})

	clientIP := callerIP(r)
	riskBodyA := map[string]interface{}{
		"event": map[string]interface{}{
			"ip":   clientIP,
			"flow": map[string]interface{}{"type": "AUTHENTICATION"},
			"session": map[string]interface{}{"id": "m2m-demo-session-a"},
			"user": map[string]interface{}{
				"id":   "m2m-user-trusted",
				"type": "EXTERNAL",
				"name": "m2m-user-trusted",
			},
			"browser":     map[string]interface{}{"userAgent": r.Header.Get("User-Agent")},
			"sharingType": "SHARED",
			"targetResource": map[string]interface{}{
				"id":   "m2m-demo-resource",
				"name": "m2m-demo-resource",
			},
		},
		"riskPolicySet": map[string]interface{}{"id": riskPolicySetID},
	}
	riskLevelA, riskScoreA, riskCardsA := runRiskAndGate(accessToken, riskURL, mgmtURL, riskBodyA, "7a", "8a", r)
	cards = append(cards, riskCardsA...)

	// Steps 7b / 8b — User B: suspicious caller.
	// The event is deliberately crafted to trigger a HIGH risk score:
	//   ip:        185.220.101.1 — a known Tor exit node. Tor is an
	//              anonymizing network. PingOne Protect's Anonymous Network
	//              Detection predictor scores this IP at 80, which exceeds the
	//              HIGH threshold of 75 in the policy set.
	//   user.type: ANONYMOUS — signals that the upstream identity is unknown.
	//   userAgent: a bot-like string to reinforce the suspicious profile.
	// The downstream management API call is blocked when HIGH is returned.
	cards = append(cards, card{Divider: true, Title: "User B — suspicious (Tor IP, type=ANONYMOUS)"})

	riskBodyB := map[string]interface{}{
		"event": map[string]interface{}{
			"ip":   "185.220.101.1", // known Tor exit node — triggers Anonymous Network Detection
			"flow": map[string]interface{}{"type": "AUTHENTICATION"},
			"session": map[string]interface{}{"id": "m2m-demo-session-b"},
			"user": map[string]interface{}{
				"id":   "m2m-user-suspicious",
				"type": "ANONYMOUS",
				"name": "m2m-user-suspicious",
			},
			"browser":     map[string]interface{}{"userAgent": "python-requests/2.28.0"}, // bot-like UA
			"sharingType": "SHARED",
			"targetResource": map[string]interface{}{
				"id":   "m2m-demo-resource",
				"name": "m2m-demo-resource",
			},
		},
		"riskPolicySet": map[string]interface{}{"id": riskPolicySetID},
	}
	riskLevelB, riskScoreB, riskCardsB := runRiskAndGate(accessToken, riskURL, mgmtURL, riskBodyB, "7b", "8b", r)
	cards = append(cards, riskCardsB...)

	_ = riskLevelA
	_ = riskScoreA
	_ = riskLevelB
	_ = riskScoreB

	render(w, "Run — complete", renderCards(cards)+`<p style="margin-top:20px;"><a href="/">Run again</a></p>`)
}

// runRiskAndGate calls the PingOne Protect risk evaluation endpoint, appends
// result cards, then either makes the downstream management API call or blocks
// it based on the returned risk level.
//
// PingOne Protect evaluates the event body against the configured risk policy
// set and returns result.level (LOW / MEDIUM / HIGH) and result.score (0–100).
// The score is the combined output of all active predictors in the policy.
//
// This function implements the enforcement pattern:
//   - LOW / MEDIUM: the downstream API call proceeds. The access token is sent
//     as a Bearer token in the Authorization header.
//   - HIGH: the downstream call is blocked. This is where a real application
//     would deny the request, trigger step-up authentication, or alert on-call.
func runRiskAndGate(accessToken, riskURL, mgmtURL string, riskBody map[string]interface{}, riskStep, mgmtStep string, r *http.Request) (level, score string, cards []card) {
	riskBodyBytes, _ := json.Marshal(riskBody)
	riskReq, _ := http.NewRequest("POST", riskURL, strings.NewReader(string(riskBodyBytes)))
	// The access token obtained in step 2 is used here as a Bearer token.
	// Bearer tokens are sent in the Authorization header as "Bearer <token>".
	// The management API and the Protect API both accept the same token because
	// both endpoints are within the same PingOne environment.
	riskReq.Header.Set("Authorization", "Bearer "+accessToken)
	riskReq.Header.Set("Content-Type", "application/json")
	riskResp, riskErr := http.DefaultClient.Do(riskReq)
	var riskRaw []byte
	var riskParsed map[string]interface{}
	riskStatus := 0
	if riskErr == nil {
		defer riskResp.Body.Close()
		riskRaw, _ = io.ReadAll(riskResp.Body)
		_ = json.Unmarshal(riskRaw, &riskParsed)
		riskStatus = riskResp.StatusCode
	}
	riskOK := riskErr == nil && riskStatus < 400
	level, score = extractRiskResult(riskParsed)

	eventUser, _ := riskBody["event"].(map[string]interface{})["user"].(map[string]interface{})
	userType, _ := eventUser["type"].(string)
	eventIP, _ := riskBody["event"].(map[string]interface{})["ip"].(string)

	var riskDetail string
	if riskStep == "7b" {
		riskDetail = fmt.Sprintf(
			`<strong>This evaluation is intentionally constructed to trigger a HIGH risk score.</strong><br><br>`+
				`The IP <code>%s</code> is a known Tor exit node. Tor is an anonymizing network commonly associated with `+
				`attempts to obscure origin and bypass geo-controls. PingOne Protect's <strong>Anonymous Network Detection</strong> `+
				`predictor recognizes this IP and scores it at <strong>80</strong> — above the policy set's HIGH threshold of 75 — `+
				`causing the overall evaluation to return HIGH.<br><br>`+
				`<code>user.type</code> is set to <code>ANONYMOUS</code> and a bot-like user agent is supplied to further reflect `+
				`what a real suspicious M2M caller might look like. In production you would populate these fields from `+
				`the actual upstream caller rather than hardcoding them.<br><br>`+
				`SDK signals are omitted — there is no browser SDK in an M2M flow.<br>`+
				`HTTP %d &middot; level: <code>%s</code> &middot; score: <code>%s</code>`,
			template.HTMLEscapeString(eventIP),
			riskStatus,
			template.HTMLEscapeString(level),
			template.HTMLEscapeString(score),
		)
	} else {
		riskDetail = fmt.Sprintf(
			`Event: ip=<code>%s</code>, user.type=<code>%s</code>.<br>`+
				`PingOne Protect scores the event against the configured risk policy set and returns a risk level (LOW / MEDIUM / HIGH) plus per-predictor details.<br>`+
				`SDK signals are intentionally omitted — there is no browser SDK in an M2M flow.<br>`+
				`HTTP %d &middot; level: <code>%s</code> &middot; score: <code>%s</code>`,
			template.HTMLEscapeString(eventIP),
			template.HTMLEscapeString(userType),
			riskStatus,
			template.HTMLEscapeString(level),
			template.HTMLEscapeString(score),
		)
	}

	cards = append(cards, card{
		Title:  fmt.Sprintf("%s. PingOne Protect risk evaluation", riskStep),
		OK:     riskOK,
		URL:    "POST " + riskURL,
		Detail: template.HTML(riskDetail),
		Body:   fmt.Sprintf("request:\n%s\n\nresponse:\n%s", prettyAny(riskBody), prettyJSONOrRaw(riskRaw)),
	})

	if !riskOK {
		cards = append(cards, card{
			Title:  fmt.Sprintf("%s. Call PingOne Management API", mgmtStep),
			OK:     false,
			URL:    "GET " + mgmtURL,
			Detail: "Skipped — the risk evaluation step did not succeed.",
		})
		return
	}

	if strings.EqualFold(level, "HIGH") {
		// High-risk callers are blocked. The management API is never called.
		// In a production system this is where you would log the event,
		// trigger an alert, or require step-up authentication.
		cards = append(cards, card{
			Title: fmt.Sprintf("%s. Call PingOne Management API", mgmtStep),
			OK:    false,
			URL:   "GET " + mgmtURL,
			Detail: template.HTML(fmt.Sprintf(
				`<strong>Blocked.</strong> PingOne Protect returned risk level <code>%s</code> (score: <code>%s</code>). `+
					`Anonymous Network Detection flagged the IP as a known Tor exit node. `+
					`The downstream management API call was <strong>not</strong> made.`,
				template.HTMLEscapeString(level),
				template.HTMLEscapeString(score),
			)),
		})
		return
	}

	// Low/medium risk: proceed with the management API call.
	// The same access token obtained via client_credentials is sent as a
	// Bearer token. The PingOne management API validates the token's signature,
	// expiry, and scopes before processing the request.
	mgmtReq, _ := http.NewRequest("GET", mgmtURL, nil)
	mgmtReq.Header.Set("Authorization", "Bearer "+accessToken)
	mgmtResp, mgmtErr := http.DefaultClient.Do(mgmtReq)
	var mgmtRaw []byte
	mgmtStatus := 0
	if mgmtErr == nil {
		defer mgmtResp.Body.Close()
		mgmtRaw, _ = io.ReadAll(mgmtResp.Body)
		mgmtStatus = mgmtResp.StatusCode
	}
	cards = append(cards, card{
		Title: fmt.Sprintf("%s. Call PingOne Management API", mgmtStep),
		OK:    mgmtErr == nil && mgmtStatus < 400,
		URL:   "GET " + mgmtURL,
		Detail: template.HTML(fmt.Sprintf(
			`Risk level <code>%s</code> — proceeding. The access token is sent as a Bearer token.<br>HTTP %d`,
			template.HTMLEscapeString(level),
			mgmtStatus,
		)),
		Body: prettyJSONOrRaw(mgmtRaw),
	})
	return
}

// callerIP returns the IP address of the HTTP request originator.
//
// In an M2M context this IP represents the machine (or service) making the
// request rather than a human user's browser. It is forwarded to PingOne
// Protect as the event IP so Protect can apply network-based predictors such
// as Anonymous Network Detection (Tor/VPN/proxy detection) and velocity checks.
//
// X-Forwarded-For is checked first because in cloud deployments the app sits
// behind a load balancer or reverse proxy that rewrites RemoteAddr to its own
// IP. The first entry in X-Forwarded-For is the original client IP.
func callerIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "::1" {
		return "127.0.0.1"
	}
	return host
}

// extractRiskResult pulls the risk level and score out of a PingOne Protect
// riskEvaluations response.
//
// The response body has the shape:
//
//	{ "result": { "level": "LOW", "score": 12, ... }, "details": { ... } }
//
// result.level is the overall verdict: LOW, MEDIUM, or HIGH. result.score is
// the combined numeric score (0–100) from all active predictors. The details
// object contains per-predictor scores and can be used to understand which
// predictor drove the final verdict.
func extractRiskResult(parsed map[string]interface{}) (level, score string) {
	level = "n/a"
	score = "n/a"
	res, _ := parsed["result"].(map[string]interface{})
	if res == nil {
		return
	}
	if l, ok := res["level"].(string); ok && l != "" {
		level = l
	}
	if s, ok := res["score"].(float64); ok {
		score = fmt.Sprintf("%v", s)
	} else if s, ok := res["score"].(string); ok && s != "" {
		score = s
	}
	return
}

// --- claim validation ---

// validateAccessClaims verifies the standard claims that must be present and
// valid in any access token returned by PingOne for a client_credentials grant.
//
// Why client_id instead of sub?
// In PingOne Worker app tokens there is no authenticated user, so the "sub"
// (subject) claim is absent. Instead PingOne puts the client's own ID in the
// "client_id" claim. Always check this claim when validating M2M tokens —
// checking "sub" would silently pass because the claim is simply missing.
func validateAccessClaims(claims map[string]interface{}, expectedIssuer, expectedClientID string) map[string]string {
	errs := map[string]string{}
	if iss, _ := claims["iss"].(string); iss != expectedIssuer {
		errs["iss"] = fmt.Sprintf("got %q, want %q", iss, expectedIssuer)
	}
	// PingOne Worker app tokens put the client ID in "client_id", not "sub" (sub is absent).
	if cid, _ := claims["client_id"].(string); cid != expectedClientID {
		errs["client_id"] = fmt.Sprintf("got %q, want %q", cid, expectedClientID)
	}
	now := time.Now().Unix()
	if exp, ok := numericClaim(claims["exp"]); ok {
		if exp < now {
			errs["exp"] = fmt.Sprintf("expired (exp=%d, now=%d)", exp, now)
		}
	} else {
		errs["exp"] = "missing or non-numeric"
	}
	if iat, ok := numericClaim(claims["iat"]); ok {
		if iat > now+60 {
			errs["iat"] = fmt.Sprintf("in the future (iat=%d, now=%d)", iat, now)
		}
	}
	return errs
}

// --- helpers ---

// card is the data structure for each step displayed in the results UI.
//
// Divider is a special flag: when true the card renders as a section header
// (dark-red background) rather than an individual step result. This is used
// to visually separate the "User A" and "User B" blocks in the output.
// Collapsed controls whether the response body <details> element starts open
// or closed — set it on verbose responses (e.g. the JWKS) to keep the page
// readable without hiding the data.
type card struct {
	Title     string
	OK        bool
	URL       string
	Detail    template.HTML
	Body      string
	Collapsed bool
	Divider   bool // if true, renders as a section header, not a result card
}

func render(w http.ResponseWriter, title, bodyHTML string) {
	t, err := template.New("page").Parse(pageHTML)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	t.Execute(w, struct {
		Title string
		Body  template.HTML
	}{Title: title, Body: template.HTML(bodyHTML)})
}

func renderCards(cards []card) string {
	t, err := template.New("cards").Parse(cardsHTML)
	if err != nil {
		return err.Error()
	}
	var sb strings.Builder
	if err := t.Execute(&sb, cards); err != nil {
		return err.Error()
	}
	return sb.String()
}

func renderClaimChecks(errs map[string]string) template.HTML {
	if len(errs) == 0 {
		return "<span style=\"color:#0a7a0a;\">All claims valid.</span>"
	}
	var sb strings.Builder
	sb.WriteString(`<ul style="color:#b00020;">`)
	for k, v := range errs {
		sb.WriteString("<li><code>" + template.HTMLEscapeString(k) + "</code>: " + template.HTMLEscapeString(v) + "</li>")
	}
	sb.WriteString("</ul>")
	return template.HTML(sb.String())
}

func ifThenElse(cond bool, a, b interface{}) template.HTML {
	if cond {
		return template.HTML(fmt.Sprint(a))
	}
	return template.HTML(fmt.Sprint(b))
}

func prettyAny(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func prettyJSONOrRaw(raw []byte) string {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	return prettyAny(v)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// --- JWT/JWS verification (RS256 only) ---

// decodeJWT splits a JWT string into its three base64url-encoded parts and
// decodes the header and payload JSON objects.
//
// A JWT is structured as base64url(header) + "." + base64url(payload) + "." +
// base64url(signature). The header and payload are JSON objects; the signature
// is raw bytes. This function does not verify the signature — call verifyJWS
// separately after fetching the JWKS.
func decodeJWT(token string) (header, payload map[string]interface{}, sigPresent bool, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, false, fmt.Errorf("not a 3-part JWT: %d parts", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, false, fmt.Errorf("decode header: %w", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, false, fmt.Errorf("decode payload: %w", err)
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, false, fmt.Errorf("parse header: %w", err)
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, nil, false, fmt.Errorf("parse payload: %w", err)
	}
	return header, payload, parts[2] != "", nil
}

// verifyJWS validates the RS256 signature of a JWT against a JWKS.
//
// The verification process:
//  1. Read the "kid" (key ID) from the JWT header.
//  2. Find the matching public key in the JWKS (matched by kid).
//  3. Reconstruct the signed input: "{base64url(header)}.{base64url(payload)}".
//  4. SHA-256 hash the signed input.
//  5. Verify the hash against the signature using the RSA public key.
//
// If the signature does not match it means either the token was tampered with
// or it was signed by a different key. In either case the token must be rejected.
func verifyJWS(token string, header map[string]interface{}, jwks map[string]interface{}) error {
	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)
	if alg != "RS256" {
		return fmt.Errorf("unsupported alg %q (this sample verifies RS256 only)", alg)
	}
	keys, _ := jwks["keys"].([]interface{})
	var match map[string]interface{}
	for _, k := range keys {
		km, _ := k.(map[string]interface{})
		if id, _ := km["kid"].(string); id == kid {
			match = km
			break
		}
	}
	if match == nil {
		return fmt.Errorf("no JWK with kid=%q", kid)
	}
	pub, err := jwkToRSAPublicKey(match)
	if err != nil {
		return err
	}

	parts := strings.Split(token, ".")
	signedInput := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	digest := sha256.Sum256(signedInput)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// jwkToRSAPublicKey converts a JWK (JSON Web Key) object into a Go
// *rsa.PublicKey that can be passed to rsa.VerifyPKCS1v15.
//
// An RSA JWK has two components:
//   - "n": the modulus (base64url-encoded big-endian bytes)
//   - "e": the public exponent (base64url-encoded big-endian bytes)
//
// Both are decoded from base64url, then interpreted as unsigned big-endian
// integers to construct the RSA public key.
func jwkToRSAPublicKey(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	if kty != "RSA" {
		return nil, fmt.Errorf("unsupported kty %q (RSA only)", kty)
	}
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	var ePadded [8]byte
	copy(ePadded[8-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint64(ePadded[:]))
	n := new(big.Int).SetBytes(nBytes)
	return &rsa.PublicKey{N: n, E: e}, nil
}

// numericClaim safely extracts an integer from a JSON-decoded claim value.
// JSON numbers unmarshal as float64 in Go, but claims like exp and iat are
// logically integers. This helper handles float64, int64, and int.
func numericClaim(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

// --- HTML templates ---

const pageHTML = `
<!DOCTYPE html>
<html>
<head>
<title>{{.Title}}</title>
<style>
  body{font-family:sans-serif; margin:0; background:#f5f5f5;}
  h2{margin-top:0;}
  button{font-size:16px; padding:10px 20px; cursor:pointer; background:#E1003B; color:#fff; border:none; border-radius:4px;}
  pre{background:#f4f4f4; padding:12px; border-left:3px solid #888; white-space:pre-wrap; word-break:break-all; margin:0;}
  code{background:#f0f0f0; padding:1px 4px; border-radius:2px;}
  .card{margin-top:18px; padding:14px 16px; border:1px solid #ddd; border-radius:4px; background:#fff;}
  .card h3{margin:0 0 6px 0;}
  .ok{color:#0a7a0a;}
  .err{color:#b00020;}
  .url{font-family:monospace; font-size:13px; color:#555; background:#f0f0f0; padding:4px 8px; border-radius:3px; display:block; margin:6px 0; word-break:break-all;}
  details{margin-top:6px;}
  summary{cursor:pointer; font-size:13px; color:#444; user-select:none; padding:2px 0;}
  details pre{margin-top:4px;}
  .divider{margin-top:30px; margin-bottom:4px; padding:8px 14px; background:#B8002F; color:#fff; border-radius:4px; font-weight:600; font-size:15px;}
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px;max-width:980px;margin:0 auto;">
{{.Body}}
</div>
</body>
</html>`

const cardsHTML = `{{range .}}
{{if .Divider}}
<div class="divider">{{.Title}}</div>
{{else}}
<div class="card">
  <h3 class="{{if .OK}}ok{{else}}err{{end}}">{{.Title}} {{if .OK}}(ok){{else}}(failed){{end}}</h3>
  {{if .URL}}<div class="url">{{.URL}}</div>{{end}}
  {{if .Detail}}<div>{{.Detail}}</div>{{end}}
  {{if .Body}}{{if .Collapsed}}<details><summary>Show response</summary><pre>{{.Body}}</pre></details>{{else}}<details open><summary>Hide</summary><pre>{{.Body}}</pre></details>{{end}}{{end}}
</div>
{{end}}
{{end}}`
