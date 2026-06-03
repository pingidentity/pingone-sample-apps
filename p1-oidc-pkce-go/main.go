// Package main implements an OIDC Authorization Code flow with PKCE (Proof Key
// for Code Exchange) against PingOne.
//
// # Why PKCE?
//
// The standard OAuth 2.0 authorization_code flow is vulnerable to authorization
// code interception: a malicious app on the same device can register for the same
// redirect URI and steal the code before your app redeems it. PKCE (RFC 7636)
// closes this gap. Before redirecting the user to the authorization server, the
// client generates a random secret called the code_verifier and sends a one-way
// hash of it (the code_challenge) in the authorization request. The server stores
// the hash. When the client later presents the code at the token endpoint it must
// also send the original verifier. The server re-hashes it and compares — only the
// app that generated the verifier can complete the exchange.
//
// PKCE is especially important for public clients (native/SPA apps) that cannot
// keep a client_secret, but it is also recommended for confidential clients. This
// sample demonstrates a confidential client: the token endpoint is called with
// BOTH HTTP Basic authentication (client_id + client_secret) AND the PKCE
// code_verifier.
//
// # Nine-step flow this sample walks through:
//
//  1. Generate code_verifier (RFC 7636 §4.1: 43-128 unreserved chars)
//  2. Compute code_challenge = base64url-no-pad(SHA-256(ASCII(code_verifier)))
//  3. Generate state (CSRF protection) and nonce (ID token replay protection)
//  4. Build GET /as/authorize URL carrying code_challenge + code_challenge_method=S256
//  5. Receive callback — PingOne 302s back with ?code=...&state=...
//  6. Validate state — abort if mismatch (CSRF check)
//  7. POST /as/token — exchange code for tokens, sending code_verifier + HTTP Basic
//  8. Decode + verify ID token (RS256 signature against JWKS)
//  9. Call GET /as/userinfo with the access token
//
// Prerequisites in PingOne:
//   - An OIDC Web App with: response_type=code, grant_type=authorization_code,
//     Token Endpoint Auth Method = CLIENT_SECRET_BASIC,
//     PKCE Enforcement = REQUIRED, redirect URI = PINGONE_REDIRECT_URI.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha256" // registers SHA-256 with crypto.SHA256.New
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
	"sync"
	"time"

	"github.com/joho/godotenv"
)

//go:embed logo.png
var logoPNG []byte

var (
	envID        string
	clientID     string
	clientSecret string
	authPath     string
	redirectURI  string
	scopes       string
)

// sessionState holds the PKCE artifacts and tokens that must survive the browser
// redirect to PingOne and back. Because the redirect leaves the app's process
// (the user's browser navigates away), this state cannot live in a function-local
// variable — it must be persisted server-side and correlated to the browser via
// the "sid" cookie.
//
// Verifier / Challenge — the RFC 7636 secret pair. The verifier never leaves the
// server; only the challenge is sent to the authorization endpoint. On callback
// the verifier is sent to the token endpoint so PingOne can re-derive and compare
// the challenge.
//
// State — a random string included in the /authorize URL and echoed back in the
// callback query string. Comparing the echoed value to the stored value proves the
// callback originated from a redirect we initiated (CSRF protection).
//
// Nonce — a random string included in the /authorize request and embedded by
// PingOne as a claim in the ID token. Comparing it to the stored value proves the
// ID token was minted for this specific login attempt (replay protection).
//
// AccessToken / IDToken / RefreshToken — stored after the token exchange so the
// /refresh handler can use the refresh_token without re-running the full flow.
type sessionState struct {
	Verifier     string
	Challenge    string
	State        string
	Nonce        string
	AccessToken  string
	IDToken      string
	RefreshToken string
	IDClaims     map[string]interface{}
}

// sessions is a single-process in-memory session store keyed by an opaque "sid"
// cookie value. A sync.Mutex protects concurrent map access from parallel requests.
// Production apps should use a distributed store (Redis, database) instead.
var sessions = struct {
	sync.Mutex
	m map[string]*sessionState
}{m: map[string]*sessionState{}}

// getSession looks up the current session from the "sid" cookie. Returns the
// empty string and nil if no session exists or the cookie is absent.
func getSession(r *http.Request) (string, *sessionState) {
	c, err := r.Cookie("sid")
	if err == nil {
		sessions.Lock()
		s := sessions.m[c.Value]
		sessions.Unlock()
		if s != nil {
			return c.Value, s
		}
	}
	return "", nil
}

// newSession creates a fresh session, stores it, and sets the "sid" cookie on the
// response. HttpOnly prevents JavaScript from reading the cookie value; SameSite=Lax
// allows the cookie to be sent on top-level navigations (like the PingOne callback
// redirect) while blocking it on third-party sub-requests.
func newSession(w http.ResponseWriter) (string, *sessionState) {
	sid := randomHex(16)
	s := &sessionState{}
	sessions.Lock()
	sessions.m[sid] = s
	sessions.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return sid, s
}

// main loads configuration from the environment and registers the four HTTP
// handlers that drive the PKCE flow:
//
//   - GET  /          — landing page with "Begin Login" button
//   - POST /prepare   — generates PKCE artifacts, builds authorize URL, shows step 1
//   - GET  /callback  — receives the authorization code from PingOne, exchanges it
//   - POST /refresh   — uses a stored refresh_token to obtain a new access_token
func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Falling back to system environment variables.")
	}

	envID = os.Getenv("PINGONE_ENV_ID")
	clientID = os.Getenv("PINGONE_CLIENT_ID")
	clientSecret = os.Getenv("PINGONE_CLIENT_SECRET")
	authPath = strings.TrimRight(os.Getenv("PINGONE_AUTH_PATH"), "/")
	redirectURI = os.Getenv("PINGONE_REDIRECT_URI")
	scopes = os.Getenv("PINGONE_SCOPES")

	if envID == "" || clientID == "" || clientSecret == "" || authPath == "" || redirectURI == "" || scopes == "" {
		log.Fatal("Missing required environment variables. Please check your .env file.")
	}

	http.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(logoPNG)
	})
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/prepare", handlePrepare)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/refresh", handleRefresh)

	fmt.Println("OIDC Auth Code + PKCE demo on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

// --- HTTP handlers ---

func handleIndex(w http.ResponseWriter, _ *http.Request) {
	render(w, "OIDC Auth Code + PKCE — start", `
<h2>OIDC Authorization Code + PKCE (confidential client)</h2>
<p>This sample walks through every artifact in the OIDC Authorization Code flow with PKCE so you can see exactly what each value is, how it's derived, and how it's validated.</p>
<p>The client is <strong>confidential</strong> — the token endpoint is called with HTTP Basic auth (client ID + secret) AND the PKCE <code>code_verifier</code>.</p>
<form action="/prepare" method="POST"><button type="submit">Begin Login</button></form>
<p style="color:#666;font-size:13px;margin-top:30px;">PingOne config required: OIDC Web App with PKCE Enforcement = REQUIRED, Token Endpoint Auth Method = Client Secret Basic, redirect URI = `+template.HTMLEscapeString(redirectURI)+`</p>
`)
}

// handlePrepare generates all PKCE artifacts, stores them in the session, builds
// the /authorize URL, and presents step-by-step cards so the developer can inspect
// each value before clicking through to PingOne.
//
// Steps performed:
//  1. Generate code_verifier — 32 cryptographically random bytes, base64url-no-pad
//     encoded. This yields a 43-character string that satisfies RFC 7636 §4.1's
//     requirement of 43-128 characters from the unreserved set [A-Za-z0-9-._~].
//     base64url output naturally falls within that set, so no filtering is needed.
//  2. Compute code_challenge = base64url-no-pad(SHA-256(ASCII(code_verifier))).
//     The method S256 (uppercase) must be sent as the code_challenge_method parameter.
//     Never use "plain" — it provides no security benefit over no PKCE at all.
//  3. Generate state and nonce — independent random hex strings. State goes in the
//     authorize URL and is echoed back in the callback; nonce goes in the authorize
//     URL and is embedded in the ID token as a claim.
//  4. Build the authorize URL with all required parameters.
func handlePrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	_, s := newSession(w)

	// 1. code_verifier — RFC 7636: 43-128 chars from unreserved set [A-Z a-z 0-9 - . _ ~].
	// base64url-no-pad of 32 random bytes yields 43 chars that fall entirely within the unreserved set.
	verifierBytes := randomBytes(32)
	s.Verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// 2. code_challenge = base64url-nopad( SHA-256( ASCII(code_verifier) ) )
	// RawURLEncoding omits the "=" padding characters that standard base64 adds.
	// Padding is forbidden by RFC 7636; sending a padded value will cause PingOne
	// to reject the token exchange with an "invalid_grant" error.
	hash := sha256.Sum256([]byte(s.Verifier))
	s.Challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	// 3. state + nonce — independent random values for CSRF and replay protection.
	s.State = randomHex(16)
	s.Nonce = randomHex(16)

	// 4. Build the /authorize URL.
	// Every parameter must be percent-encoded to survive the redirect. code_challenge_method
	// is the literal string "S256" — the "S" must be uppercase; "s256" is not valid.
	authorizeURL := fmt.Sprintf(
		"%s/%s/as/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=S256",
		authPath, envID,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scopes),
		url.QueryEscape(s.State),
		url.QueryEscape(s.Nonce),
		url.QueryEscape(s.Challenge),
	)

	cards := []card{
		{
			Title: "1. Generate code_verifier",
			OK:    true,
			Detail: template.HTML(fmt.Sprintf(
				"Random %d bytes → <code>base64url</code>-no-pad → %d-char verifier. RFC 7636 §4.1 allows 43-128 chars from the unreserved set <code>[A-Za-z0-9-._~]</code>; base64url output naturally falls in that set.",
				len(verifierBytes), len(s.Verifier),
			)),
			Body: s.Verifier,
		},
		{
			Title: "2. Compute code_challenge",
			OK:    true,
			Detail: template.HTML(
				"<code>code_challenge = base64url-no-pad( SHA-256( ASCII(code_verifier) ) )</code><br>" +
					"<code>code_challenge_method = S256</code>",
			),
			Body: fmt.Sprintf(
				"SHA-256 digest (hex):\n  %s\n\nbase64url-no-pad encoding:\n  %s",
				hex.EncodeToString(hash[:]),
				s.Challenge,
			),
		},
		{
			Title:  "3. Generate state and nonce",
			OK:     true,
			Detail: "Both are random opaque strings: <code>state</code> defends the callback from CSRF; <code>nonce</code> is echoed back as a claim in the ID token to defend against replay.",
			Body:   fmt.Sprintf("state: %s\nnonce: %s", s.State, s.Nonce),
		},
		{
			Title:  "4. Build /authorize URL",
			OK:     true,
			URL:    "GET " + authorizeURL,
			Detail: "Click the button below to redirect to PingOne. After you authenticate, PingOne will 302 back to <code>" + template.HTML(template.HTMLEscapeString(redirectURI)) + "</code> with a <code>code</code> and the original <code>state</code>.",
		},
	}

	body := renderCards(cards) + fmt.Sprintf(
		`<p><a href="%s"><button>Continue to PingOne →</button></a></p>`,
		template.HTMLEscapeString(authorizeURL),
	)
	render(w, "Step 1 — Prepare PKCE artifacts", body)
}

// handleCallback is the OAuth 2.0 redirect URI handler. PingOne calls this after
// the user authenticates, appending ?code=...&state=... to the URL.
//
// Steps performed:
//  1. Read the "code" and "state" query parameters from the redirect.
//  2. Validate state — compare the echoed state to the stored value. A mismatch
//     means the request was not initiated by this app (possible CSRF attack).
//     Abort immediately if they don't match; never proceed to token exchange.
//  3. Exchange the code for tokens — POST to /as/token with the code_verifier.
//     The verifier is sent alongside HTTP Basic auth (client_id + client_secret)
//     because this is a confidential client. PingOne re-hashes the verifier with
//     SHA-256 and verifies it matches the code_challenge stored from step 4.
//     The redirect_uri must exactly match the value sent in the /authorize request
//     and the URI registered on the PingOne application — all three must agree.
//  4. Decode the ID token — split on ".", base64url-decode each segment.
//  5. Fetch the JWKS — public keys published by PingOne for signature verification.
//  6. Verify the ID token signature against the JWKS (RS256).
//  7. Validate ID token claims: iss, aud, exp, iat, nonce.
//  8. Call /userinfo with the access token.
//  9. Display final tokens.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	_, s := getSession(r)
	if s == nil {
		render(w, "Callback — error", `<p class="err">No session found. Cookies may have been blocked. <a href="/">Start over</a>.</p>`)
		return
	}

	cards := []card{}

	q := r.URL.Query()
	gotCode := q.Get("code")
	gotState := q.Get("state")
	gotErr := q.Get("error")

	if gotErr != "" {
		cards = append(cards, card{
			Title:  "Callback received an error",
			OK:     false,
			Detail: template.HTML(fmt.Sprintf("<code>error=%s</code><br><code>error_description=%s</code>", template.HTMLEscapeString(gotErr), template.HTMLEscapeString(q.Get("error_description")))),
			Body:   r.URL.RawQuery,
		})
		render(w, "Callback — error", renderCards(cards)+`<p><a href="/">Start over</a></p>`)
		return
	}

	// Card 1: Receive callback. The authorization code is single-use and typically
	// expires within minutes — do not cache it or allow it to sit idle.
	cards = append(cards, card{
		Title:  "1. Receive callback",
		OK:     true,
		URL:    "GET " + redirectURI + "?" + r.URL.RawQuery,
		Detail: "PingOne redirected the browser back with <code>code</code> and <code>state</code>. The <code>code</code> is single-use and short-lived.",
		Body:   fmt.Sprintf("code:  %s\nstate: %s", gotCode, gotState),
	})

	// Card 2: State validation — defends against CSRF.
	// If state does not match the value we stored in handlePrepare, someone may be
	// replaying an old callback or initiating a cross-site request. Abort.
	stateOK := gotState == s.State
	cards = append(cards, card{
		Title: "2. Validate state",
		OK:    stateOK,
		Detail: template.HTML(fmt.Sprintf(
			"Stored state: <code>%s</code><br>Returned state: <code>%s</code><br>%s",
			template.HTMLEscapeString(s.State),
			template.HTMLEscapeString(gotState),
			ifThenElse(stateOK, "Match — request is authentic.", "<strong>Mismatch — abort.</strong>"),
		)),
	})
	if !stateOK {
		render(w, "Callback — state mismatch", renderCards(cards)+`<p><a href="/">Start over</a></p>`)
		return
	}

	// Card 3: Token exchange — confidential client sends HTTP Basic + code_verifier.
	// PingOne verifies:
	//   - The code is valid and not yet used.
	//   - The redirect_uri matches the one sent in /authorize and the registered value.
	//   - SHA-256(code_verifier) == code_challenge stored from the authorize request.
	// On success PingOne issues access_token, id_token, and (if offline_access scope
	// was requested) refresh_token.
	tokenURL := fmt.Sprintf("%s/%s/as/token", authPath, envID)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", gotCode)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", s.Verifier)

	basic := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))

	tokReq, _ := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// HTTP Basic authentication encodes "client_id:client_secret" in base64 and
	// sends it as "Authorization: Basic <base64>". This is CLIENT_SECRET_BASIC
	// in OIDC terminology — it must match the Token Endpoint Auth Method set on the
	// PingOne application.
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

	cards = append(cards, card{
		Title: "3. Exchange code for tokens",
		OK:    tokErr == nil && tokStatus < 400,
		URL:   "POST " + tokenURL,
		Detail: template.HTML(fmt.Sprintf(
			`Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>Form body:<br>&nbsp;&nbsp;<code>grant_type=authorization_code</code><br>&nbsp;&nbsp;<code>code=%s</code><br>&nbsp;&nbsp;<code>redirect_uri=%s</code><br>&nbsp;&nbsp;<strong><code>code_verifier=%s</code></strong> ← PingOne re-hashes this and compares to the original code_challenge<br>HTTP %d`,
			template.HTMLEscapeString(gotCode),
			template.HTMLEscapeString(redirectURI),
			template.HTMLEscapeString(s.Verifier),
			tokStatus,
		)),
		Body: prettyJSONOrRaw(tokRaw),
	})
	if tokErr != nil || tokStatus >= 400 {
		render(w, "Callback — token exchange failed", renderCards(cards)+`<p><a href="/">Start over</a></p>`)
		return
	}

	idToken, _ := tokParsed["id_token"].(string)
	accessToken, _ := tokParsed["access_token"].(string)
	refreshToken, _ := tokParsed["refresh_token"].(string)
	s.AccessToken = accessToken
	s.IDToken = idToken
	s.RefreshToken = refreshToken

	// Card 4: Decode ID token (header + payload). Signature verification is the next step.
	// A JWT is three base64url-encoded segments joined by dots: header.payload.signature.
	// Do NOT trust any claims from the payload until the signature has been verified.
	header, payload, sigOK, decodeErr := decodeJWT(idToken)
	cards = append(cards, card{
		Title:  "4. Decode ID token",
		OK:     decodeErr == nil,
		Detail: "An ID token is a JWS: three base64url segments separated by dots. The header tells us which key to use; the payload contains the claims; the signature must be verified before any claim is trusted.",
		Body:   fmt.Sprintf("header:\n%s\n\npayload:\n%s", prettyAny(header), prettyAny(payload)),
	})
	_ = sigOK

	// Card 5: Fetch JWKS — the public keys PingOne uses to sign ID tokens.
	// In production, cache this response (respect Cache-Control / Expires headers)
	// to avoid fetching on every login. Bust the cache and retry if a kid is not found.
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
		Title:     "5. Fetch JWKS",
		OK:        jwksErr == nil,
		URL:       "GET " + jwksURL,
		Detail:    "Public keys used to verify ID token signatures. Keyed by <code>kid</code>; cache with care in production.",
		Body:      prettyJSONOrRaw(jwksRaw),
		Collapsed: true,
	})

	// Card 6: Verify ID token signature (RS256).
	// The header's "kid" field identifies which JWK in the JWKS to use.
	// verifyJWS reconstructs the signing input (header + "." + payload, as raw
	// base64url strings), decodes the JWK into an RSA public key, and verifies
	// the PKCS#1 v1.5 signature.
	verifyErr := verifyJWS(idToken, header, jwks)
	cards = append(cards, card{
		Title: "6. Verify ID token signature",
		OK:    verifyErr == nil,
		Detail: template.HTML(fmt.Sprintf(
			"alg: <code>%v</code>, kid: <code>%v</code><br>%s",
			header["alg"], header["kid"],
			ifThenElse(verifyErr == nil, "Signature valid (RS256, key matched by <code>kid</code>).", template.HTMLEscapeString("Signature INVALID: "+errString(verifyErr))),
		)),
	})

	// Card 7: Validate ID token claims per OIDC Core §3.1.3.7.
	// Required checks:
	//   iss  — must equal {authPath}/{envID}/as (the issuer of this PingOne environment)
	//   aud  — must contain our client_id (or the token is for a different app)
	//   exp  — must be in the future (token is not expired)
	//   iat  — must not be in the future (clock skew guard; 60 s tolerance)
	//   nonce — must match the value we stored in handlePrepare (replay guard)
	expectedIssuer := fmt.Sprintf("%s/%s/as", authPath, envID)
	claimsErrs := validateIDClaims(payload, expectedIssuer, clientID, s.Nonce)
	cards = append(cards, card{
		Title: "7. Validate ID token claims",
		OK:    len(claimsErrs) == 0,
		Detail: template.HTML(fmt.Sprintf(
			"Required checks: <code>iss</code> matches <code>%s</code>, <code>aud</code> contains <code>%s</code>, <code>exp</code> &gt; now, <code>iat</code> not in the future, <code>nonce</code> matches the value sent on /authorize.<br>%s",
			template.HTMLEscapeString(expectedIssuer),
			template.HTMLEscapeString(clientID),
			renderClaimChecks(claimsErrs),
		)),
		Body: prettyAny(payload),
	})
	s.IDClaims = payload

	// Card 8: /userinfo — fetch profile claims for the authenticated user.
	// The access token is sent as a Bearer token in the Authorization header.
	// The response is a JSON object with the same sub as the ID token, plus
	// whatever profile scopes were requested (email, profile, etc.).
	userinfoURL := fmt.Sprintf("%s/%s/as/userinfo", authPath, envID)
	uiReq, _ := http.NewRequest("GET", userinfoURL, nil)
	uiReq.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp, uiErr := http.DefaultClient.Do(uiReq)
	var uiRaw []byte
	uiStatus := 0
	if uiErr == nil {
		defer uiResp.Body.Close()
		uiRaw, _ = io.ReadAll(uiResp.Body)
		uiStatus = uiResp.StatusCode
	}
	cards = append(cards, card{
		Title:  "8. Call /userinfo",
		OK:     uiErr == nil && uiStatus < 400,
		URL:    "GET " + userinfoURL,
		Detail: template.HTML(fmt.Sprintf("Header: <code>Authorization: Bearer &lt;access_token&gt;</code><br>HTTP %d", uiStatus)),
		Body:   prettyJSONOrRaw(uiRaw),
	})

	// Card 9: Final tokens — collapsed by default because the raw token strings
	// are long and of limited value to display prominently.
	cards = append(cards, card{
		Title:     "9. Tokens",
		OK:        true,
		Detail:    "These are the final values returned by the token endpoint.",
		Body:      fmt.Sprintf("access_token:\n%s\n\nid_token:\n%s\n\nrefresh_token:\n%s", accessToken, idToken, refreshToken),
		Collapsed: true,
	})

	body := renderCards(cards)
	if refreshToken != "" {
		body += `<form action="/refresh" method="POST"><button type="submit">Use refresh token →</button></form>`
	}
	body += `<p style="margin-top:20px;"><a href="/">Start over</a></p>`
	render(w, "Callback — complete", body)
}

// handleRefresh uses the refresh_token stored in the session to obtain a new
// access_token from PingOne without requiring the user to re-authenticate.
//
// The refresh_token grant does NOT re-play PKCE — PKCE only applies to the
// authorization_code exchange. Client authentication here is HTTP Basic only.
//
// PingOne typically rotates the refresh_token on every use (issues a new one and
// invalidates the old). The handler stores the new refresh_token back to the
// session so the next refresh still works.
func handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_, s := getSession(r)
	if s == nil || s.RefreshToken == "" {
		render(w, "Refresh — error", `<p class="err">No refresh token in session. <a href="/">Start over</a>.</p>`)
		return
	}

	tokenURL := fmt.Sprintf("%s/%s/as/token", authPath, envID)
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", s.RefreshToken)

	basic := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req, _ := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+basic)

	resp, err := http.DefaultClient.Do(req)
	var raw []byte
	var parsed map[string]interface{}
	status := 0
	if err == nil {
		defer resp.Body.Close()
		raw, _ = io.ReadAll(resp.Body)
		_ = json.Unmarshal(raw, &parsed)
		status = resp.StatusCode
	}

	cards := []card{
		{
			Title: "Refresh access token",
			OK:    err == nil && status < 400,
			URL:   "POST " + tokenURL,
			Detail: template.HTML(fmt.Sprintf(
				`Headers:<br>&nbsp;&nbsp;<code>Authorization: Basic base64(client_id:client_secret)</code><br>&nbsp;&nbsp;<code>Content-Type: application/x-www-form-urlencoded</code><br>Form body:<br>&nbsp;&nbsp;<code>grant_type=refresh_token</code><br>&nbsp;&nbsp;<code>refresh_token=&lt;previous refresh_token&gt;</code><br>HTTP %d<br>Note: PKCE is not re-played here; the refresh grant authenticates only via client credentials. PingOne typically rotates the refresh_token on each use — store the new one.`,
				status,
			)),
			Body: prettyJSONOrRaw(raw),
		},
	}

	// Store the rotated tokens so subsequent refreshes still work.
	if err == nil && status < 400 {
		if newAccess, ok := parsed["access_token"].(string); ok {
			s.AccessToken = newAccess
		}
		if newID, ok := parsed["id_token"].(string); ok {
			s.IDToken = newID
		}
		if newRefresh, ok := parsed["refresh_token"].(string); ok {
			s.RefreshToken = newRefresh
		}
	}

	render(w, "Refresh — result", renderCards(cards)+`<p><a href="/">Start over</a></p>`)
}

// --- Helpers ---

// card is the display model for a single step in the PKCE walkthrough. Each card
// maps to one HTTP request or validation step and is rendered as a bordered panel.
//
// OK / Title — shown as a green (ok) or red (failed) heading.
// URL — the full request line (e.g. "POST https://..."), shown in a monospace badge.
// Detail — trusted HTML explaining what happened and why (protocol details, values).
// Body — raw text response body, HTML-escaped before display inside a <pre> block.
// Collapsed — when true the response body starts hidden (for long / unimportant responses).
type card struct {
	Title     string
	OK        bool
	URL       string
	Detail    template.HTML
	Body      string
	Collapsed bool
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

// renderClaimChecks converts the map returned by validateIDClaims into an HTML
// fragment. An empty map (all claims valid) produces a green "All claims valid."
// message. Any failures are listed as a red unordered list.
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

// randomBytes returns n cryptographically random bytes. Panics if the OS CSPRNG
// is unavailable — this should never happen on a supported platform.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func randomHex(nBytes int) string {
	return hex.EncodeToString(randomBytes(nBytes))
}

// --- JWT/JWS verification (RS256 only) ---

// decodeJWT splits a compact-serialized JWT into its three parts and base64url-
// decodes the header and payload segments into maps. It does NOT verify the
// signature — call verifyJWS for that.
//
// The function uses RawURLEncoding (no padding) because JWT segments are encoded
// without the "=" padding characters that standard base64 appends.
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

// verifyJWS verifies an RS256-signed JWS token using the public keys in jwks.
// The signing input for RS256 is the ASCII string "header_b64url.payload_b64url"
// — the raw base64url segments from the token, not re-encoded from parsed JSON.
// This function supports RS256 only; other algorithms are rejected.
func verifyJWS(token string, header map[string]interface{}, jwks map[string]interface{}) error {
	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)
	if alg != "RS256" {
		return fmt.Errorf("unsupported alg %q (this sample verifies RS256 only)", alg)
	}
	// Find the JWK whose kid matches the token header.
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

// jwkToRSAPublicKey reconstructs an *rsa.PublicKey from a JWK map.
// The JWK "n" and "e" fields are base64url-encoded big-endian integers.
// "n" is the RSA modulus; "e" is the public exponent (commonly 65537).
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
	// e is big-endian; pad to 8 bytes for binary.BigEndian.Uint64.
	var ePadded [8]byte
	copy(ePadded[8-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint64(ePadded[:]))
	n := new(big.Int).SetBytes(nBytes)
	return &rsa.PublicKey{N: n, E: e}, nil
}

// validateIDClaims checks the standard OIDC Core §3.1.3.7 ID token claims.
// Returns a map of claim name → error message; an empty map means all checks passed.
//
// iss — must exactly match the PingOne issuer URL for this environment.
// aud — may be a single string or a JSON array; must contain our client_id.
// exp — Unix timestamp; must be greater than now (token is not expired).
// iat — Unix timestamp; must not be more than 60 seconds in the future (clock skew).
// nonce — must match the value we generated in handlePrepare; proves the token was
// issued in response to our specific authorize request.
func validateIDClaims(claims map[string]interface{}, expectedIssuer, expectedAud, expectedNonce string) map[string]string {
	errs := map[string]string{}
	if iss, _ := claims["iss"].(string); iss != expectedIssuer {
		errs["iss"] = fmt.Sprintf("got %q, want %q", iss, expectedIssuer)
	}
	if !audienceContains(claims["aud"], expectedAud) {
		errs["aud"] = fmt.Sprintf("does not contain %q", expectedAud)
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
	if nonce, _ := claims["nonce"].(string); nonce != expectedNonce {
		errs["nonce"] = fmt.Sprintf("got %q, want %q", nonce, expectedNonce)
	}
	return errs
}

// audienceContains handles the OIDC spec's allowance for aud to be either a single
// string or a JSON array of strings. Returns true if want is present in either form.
func audienceContains(aud interface{}, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, item := range v {
			if s, _ := item.(string); s == want {
				return true
			}
		}
	}
	return false
}

// numericClaim converts a JSON-decoded numeric claim to int64. JWT claims use
// JSON number (float64 in Go's encoding/json); the function also handles int64
// and int for callers that pre-parse numeric claims.
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
  button:hover{background:#b8002f;}
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
</style>
</head>
<body>
<header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:24px;">
  <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
</header>
<div style="padding:32px 40px; max-width:900px; margin:0 auto;">
{{.Body}}
</div>
</body>
</html>`

const cardsHTML = `{{range .}}
<div class="card">
  <h3 class="{{if .OK}}ok{{else}}err{{end}}">{{.Title}} {{if .OK}}(ok){{else}}(failed){{end}}</h3>
  {{if .URL}}<div class="url">{{.URL}}</div>{{end}}
  {{if .Detail}}<div>{{.Detail}}</div>{{end}}
  {{if .Body}}{{if .Collapsed}}<details><summary>Show response</summary><pre>{{.Body}}</pre></details>{{else}}<details open><summary>Hide</summary><pre>{{.Body}}</pre></details>{{end}}{{end}}
</div>
{{end}}`
