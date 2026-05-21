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

// --- session store ---
//
// Single-process in-memory session store keyed by an opaque "sid" cookie.
// Persists PKCE artifacts across the redirect to PingOne and back.
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

var sessions = struct {
	sync.Mutex
	m map[string]*sessionState
}{m: map[string]*sessionState{}}

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

// --- main ---

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
	hash := sha256.Sum256([]byte(s.Verifier))
	s.Challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	// 3. state + nonce — independent random values for CSRF and replay protection.
	s.State = randomHex(16)
	s.Nonce = randomHex(16)

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

	cards = append(cards, card{
		Title:  "1. Receive callback",
		OK:     true,
		URL:    "GET " + redirectURI + "?" + r.URL.RawQuery,
		Detail: "PingOne redirected the browser back with <code>code</code> and <code>state</code>. The <code>code</code> is single-use and short-lived.",
		Body:   fmt.Sprintf("code:  %s\nstate: %s", gotCode, gotState),
	})

	// 2. State validation — defends against CSRF.
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

	// 3. Token exchange — confidential client: HTTP Basic + code_verifier.
	tokenURL := fmt.Sprintf("%s/%s/as/token", authPath, envID)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", gotCode)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", s.Verifier)

	basic := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))

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

	// 4. Decode ID token (header + payload). Signature verification is the next step.
	header, payload, sigOK, decodeErr := decodeJWT(idToken)
	cards = append(cards, card{
		Title:  "4. Decode ID token",
		OK:     decodeErr == nil,
		Detail: "An ID token is a JWS: three base64url segments separated by dots. The header tells us which key to use; the payload contains the claims; the signature must be verified before any claim is trusted.",
		Body:   fmt.Sprintf("header:\n%s\n\npayload:\n%s", prettyAny(header), prettyAny(payload)),
	})
	_ = sigOK

	// 5. Fetch JWKS.
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

	// 6. Verify ID token signature (RS256).
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

	// 7. Validate ID token claims.
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

	// 8. /userinfo
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

	// 9. Final tokens.
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

// --- helpers ---

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
