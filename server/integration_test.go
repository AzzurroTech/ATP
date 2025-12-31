package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

/* ---------------------------------------------------------
   Helper – creates a temporary data directory for each test
   and swaps the global `dataDir` variable so the server writes
   inside the sandbox.
--------------------------------------------------------- */
func withTempDataDir(t *testing.T, fn func()) {
	tmp := t.TempDir()
	orig := dataDir
	dataDir = tmp
	// Reset global users slice
	users = nil
	// Ensure a clean users file
	if err := os.RemoveAll(filepath.Join(tmp, "users.json")); err != nil && !os.IsNotExist(err) {
		t.Fatalf("cleanup error: %v", err)
	}
	fn()
	// Restore original after test
	dataDir = orig
}

/* ---------------------------------------------------------
   Helper – builds the full HTTP handler stack exactly as the
   production server does (static files, API, security headers,
   health endpoint).
--------------------------------------------------------- */
func buildHandler() http.Handler {
	mux := http.NewServeMux()

	// Static assets (not needed for API tests but kept for completeness)
	fs := http.FileServer(http.Dir(staticDir))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// UI entry point
	mux.HandleFunc("/", indexHandler)

	// Health endpoint
	mux.HandleFunc("/health", healthHandler)

	// Auth endpoints (rate‑limited)
	mux.HandleFunc("/api/auth/register", rateLimited(registerHandler))
	mux.HandleFunc("/api/auth/login", rateLimited(loginHandler))

	// Context endpoints (rate‑limited)
	mux.HandleFunc("/api/context/upload", rateLimited(uploadHandler))
	mux.HandleFunc("/api/context/download", rateLimited(downloadHandler))

	// Apply security‑header middleware
	return securityHeaders(mux)
}

/* ---------------------------------------------------------
   1️⃣ Test health endpoint – sanity check
--------------------------------------------------------- */
func TestHealthEndpoint(t *testing.T) {
	withTempDataDir(t, func() {
		srv := httptest.NewServer(buildHandler())
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/health")
		if err != nil {
			t.Fatalf("GET /health error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
		var payload map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			t.Fatalf("decode health payload: %v", err)
		}
		if payload["status"] != "ok" {
			t.Fatalf("unexpected health payload: %+v", payload)
		}
		resp.Body.Close()
	})
}

/* ---------------------------------------------------------
   2️⃣ Test full auth flow (register → login) and token handling
--------------------------------------------------------- */
func TestAuthFlow(t *testing.T) {
	withTempDataDir(t, func() {
		srv := httptest.NewServer(buildHandler())
		defer srv.Close()

		// ---- Register ----
		regReq := registerRequest{
			Login:    "alice@example.com",
			Password: "SuperSecret123!",
		}
		b, _ := json.Marshal(regReq)
		resp, err := http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("register request error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("register returned %d, want 200", resp.StatusCode)
		}
		var regResp registerResponse
		if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
			t.Fatalf("decode register response: %v", err)
		}
		if regResp.UserID == "" {
			t.Fatalf("register response missing user_id")
		}
		resp.Body.Close()

		// ---- Login ----
		loginReq := loginRequest{
			Login:    "alice@example.com",
			Password: "SuperSecret123!",
		}
		b, _ = json.Marshal(loginReq)
		resp, err = http.Post(srv.URL+"/api/auth/login", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("login request error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login returned %d, want 200", resp.StatusCode)
		}
		var loginResp loginResponse
		if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
			t.Fatalf("decode login response: %v", err)
		}
		if loginResp.Token == "" {
			t.Fatalf("login response missing token")
		}
		resp.Body.Close()

		// Store token for later calls
		token := loginResp.Token

		/* -------------------------------------------------
		   3️⃣ Upload a dummy encrypted context (base64 payload)
		   ------------------------------------------------- */
		// For simplicity we just upload a known base64 string.
		payload := base64.StdEncoding.EncodeToString([]byte("dummy-encrypted-data"))
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/context/upload", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("upload request creation: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("upload request error: %v", err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload returned %d, want 201", resp.StatusCode)
		}
		resp.Body.Close()

		/* -------------------------------------------------
		   4️⃣ Download the same context and verify payload
		   ------------------------------------------------- */
		req, err = http.NewRequest(http.MethodGet, srv.URL+"/api/context/download", nil)
		if err != nil {
			t.Fatalf("download request creation: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("download request error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("download returned %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading download body: %v", err)
		}
		resp.Body.Close()
		if string(body) != payload {
			t.Fatalf("downloaded payload mismatch: got %q, want %q", string(body), payload)
		}
	})
}

/* ---------------------------------------------------------
   5️⃣ Rate‑limit test – exceed maxAttempts on a single IP
--------------------------------------------------------- */
func TestRateLimiting(t *testing.T) {
	withTempDataDir(t, func() {
		srv := httptest.NewServer(buildHandler())
		defer srv.Close()

		// Helper to perform a POST to /api/auth/register (rate‑limited)
		doRegister := func(email string) (*http.Response, error) {
			reqBody := registerRequest{
				Login:    email,
				Password: "Password123!",
			}
			b, _ := json.Marshal(reqBody)
			return http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(b))
		}

		// Exhaust the allowed attempts
		for i := 0; i < maxAttempts; i++ {
			resp, err := doRegister(fmt.Sprintf("user%d@example.com", i))
			if err != nil {
				t.Fatalf("register attempt %d error: %v", i+1, err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 OK on attempt %d, got %d", i+1, resp.StatusCode)
			}
			resp.Body.Close()
		}

		// Next attempt must be rejected with 429
		resp, err := doRegister("exceed@example.com")
		if err != nil {
			t.Fatalf("register exceed error: %v", err)
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("expected 429 Too Many Requests, got %d", resp.StatusCode)
		}
		// Verify Retry‑After header is present and parsable
		if ra := resp.Header.Get("Retry-After"); ra == "" {
			t.Fatalf("Retry-After header missing on rate‑limit response")
		}
		resp.Body.Close()
	})
}

/* ---------------------------------------------------------
   6️⃣ Upload size limit – ensure server rejects oversized payloads
--------------------------------------------------------- */
func TestUploadSizeLimit(t *testing.T) {
	withTempDataDir(t, func() {
		srv := httptest.NewServer(buildHandler())
		defer srv.Close()

		// Register & login first to obtain a token
		reg := registerRequest{Login: "biguser@example.com", Password: "BigPass123!"}
		b, _ := json.Marshal(reg)
		resp, err := http.Post(srv.URL+"/api/auth/register", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("register error: %v", err)
		}
		resp.Body.Close()

		login := loginRequest{Login: "biguser@example.com", Password: "BigPass123!"}
		b, _ = json.Marshal(login)
		resp, err = http.Post(srv.URL+"/api/auth/login", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("login error: %v", err)
		}
		var lr loginResponse
		if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
			t.Fatalf("decode login response: %v", err)
		}
		resp.Body.Close()
		token := lr.Token

		// Build a payload larger than maxUploadSize (5 MiB)
		oversized := make([]byte, maxUploadSize+1024) // 1 KiB over the limit
		for i := range oversized {
			oversized[i] = 'A'
		}
		payload := base64.StdEncoding.EncodeToString(oversized)

		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/context/upload", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("upload request creation: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("upload request error: %v", err)
		}
		// Expect 400 Bad Request due to size limit
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for oversized upload, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})
}

/* ---------------------------------------------------------
   7️⃣ Token expiry – ensure a token older than the configured
        max age (24 h) is rejected.
--------------------------------------------------------- */
func TestTokenExpiry(t *testing.T) {
	withTempDataDir(t, func() {
		srv := httptest.NewServer(buildHandler())
		defer srv.Close()

		// Create a user directly (bypass HTTP) so we can craft an old token
		user, err := createUser("oldtoken@example.com", "OldPass123")
		if err != nil {
			t.Fatalf("createUser error: %v", err)
		}

		// Manually craft a token with a timestamp older than tokenMaxAge
		oldTS := time.Now().Add(-tokenMaxAge - time.Hour).Unix()
		msg := fmt.Sprintf("%s|%d", user.ID, oldTS)
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		mac.Write([]byte(msg))
		sig := mac.Sum(nil)
		expiredToken := base64.RawURLEncoding.EncodeToString(sig)

		// Attempt to download with the expired token – should get 401
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/context/download", nil)
		if err != nil {
			t.Fatalf("download request creation: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("download request error: %v", err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for expired token, got %d", resp.StatusCode)
		}
		resp.Body.Close()
	})
}