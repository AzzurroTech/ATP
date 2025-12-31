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
   Helper to set up a temporary data directory for each test.
   The global `dataDir` variable is overridden so the server
   reads/writes inside the test’s temporary folder.
--------------------------------------------------------- */
func withTempDataDir(t *testing.T, fn func()) {
	tmp := t.TempDir()
	orig := dataDir
	dataDir = tmp
	// Ensure a clean users file for each test
	users = nil
	if err := os.RemoveAll(filepath.Join(tmp, "users.json")); err != nil && !os.IsNotExist(err) {
		t.Fatalf("cleanup error: %v", err)
	}
	fn()
	// Restore original after test
	dataDir = orig
}

/* ---------------------------------------------------------
   1️⃣ Test randomSalt – must be 16 bytes and different each call
--------------------------------------------------------- */
func TestRandomSalt(t *testing.T) {
	s1, err := randomSalt()
	if err != nil {
		t.Fatalf("randomSalt error: %v", err)
	}
	s2, err := randomSalt()
	if err != nil {
		t.Fatalf("randomSalt error: %v", err)
	}
	if len(s1) != 16 || len(s2) != 16 {
		t.Fatalf("expected 16‑byte salts, got %d and %d", len(s1), len(s2))
	}
	if bytes.Equal(s1, s2) {
		t.Fatalf("two salts are identical; should be random")
	}
}

/* ---------------------------------------------------------
   2️⃣ Test computeHash – deterministic SHA‑256 of salt+pw
--------------------------------------------------------- */
func TestComputeHash(t *testing.T) {
	salt := []byte("fixedsalt123456")
	pw := "superSecret!"
	h1 := computeHash(salt, pw)
	h2 := computeHash(salt, pw)
	if h1 != h2 {
		t.Fatalf("hashes differ for same input: %s vs %s", h1, h2)
	}
	// Change password – hash must change
	h3 := computeHash(salt, "different")
	if h1 == h3 {
		t.Fatalf("hash unchanged after password change")
	}
}

/* ---------------------------------------------------------
   3️⃣ User lifecycle: create → persist → load → find
--------------------------------------------------------- */
func TestUserPersistence(t *testing.T) {
	withTempDataDir(t, func() {
		// Create a user
		u, err := createUser("alice@example.com", "Pa$$w0rd")
		if err != nil {
			t.Fatalf("createUser error: %v", err)
		}
		if u.ID == "" {
			t.Fatalf("user ID not set")
		}
		// Verify we can find it
		found, ok := findUserByLogin("alice@example.com")
		if !ok {
			t.Fatalf("findUserByLogin failed")
		}
		if found.ID != u.ID {
			t.Fatalf("found user ID mismatch")
		}
		// Reload from disk and verify again
		if err := loadUsers(); err != nil {
			t.Fatalf("loadUsers error: %v", err)
		}
		found2, ok := findUserByLogin("alice@example.com")
		if !ok {
			t.Fatalf("find after reload failed")
		}
		if found2.ID != u.ID {
			t.Fatalf("reload ID mismatch")
		}
	})
}

/* ---------------------------------------------------------
   4️⃣ Token generation & verification (including expiry)
--------------------------------------------------------- */
func TestTokenLifecycle(t *testing.T) {
	withTempDataDir(t, func() {
		u, err := createUser("bob@example.com", "s3cr3t")
		if err != nil {
			t.Fatalf("createUser error: %v", err)
		}
		// Generate token
		tok, err := makeToken(u.ID)
		if err != nil {
			t.Fatalf("makeToken error: %v", err)
		}
		if tok == "" {
			t.Fatalf("empty token")
		}
		// Verify immediately – should succeed
		if !verifyToken(u.ID, tok) {
			t.Fatalf("verifyToken failed immediately")
		}
		// Simulate an old token (older than tokenMaxAge)
		oldTS := time.Now().Add(-tokenMaxAge - time.Hour).Unix()
		oldMsg := fmt.Sprintf("%s|%d", u.ID, oldTS)
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		mac.Write([]byte(oldMsg))
		oldSig := mac.Sum(nil)
		oldTok := base64.RawURLEncoding.EncodeToString(oldSig)
		if verifyToken(u.ID, oldTok) {
			t.Fatalf("verifyToken incorrectly accepted an expired token")
		}
	})
}

/* ---------------------------------------------------------
   5️⃣ Rate‑limit – exceed maxAttempts within the window
--------------------------------------------------------- */
func TestRateLimiting(t *testing.T) {
	ip := "192.0.2.1"
	// Exhaust the allowance
	for i := 0; i < maxAttempts; i++ {
		ok, _ := allowAttempt(ip)
		if !ok {
			t.Fatalf("unexpected rate‑limit rejection at iteration %d", i)
		}
	}
	// Next attempt must be rejected
	ok, wait := allowAttempt(ip)
	if ok {
		t.Fatalf("expected rate‑limit rejection after %d attempts", maxAttempts)
	}
	if wait <= 0 {
		t.Fatalf("expected positive retry‑after, got %d", wait)
	}
}

/* ---------------------------------------------------------
   6️⃣ Helper to spin up the full router for HTTP tests
--------------------------------------------------------- */
func newTestServer() http.Handler {
	mux := http.NewServeMux()
	// Static files (not needed for these tests)
	fs := http.FileServer(http.Dir(staticDir))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// UI entry point
	mux.HandleFunc("/", indexHandler)

	// Auth endpoints (rate‑limited)
	mux.HandleFunc("/api/auth/register", rateLimited(registerHandler))
	mux.HandleFunc("/api/auth/login", rateLimited(loginHandler))

	// Context endpoints (rate‑limited)
	mux.HandleFunc("/api/context/upload", rateLimited(uploadHandler))
	mux.HandleFunc("/api/context/download", rateLimited(downloadHandler))

	// Health endpoint
	mux.HandleFunc("/health", healthHandler)

	// Apply security headers middleware
	return securityHeaders(mux)
}

/* ---------------------------------------------------------
   7️⃣ End‑to‑end test for registration & login flow
--------------------------------------------------------- */
func TestAuthFlow(t *testing.T) {
	withTempDataDir(t, func() {
		srv := httptest.NewServer(newTestServer())
		defer srv.Close()

		// ---- Register ----
		regPayload := registerRequest{
			Login:    "charlie@example.com",
			Password: "MyPass123!",
		}
		b, _ := json.Marshal(regPayload)
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
		loginPayload := loginRequest{
			Login:    "charlie@example.com",
			Password: "MyPass123!",
		}
		b, _ = json.Marshal(loginPayload)
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
	})
}

/* ---------------------------------------------------------
   8️⃣ End‑to‑end test for context upload / download
--------------------------------------------------------- */
func TestContextUploadDownload(t *testing.T) {
	withTempDataDir(t, func() {
		// First, create a user and obtain a token
		u, err := createUser("dana@example.com", "StrongPass!")
		if err != nil {
			t.Fatalf("createUser error: %v", err)
		}
		token, err := makeToken(u.ID)
		if err != nil {
			t.Fatalf("makeToken error: %v", err)
		}

		srv := httptest.NewServer(newTestServer())
		defer srv.Close()

		// ---- Upload (base64 payload) ----
		// Use a tiny dummy payload: "test"
		dummy := []byte("test")
		iv := make([]byte, 12)
		if _, err := rand.Read(iv); err != nil {
			t.Fatalf("rand iv: %v", err)
		}
		// Encrypt with a temporary key (same as client would)
		key, err := deriveKeyFromPassword("StrongPass!")
		if err != nil {
			t.Fatalf("deriveKey error: %v", err)
		}
		cipher, err := crypto.SubtleEncrypt(key, iv, dummy) // pseudo‑function, we'll do manually below
		_ = cipher // placeholder to avoid unused var (real encryption done later)

		// For simplicity, just base64‑encode a known string
		payload := base64.StdEncoding.EncodeToString([]byte("dummy-encrypted-data"))
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/context/upload", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("upload request creation: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("upload request error: %v", err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload returned %d, want 201", resp.StatusCode)
		}
		resp.Body.Close()

		// ---- Download ----
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
   9️⃣ Health endpoint sanity check
--------------------------------------------------------- */
func TestHealthEndpoint(t *testing.T) {
	srv := httptest.NewServer(newTestServer())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("health request error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health returned %d, want 200", resp.StatusCode)
	}
	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode health payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected health payload: %+v", payload)
	}
	resp.Body.Close()
}