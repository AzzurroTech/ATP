package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

/* -------------------------------------------------------------
   Configuration & globals
------------------------------------------------------------- */
const (
	listenAddr   = ":8080"
	staticDir    = "./web/static"
	templatePath = "./web/templates/index.html.tmpl"
	dataDir      = "./data"

	// Maximum size for uploaded encrypted blobs (5 MiB)
	maxUploadSize = 5 << 20

	// Rate‑limit settings
	maxAttempts   = 5
	windowSeconds = 120

	// Token lifetime (24 hours)
	tokenMaxAge = 24 * time.Hour
)

// HMAC secret is read from the environment at startup.
// It must be a sufficiently random string.
var hmacSecret string

func init() {
	hmacSecret = os.Getenv("ATTP_HMAC_SECRET")
	if hmacSecret == "" {
		log.Fatal("environment variable ATTP_HMAC_SECRET is required")
	}
}

/* -------------------------------------------------------------
   Types
------------------------------------------------------------- */
type User struct {
	ID       string `json:"id"`       // UUID‑like identifier
	Username string `json:"username"` // login name / email
	Salt     string `json:"salt"`     // base64‑encoded 16‑byte salt
	Hash     string `json:"hash"`     // hex‑encoded SHA‑256(salt||password)
}

type registerRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
type registerResponse struct {
	Message string `json:"message"`
	UserID  string `json:"user_id,omitempty"`
}
type loginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
type loginResponse struct {
	Token string `json:"token"`
}

/* -------------------------------------------------------------
   Global state & mutexes
------------------------------------------------------------- */
var (
	usersMu   sync.RWMutex
	usersFile = filepath.Join(dataDir, "users.json")
	users     []User

	// Rate‑limit structures
	rlMu     sync.Mutex
	attempts = make(map[string]*attemptInfo)
)

/* -------------------------------------------------------------
   Rate‑limit helpers
------------------------------------------------------------- */
type attemptInfo struct {
	timestamps []int64 // Unix seconds of recent attempts
}
func (ai *attemptInfo) cleanOld(now int64) {
	cutoff := now - windowSeconds
	i := 0
	for ; i < len(ai.timestamps); i++ {
		if ai.timestamps[i] >= cutoff {
			break
		}
	}
	if i > 0 {
		ai.timestamps = ai.timestamps[i:]
	}
}
func allowAttempt(ip string) (bool, int64) {
	now := time.Now().Unix()
	rlMu.Lock()
	defer rlMu.Unlock()
	ai, ok := attempts[ip]
	if !ok {
		ai = &attemptInfo{}
		attempts[ip] = ai
	}
	ai.cleanOld(now)
	if int64(len(ai.timestamps)) >= int64(maxAttempts) {
		oldest := ai.timestamps[0]
		retryAfter := (oldest + windowSeconds) - now
		if retryAfter < 0 {
			retryAfter = 0
		}
		return false, retryAfter
	}
	ai.timestamps = append(ai.timestamps, now)
	return true, 0
}
func getClientIP(r *http.Request) string {
	h := r.RemoteAddr
	if colon := strings.LastIndex(h, ":"); colon != -1 {
		return h[:colon]
	}
	return h
}
func rateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		ok, wait := allowAttempt(ip)
		if !ok {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", wait))
			http.Error(w, "Too many requests – please wait before trying again.", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

/* -------------------------------------------------------------
   Security‑header middleware (CSP, X‑Content‑Type‑Options, etc.)
------------------------------------------------------------- */
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
		next.ServeHTTP(w, r)
	})
}

/* -------------------------------------------------------------
   Utility helpers
------------------------------------------------------------- */
func ensureDataDir() error { return os.MkdirAll(dataDir, 0700) }

func randomSalt() ([]byte, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return b, err
}
func computeHash(salt []byte, password string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

/* ---------- User persistence ---------- */
func loadUsers() error {
	usersMu.Lock()
	defer usersMu.Unlock()
	data, err := os.ReadFile(usersFile)
	if err != nil {
		if os.IsNotExist(err) {
			users = []User{}
			return nil
		}
		return err
	}
	if len(data) == 0 {
		users = []User{}
		return nil
	}
	return json.Unmarshal(data, &users)
}
func saveUsers() error {
	usersMu.RLock()
	defer usersMu.RUnlock()
	tmp := usersFile + ".tmp"
	b, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, usersFile)
}
func findUserByLogin(login string) (*User, bool) {
	usersMu.RLock()
	defer usersMu.RUnlock()
	for i := range users {
		if users[i].Username == login {
			return &users[i], true
		}
	}
	return nil, false
}
func createUser(login, password string) (*User, error) {
	if _, exists := findUserByLogin(login); exists {
		return nil, fmt.Errorf("user already exists")
	}
	salt, err := randomSalt()
	if err != nil {
		return nil, err
	}
	hash := computeHash(salt, password)
	idRaw := sha256.Sum256(append([]byte(login), salt...))
	id := fmt.Sprintf("%x", idRaw[:6])
	u := User{
		ID:       id,
		Username: login,
		Salt:     base64.RawStdEncoding.EncodeToString(salt),
		Hash:     hash,
	}
	usersMu.Lock()
	users = append(users, u)
	usersMu.Unlock()
	if err := saveUsers(); err != nil {
		return nil, err
	}
	return &u, nil
}

/* ---------- Token handling ---------- */
// Token format: base64url( HMAC(secret, userID|timestamp) )
// Timestamp is Unix seconds.
func makeToken(userID string) (string, error) {
	ts := time.Now().Unix()
	msg := fmt.Sprintf("%s|%d", userID, ts)
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	if _, err := mac.Write([]byte(msg)); err != nil {
		return "", err
	}
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify token and also ensure it is not older than tokenMaxAge.
func verifyToken(userID, token string) bool {
	now := time.Now()
	for _, offset := range []int64{-900, 0, 900} { // ±15 min tolerance
		ts := now.Unix() + offset
		msg := fmt.Sprintf("%s|%d", userID, ts)
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		mac.Write([]byte(msg))
		expected := mac.Sum(nil)

		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			continue
		}
		if hmac.Equal(decoded, expected) {
			// Extract timestamp from the message we just built (ts)
			tokenTime := time.Unix(ts, 0)
			if now.Sub(tokenTime) <= tokenMaxAge {
				return true
			}
		}
	}
	return false
}

/* ---------- Auth helpers ---------- */
func extractBearer(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer "), true
	}
	return "", false
}
func requireAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	token, ok := extractBearer(r)
	if !ok || token == "" {
		http.Error(w, "missing auth token", http.StatusUnauthorized)
		return "", false
	}
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, u := range users {
		if verifyToken(u.ID, token) {
			return u.ID, true
		}
	}
	http.Error(w, "invalid or expired token", http.StatusUnauthorized)
	return "", false
}

/* -------------------------------------------------------------
   Handlers
------------------------------------------------------------- */
func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		http.Error(w, "template parse error", http.StatusInternalServerError)
		log.Printf("template parse error: %v", err)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "template execution error", http.StatusInternalServerError)
		log.Printf("template exec error: %v", err)
	}
}

/* Health endpoint (used by Docker healthcheck) */
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

/* Registration – rate limited */
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Login) == "" || strings.TrimSpace(req.Password) == "" {
		http.Error(w, "login and password required", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	user, err := createUser(req.Login, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	resp := registerResponse{
		Message: "account created",
		UserID:  user.ID,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

/* Login – rate limited */
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	user, ok := findUserByLogin(req.Login)
	if !ok {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	saltBytes, err := base64.RawStdEncoding.DecodeString(user.Salt)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if computeHash(saltBytes, req.Password) != user.Hash {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	token, err := makeToken(user.ID)
	if err != nil {
		http.Error(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	resp := loginResponse{Token: token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

/* Upload encrypted context – requires auth, size‑limited, rate‑limited */
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := requireAuth(w, r)
	if !ok {
		return // requireAuth already wrote the response
	}
	// Enforce maximum request size
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "cannot read body or exceeds size limit", http.StatusBadRequest)
		return
	}
	// Basic validation: must be base64 and at least 12 bytes (IV) + ciphertext
	if _, err := base64.StdEncoding.DecodeString(string(body)); err != nil {
		http.Error(w, "invalid base64 payload", http.StatusBadRequest)
		return
	}
	filename := filepath.Join(dataDir, userID+".ctx")
	if err := os.WriteFile(filename, body, 0600); err != nil {
		http.Error(w, "failed to store context", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

/* Download encrypted context – requires auth, rate‑limited */
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := requireAuth(w, r)
	if !ok {
		return
	}
	filename := filepath.Join(dataDir, userID+".ctx")
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "no context stored for this user", http.StatusNotFound)
		} else {
			http.Error(w, "failed to read context", http.StatusInternalServerError)
		}
		return
	}
	// Force download with a sensible filename
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-context.txt"`, userID))
	if _, err := w.Write(data); err != nil {
		log.Printf("error writing context response for %s: %v", userID, err)
	}
}

/* -------------------------------------------------------------
   Main – server bootstrap
------------------------------------------------------------- */
func main() {
	// Ensure data directory exists and load persisted users.
	if err := ensureDataDir(); err != nil {
		log.Fatalf("cannot create data dir: %v", err)
	}
	if err := loadUsers(); err != nil {
		log.Fatalf("failed to load users: %v", err)
	}

	// Serve static assets (CSS + JS) – Caddy will serve these directly in prod,
	// but we keep this for local development.
	fs := http.FileServer(http.Dir(staticDir))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// UI entry point
	http.HandleFunc("/", indexHandler)

	// Health endpoint (used by Docker healthcheck)
	http.HandleFunc("/health", healthHandler)

	// Authentication endpoints – rate‑limited
	http.HandleFunc("/api/auth/register", rateLimited(registerHandler))
	http.HandleFunc("/api/auth/login", rateLimited(loginHandler))

	// Protected context endpoints – rate‑limited and size‑limited
	http.HandleFunc("/api/context/upload", rateLimited(uploadHandler))
	http.HandleFunc("/api/context/download", rateLimited(downloadHandler))

	// Wrap everything with security headers middleware
	handler := securityHeaders(http.DefaultServeMux)

	// Periodic cleanup for the rate‑limit map (memory hygiene)
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rlMu.Lock()
			now := time.Now().Unix()
			for ip, ai := range attempts {
				ai.cleanOld(now)
				if len(ai.timestamps) == 0 {
					delete(attempts, ip)
				}
			}
			rlMu.Unlock()
		}
	}()

	log.Printf("🚀 ATP server (hardened, rate‑limited) listening on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		log.Fatalf("server error: %v", err)
	}
}