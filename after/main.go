// The fixed version of ../before. Each "FIX n" matches a "VULN n" there.
package main

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

const (
	// FIX 4: PBKDF2-SHA256 with a per-user salt (OWASP recommends 600k iterations).
	pbkdf2Iterations = 600_000
	saltBytes        = 16
	keyBytes         = 32
)

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type server struct {
	db         *sql.DB
	jwtKey     []byte
	httpClient *http.Client
	log        *slog.Logger
}

func newServer(dsn string, jwtKey []byte) (*server, error) {
	// FIX 1: the signing key comes from the environment and must be strong.
	if len(jwtKey) < 32 {
		return nil, errors.New("JWT_SECRET must be at least 32 bytes")
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL)`); err != nil {
		return nil, err
	}
	return &server{
		db:     db,
		jwtKey: jwtKey,
		// FIX 2: certificate verification on, TLS 1.2 minimum.
		httpClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		},
		log: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}, nil
}

func hashPassword(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, keyBytes)
}

// FIX 3: decode with limits and return generic messages, never err.Error().
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !decode(w, r, &c) {
		return
	}
	if !strings.Contains(c.Email, "@") || len(c.Password) < 12 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		s.fail(w, r.Context(), "salt generation failed", err)
		return
	}
	hash, err := hashPassword(c.Password, salt)
	if err != nil {
		s.fail(w, r.Context(), "hashing failed", err)
		return
	}
	// FIX 5: parameterized query.
	_, err = s.db.ExecContext(r.Context(),
		"INSERT INTO users (email, salt, hash) VALUES (?, ?, ?)",
		c.Email, hex.EncodeToString(salt), hex.EncodeToString(hash))
	if err != nil {
		// Same response whether or not the email exists, to avoid account enumeration.
		s.log.InfoContext(r.Context(), "register rejected", "reason", "insert failed")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !decode(w, r, &c) {
		return
	}
	var (
		id            int
		saltHex, want string
	)
	err := s.db.QueryRowContext(r.Context(),
		"SELECT id, salt, hash FROM users WHERE email = ?", c.Email).Scan(&id, &saltHex, &want)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		s.fail(w, r.Context(), "corrupt salt", err)
		return
	}
	got, err := hashPassword(c.Password, salt)
	if err != nil {
		s.fail(w, r.Context(), "hashing failed", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(got)), []byte(want)) != 1 {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	// Maintained JWT library (golang-jwt), short expiry, explicit claims.
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   fmt.Sprint(id),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
	})
	signed, err := token.SignedString(s.jwtKey)
	if err != nil {
		s.fail(w, r.Context(), "token signing failed", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

// maskPAN keeps only the last four digits, as PCI DSS allows for display.
func maskPAN(pan string) string {
	if len(pan) <= 4 {
		return strings.Repeat("*", len(pan))
	}
	return strings.Repeat("*", len(pan)-4) + pan[len(pan)-4:]
}

func (s *server) charge(w http.ResponseWriter, r *http.Request) {
	var p struct {
		CardNumber string `json:"cardNumber"`
		Amount     int    `json:"amount"`
	}
	if !decode(w, r, &p) || p.Amount <= 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// FIX 6: only the masked number reaches the logs.
	s.log.InfoContext(r.Context(), "charge accepted", "card", maskPAN(p.CardNumber), "amount", p.Amount)
	w.WriteHeader(http.StatusAccepted)
}

func (s *server) fail(w http.ResponseWriter, ctx context.Context, msg string, err error) {
	s.log.ErrorContext(ctx, msg, "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /charge", s.charge)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

func main() {
	// Distroless has no shell or curl, so the binary checks its own health.
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		resp, err := http.Get("http://127.0.0.1:8080/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}
	s, err := newServer("file:/data/app.db", []byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
	// FIX 7: timeouts on every phase of the connection.
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	s.log.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
