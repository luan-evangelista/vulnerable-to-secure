// WARNING: this service is intentionally vulnerable. It exists to show what a
// security pipeline catches. Do not deploy it or copy patterns from it.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
)

// VULN 1: signing key hardcoded in source code.
var jwtKey = []byte("s3cr3t-signing-key-do-not-use")

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type server struct {
	db         *sql.DB
	httpClient *http.Client
}

func newServer(dsn string) (*server, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT)`); err != nil {
		return nil, err
	}
	return &server{
		db: db,
		// VULN 2: TLS certificate verification disabled for outbound calls.
		httpClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}, nil
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		// VULN 3: internal error details returned to the client.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// VULN 4: MD5 for passwords, no salt.
	sum := md5.Sum([]byte(c.Password))
	query := fmt.Sprintf("INSERT INTO users (email, password) VALUES ('%s', '%s')", c.Email, hex.EncodeToString(sum[:]))
	// VULN 5: SQL injection.
	if _, err := s.db.Exec(query); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sum := md5.Sum([]byte(c.Password))
	var id int
	// VULN 5 again: an email of  ' OR '1'='1' --  logs in as the first user.
	err := s.db.QueryRow(fmt.Sprintf(
		"SELECT id FROM users WHERE email = '%s' AND password = '%s'",
		c.Email, hex.EncodeToString(sum[:]))).Scan(&id)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": id})
	signed, _ := token.SignedString(jwtKey)
	json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

func (s *server) charge(w http.ResponseWriter, r *http.Request) {
	var p struct {
		CardNumber string `json:"cardNumber"`
		Amount     int    `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// VULN 6: full card number written to logs.
	log.Printf("charging card %s", p.CardNumber)
	w.WriteHeader(http.StatusAccepted)
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /charge", s.charge)
	return mux
}

func main() {
	s, err := newServer("file:app.db")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening on :8080")
	// VULN 7: no server timeouts (slowloris).
	log.Fatal(http.ListenAndServe(":8080", s.routes()))
}
