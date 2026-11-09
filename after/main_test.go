package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testKey = "test-only-key-0123456789abcdef0123456789"

func newTestServer(t *testing.T) (*server, http.Handler, *bytes.Buffer) {
	t.Helper()
	s, err := newServer("file:"+t.Name()+"?mode=memory&cache=shared", []byte(testKey))
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	s.log = slog.New(slog.NewJSONHandler(logs, nil))
	return s, s.routes(), logs
}

func do(h http.Handler, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

func TestSQLInjectionNoLongerBypassesLogin(t *testing.T) {
	_, h, _ := newTestServer(t)
	if rec := do(h, "/register", `{"email":"admin@example.com","password":"correct horse battery staple"}`); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}
	if rec := do(h, "/login", `{"email":"' OR '1'='1' --","password":"wrong"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("injection must be rejected, got %d", rec.Code)
	}
	if rec := do(h, "/login", `{"email":"admin@example.com","password":"correct horse battery staple"}`); rec.Code != http.StatusOK {
		t.Fatalf("valid login failed: %d", rec.Code)
	}
}

func TestPasswordsAreSaltedAndNotMD5(t *testing.T) {
	s, h, _ := newTestServer(t)
	for _, email := range []string{"a@example.com", "b@example.com"} {
		do(h, "/register", `{"email":"`+email+`","password":"same password for both"}`)
	}
	rows, err := s.db.Query("SELECT hash FROM users")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var hash string
		_ = rows.Scan(&hash)
		hashes = append(hashes, hash)
	}
	if len(hashes) != 2 || hashes[0] == hashes[1] {
		t.Fatalf("same password must produce different hashes, got %v", hashes)
	}
	if len(hashes[0]) == 32 {
		t.Fatal("hash length matches MD5")
	}
}

func TestCardNumberIsMaskedInLogs(t *testing.T) {
	_, h, logs := newTestServer(t)
	if rec := do(h, "/charge", `{"cardNumber":"4111111111111111","amount":4990}`); rec.Code != http.StatusAccepted {
		t.Fatalf("charge: got %d", rec.Code)
	}
	out := logs.String()
	if strings.Contains(out, "4111111111111111") {
		t.Fatal("full card number found in logs")
	}
	if !strings.Contains(out, "************1111") {
		t.Fatalf("masked card not logged: %s", out)
	}
}

func TestErrorsDoNotLeakInternals(t *testing.T) {
	_, h, _ := newTestServer(t)
	rec := do(h, "/login", `{"email":`)
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusBadRequest || strings.TrimSpace(string(body)) != "invalid request" {
		t.Fatalf("unexpected response %d %q", rec.Code, body)
	}
}

func TestWeakJWTKeyIsRejected(t *testing.T) {
	if _, err := newServer("file::memory:", []byte("short")); err == nil {
		t.Fatal("expected a short key to be rejected")
	}
}
