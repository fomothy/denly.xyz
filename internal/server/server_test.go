package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fomothy/denly.xyz/internal/auth"
	"github.com/fomothy/denly.xyz/internal/config"
	"github.com/fomothy/denly.xyz/internal/drop"
	"github.com/fomothy/denly.xyz/internal/identity"
	"github.com/fomothy/denly.xyz/internal/nostr"
	"github.com/fomothy/denly.xyz/internal/profile"
	"github.com/fomothy/denly.xyz/internal/publish"
	"github.com/fomothy/denly.xyz/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()

	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "denly.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.Config{DataDir: dir, Addr: "127.0.0.1:0"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	sk, err := nostr.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	owner := sk.PublicKey()

	prof := profile.New(st)
	s, err := New(cfg, st, log, Deps{
		Owner:      &owner,
		Auth:       auth.New(testAdminToken, owner),
		Profile:    prof,
		Drops:      drop.New(st),
		Identities: identity.NewResolver(),
		// No pinner: publishing reports itself unconfigured, which is the
		// default state of a fresh instance.
		Publisher: publish.New(st, prof, nil),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.ownerKey = sk
	return s
}

// testAdminToken is the loopback credential the API tests authenticate with.
const testAdminToken = "test-admin-token"

func TestIndexRenders(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"Your den is running", "SQLite", "schema v"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

// The data dir is rendered into the page; make sure the template model is
// actually wired rather than showing a placeholder.
func TestIndexShowsDataDir(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !strings.Contains(rec.Body.String(), s.cfg.DataDir) {
		t.Errorf("body does not show data dir %q", s.cfg.DataDir)
	}
}

// "GET /{$}" must not swallow unknown paths.
func TestUnknownPathIs404(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHealthOK(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding health response: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if resp.SchemaVersion != store.LatestSchemaVersion() {
		t.Errorf("schema_version = %d, want %d", resp.SchemaVersion, store.LatestSchemaVersion())
	}
	if resp.Version == "" {
		t.Error("version is empty")
	}
}

// A wedged database must surface as 503, not a cheerful 200. install.sh and
// any monitoring rely on this.
func TestHealthDegradedWhenDBClosed(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.Close(); err != nil {
		t.Fatalf("closing store: %v", err)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	var resp healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding health response: %v", err)
	}
	if resp.Status != "degraded" {
		t.Errorf("status = %q, want degraded", resp.Status)
	}
}

func TestStaticAssetsServed(t *testing.T) {
	s := newTestServer(t)

	for _, path := range []string{"/static/style.css", "/static/favicon.svg"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET %s: empty body", path)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q, want a default-src 'none' baseline", csp)
	}
}

func TestServeShutsDownOnContextCancel(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Addr = "127.0.0.1:0"
	s.http.Addr = "127.0.0.1:0"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	// Give the listener a moment to come up before cancelling.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

func TestServeFailsOnBadAddr(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Addr = "127.0.0.1:99999" // out of range

	err := s.Serve(context.Background())
	if err == nil {
		t.Fatal("Serve accepted an invalid address, want error")
	}
}

func TestRecoverMiddleware(t *testing.T) {
	s := newTestServer(t)

	h := s.recoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestDisplayURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"127.0.0.1:8737", "http://127.0.0.1:8737"},
		{"0.0.0.0:8737", "http://localhost:8737"},
		{"[::]:8737", "http://localhost:8737"},
	}
	for _, tt := range tests {
		if got := displayURL(tt.in); got != tt.want {
			t.Errorf("displayURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{90 * time.Minute, "1h 30m"},
		{50 * time.Hour, "2d 2h"},
	}
	for _, tt := range tests {
		if got := humanDuration(tt.in); got != tt.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
