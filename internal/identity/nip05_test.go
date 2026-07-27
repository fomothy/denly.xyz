package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fomothy/denly.xyz/internal/nostr"
)

func testKey(t *testing.T) (*nostr.PrivateKey, nostr.PublicKey) {
	t.Helper()
	sk, err := nostr.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return sk, sk.PublicKey()
}

// resolverFor points a Resolver at a test server instead of the real internet.
func resolverFor(t *testing.T, handler http.Handler) (*Resolver, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	r := NewResolver()
	r.baseURL = srv.URL
	return r, srv
}

func TestParseAddress(t *testing.T) {
	tests := []struct {
		in         string
		wantName   string
		wantDomain string
		wantErr    bool
	}{
		{in: "nick@denly.xyz", wantName: "nick", wantDomain: "denly.xyz"},
		{in: "NICK@Denly.XYZ", wantName: "nick", wantDomain: "denly.xyz"},
		{in: "  nick@denly.xyz  ", wantName: "nick", wantDomain: "denly.xyz"},
		{in: "denly.xyz", wantName: "_", wantDomain: "denly.xyz"},
		{in: "_@denly.xyz", wantName: "_", wantDomain: "denly.xyz"},
		{in: "a.b-c_d@denly.xyz", wantName: "a.b-c_d", wantDomain: "denly.xyz"},
		{in: "", wantErr: true},
		{in: "@denly.xyz", wantErr: true},
		{in: "nick@", wantErr: true},
		{in: "nick@localhost", wantErr: true}, // no dot: not a real domain
		{in: "nick name@denly.xyz", wantErr: true},
		{in: "nick@denly.xyz/path", wantErr: true},
	}

	for _, tt := range tests {
		got, err := ParseAddress(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseAddress(%q) succeeded, want an error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAddress(%q): %v", tt.in, err)
			continue
		}
		if got.Name != tt.wantName || got.Domain != tt.wantDomain {
			t.Errorf("ParseAddress(%q) = %s@%s, want %s@%s",
				tt.in, got.Name, got.Domain, tt.wantName, tt.wantDomain)
		}
	}
}

func TestAddressStringCollapsesReservedName(t *testing.T) {
	addr, err := ParseAddress("denly.xyz")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if got := addr.String(); got != "denly.xyz" {
		t.Errorf("String() = %q, want the bare domain", got)
	}
}

func TestResolveFindsTheName(t *testing.T) {
	_, pk := testKey(t)

	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != WellKnownPath {
			t.Errorf("requested %q, want %q", req.URL.Path, WellKnownPath)
		}
		if got := req.URL.Query().Get("name"); got != "nick" {
			t.Errorf("name query = %q, want nick", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"names":{"nick":"` + pk.Hex() + `"}}`))
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	got, err := r.Resolve(context.Background(), addr)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != pk {
		t.Error("resolved a different key than the document listed")
	}
}

func TestResolveIsCaseInsensitiveOnNames(t *testing.T) {
	_, pk := testKey(t)
	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"names":{"Nick":"` + pk.Hex() + `"}}`))
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	if _, err := r.Resolve(context.Background(), addr); err != nil {
		t.Errorf("Resolve did not match a capitalised name: %v", err)
	}
}

func TestResolveMissingName(t *testing.T) {
	_, pk := testKey(t)
	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"names":{"someoneelse":"` + pk.Hex() + `"}}`))
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	_, err := r.Resolve(context.Background(), addr)
	if !errors.Is(err, ErrNameNotFound) {
		t.Errorf("err = %v, want ErrNameNotFound", err)
	}
}

func TestVerifyDetectsKeyMismatch(t *testing.T) {
	_, listed := testKey(t)
	_, expected := testKey(t)

	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"names":{"nick":"` + listed.Hex() + `"}}`))
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	err := r.Verify(context.Background(), addr, expected)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("err = %v, want ErrKeyMismatch", err)
	}
}

func TestVerifySucceedsOnMatch(t *testing.T) {
	_, pk := testKey(t)
	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"names":{"nick":"` + pk.Hex() + `"}}`))
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	if err := r.Verify(context.Background(), addr, pk); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// A NIP-05 claim is an assertion by one specific domain. If that domain
// redirects, the answer comes from somewhere else and is not what we asked
// for — so a redirect must not silently become a verification.
func TestResolveDoesNotFollowRedirects(t *testing.T) {
	_, pk := testKey(t)

	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"names":{"nick":"` + pk.Hex() + `"}}`))
	}))
	defer elsewhere.Close()

	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, elsewhere.URL+WellKnownPath+"?name=nick", http.StatusFound)
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	if _, err := r.Resolve(context.Background(), addr); err == nil {
		t.Error("Resolve followed a redirect to another host")
	}
}

func TestResolveRejectsBadStatus(t *testing.T) {
	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	if _, err := r.Resolve(context.Background(), addr); err == nil {
		t.Error("Resolve accepted a 404")
	}
}

func TestResolveRejectsInvalidJSON(t *testing.T) {
	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"names": this is not json`))
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	if _, err := r.Resolve(context.Background(), addr); err == nil {
		t.Error("Resolve accepted malformed JSON")
	}
}

func TestResolveRejectsUnusableKey(t *testing.T) {
	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"names":{"nick":"not-a-key"}}`))
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	if _, err := r.Resolve(context.Background(), addr); err == nil {
		t.Error("Resolve accepted a malformed public key")
	}
}

// A hostile domain could stream forever; the reader must be bounded.
func TestResolveBoundsResponseSize(t *testing.T) {
	r, _ := resolverFor(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"names":{"nick":"` + strings.Repeat("a", maxDocumentBytes*2) + `"}}`))
	}))

	addr, _ := ParseAddress("nick@denly.xyz")
	if _, err := r.Resolve(context.Background(), addr); err == nil {
		t.Error("Resolve accepted an oversized document")
	}
}

func TestBuildDocument(t *testing.T) {
	_, pk := testKey(t)

	doc := BuildDocument(pk, []string{"nick", "Nick", "  spaced  ", "", "bad name!"})

	if doc.Names["_"] != pk.Hex() {
		t.Error("the reserved _ name is missing or wrong")
	}
	if doc.Names["nick"] != pk.Hex() {
		t.Error("alias 'nick' is missing")
	}
	if doc.Names["spaced"] != pk.Hex() {
		t.Error("a padded alias was not trimmed and stored")
	}
	if _, ok := doc.Names["bad name!"]; ok {
		t.Error("an alias with invalid characters was accepted")
	}
	if _, ok := doc.Names[""]; ok {
		t.Error("an empty alias was accepted")
	}
}
