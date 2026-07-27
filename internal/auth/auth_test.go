package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/fomothy/denly.xyz/internal/nostr"
)

func newTestAuth(t *testing.T) (*Authenticator, *nostr.PrivateKey) {
	t.Helper()
	sk, err := nostr.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return New("test-token", sk.PublicKey()), sk
}

func request(remoteAddr, authorization string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/admin/thing", nil)
	r.RemoteAddr = remoteAddr
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	return r
}

func TestTokenFromLoopbackIsAccepted(t *testing.T) {
	a, _ := newTestAuth(t)
	if err := a.Authenticate(request("127.0.0.1:5555", "Bearer test-token")); err != nil {
		t.Errorf("loopback token rejected: %v", err)
	}
	if err := a.Authenticate(request("[::1]:5555", "Bearer test-token")); err != nil {
		t.Errorf("IPv6 loopback token rejected: %v", err)
	}
}

func TestWrongTokenRejected(t *testing.T) {
	a, _ := newTestAuth(t)
	if err := a.Authenticate(request("127.0.0.1:5555", "Bearer nope")); err == nil {
		t.Error("a bad token was accepted")
	}
}

// The token is the weaker credential — it can leak through proxies, logs, and
// browser history. Off-machine callers must prove key possession instead.
func TestTokenFromRemoteIsRejected(t *testing.T) {
	a, _ := newTestAuth(t)
	err := a.Authenticate(request("203.0.113.7:5555", "Bearer test-token"))
	if err == nil {
		t.Fatal("a remote request authenticated with only the admin token")
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

// A forwarded header is attacker-controlled; trusting it would let anyone
// claim to be localhost.
func TestForwardedHeaderCannotForgeLoopback(t *testing.T) {
	a, _ := newTestAuth(t)
	r := request("203.0.113.7:5555", "Bearer test-token")
	r.Header.Set("X-Forwarded-For", "127.0.0.1")

	if err := a.Authenticate(r); err == nil {
		t.Error("X-Forwarded-For was enough to pass as loopback")
	}
}

func TestSignedChallengeFromRemoteIsAccepted(t *testing.T) {
	a, sk := newTestAuth(t)

	ch, err := a.NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	sig, err := SignChallenge(sk, ch.Value)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}

	if err := a.Authenticate(request("203.0.113.7:5555", "Nostr "+ch.Value+":"+sig)); err != nil {
		t.Errorf("valid signed challenge rejected: %v", err)
	}
}

// A captured Authorization header must be worthless the second time.
func TestChallengeIsSingleUse(t *testing.T) {
	a, sk := newTestAuth(t)

	ch, _ := a.NewChallenge()
	sig, _ := SignChallenge(sk, ch.Value)
	header := "Nostr " + ch.Value + ":" + sig

	if err := a.Authenticate(request("203.0.113.7:5555", header)); err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	if err := a.Authenticate(request("203.0.113.7:5555", header)); err == nil {
		t.Error("the same challenge and signature authenticated twice")
	}
}

// A failed attempt must still burn the challenge, or an attacker could grind
// signatures against a stable value.
func TestFailedSignatureStillConsumesTheChallenge(t *testing.T) {
	a, _ := newTestAuth(t)
	other, _ := nostr.GeneratePrivateKey()

	ch, _ := a.NewChallenge()
	wrongSig, _ := SignChallenge(other, ch.Value)

	if err := a.Authenticate(request("203.0.113.7:5555", "Nostr "+ch.Value+":"+wrongSig)); err == nil {
		t.Fatal("a signature from the wrong key was accepted")
	}

	// Now the real owner cannot use it either — it is spent.
	if err := a.VerifyChallenge(ch.Value, wrongSig); !errors.Is(err, ErrChallengeUnknown) {
		t.Errorf("err = %v, want ErrChallengeUnknown after a failed attempt", err)
	}
}

func TestChallengeExpires(t *testing.T) {
	a, sk := newTestAuth(t)

	ch, _ := a.NewChallenge()
	sig, _ := SignChallenge(sk, ch.Value)

	a.now = func() time.Time { return time.Now().Add(ChallengeTTL + time.Second) }

	if err := a.VerifyChallenge(ch.Value, sig); !errors.Is(err, ErrChallengeUnknown) {
		t.Errorf("err = %v, want ErrChallengeUnknown for an expired challenge", err)
	}
}

func TestSignatureFromWrongKeyRejected(t *testing.T) {
	a, _ := newTestAuth(t)
	impostor, _ := nostr.GeneratePrivateKey()

	ch, _ := a.NewChallenge()
	sig, _ := SignChallenge(impostor, ch.Value)

	if err := a.VerifyChallenge(ch.Value, sig); err == nil {
		t.Error("a signature from a different key was accepted")
	}
}

func TestUnknownChallengeRejected(t *testing.T) {
	a, sk := newTestAuth(t)
	sig, _ := SignChallenge(sk, "never-issued")

	if err := a.VerifyChallenge("never-issued", sig); !errors.Is(err, ErrChallengeUnknown) {
		t.Errorf("err = %v, want ErrChallengeUnknown", err)
	}
}

func TestNoCredentialsRejected(t *testing.T) {
	a, _ := newTestAuth(t)
	for _, header := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "Nostr malformed"} {
		if err := a.Authenticate(request("127.0.0.1:5555", header)); err == nil {
			t.Errorf("Authorization %q was accepted", header)
		}
	}
}

func TestMiddlewareBlocksAndAdvertises(t *testing.T) {
	a, _ := newTestAuth(t)
	reached := false
	h := a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("203.0.113.7:5555", ""))

	if reached {
		t.Error("the handler ran for an unauthenticated request")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("no WWW-Authenticate header telling the client how to authenticate")
	}
}

func TestMiddlewarePassesAuthenticatedRequests(t *testing.T) {
	a, _ := newTestAuth(t)
	reached := false
	h := a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("127.0.0.1:5555", "Bearer test-token"))

	if !reached {
		t.Error("an authenticated request did not reach the handler")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestChallengeFloodIsBounded(t *testing.T) {
	a, _ := newTestAuth(t)
	for i := 0; i < maxChallenges; i++ {
		if _, err := a.NewChallenge(); err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
	}
	if _, err := a.NewChallenge(); err == nil {
		t.Error("challenge issuance is unbounded")
	}
}

func TestLoadOrCreateTokenIsStableAndPrivate(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateToken: %v", err)
	}
	if len(first) != tokenBytes*2 {
		t.Errorf("token length = %d, want %d hex chars", len(first), tokenBytes*2)
	}

	second, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateToken: %v", err)
	}
	if first != second {
		t.Error("the admin token changed between reads")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(TokenPath(dir))
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("token file mode = %04o, want 0600", perm)
		}
	}
}
