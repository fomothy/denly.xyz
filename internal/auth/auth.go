// Package auth guards denly's mutable endpoints.
//
// There are no passwords, by design. A password would be a second secret to
// lose, phish, or reuse, on top of the identity key that already proves who
// you are. Instead:
//
//   - From loopback, a request is trusted if it carries the admin token that
//     `denly serve` writes into the data directory. Reading that file already
//     requires being the user who owns the instance.
//   - From anywhere else, the caller must sign a short-lived, single-use
//     challenge with the instance's identity key. Possession of the key is the
//     only credential, and a captured signature is worthless once used.
//
// This lands with the first mutable endpoint rather than after it. Retrofitting
// auth onto existing write paths is how endpoints get missed.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fomothy/denly.xyz/internal/nostr"
)

// TokenFileName holds the loopback admin token inside the data directory.
const TokenFileName = "admin-token"

const (
	// ChallengeTTL bounds how long a challenge stays usable. Long enough to
	// sign in another tool, short enough that a leaked challenge is stale
	// before it is useful.
	ChallengeTTL = 2 * time.Minute

	// maxChallenges caps memory so an unauthenticated caller cannot exhaust
	// it by requesting challenges in a loop.
	maxChallenges = 256

	tokenBytes = 32
)

var (
	// ErrUnauthorized is returned when a request carries no valid credential.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrChallengeUnknown is returned for an expired, unknown, or already-used
	// challenge.
	ErrChallengeUnknown = errors.New("unknown or expired challenge")
)

// Authenticator validates admin requests.
type Authenticator struct {
	token  string
	owner  nostr.PublicKey
	now    func() time.Time
	mu     sync.Mutex
	issued map[string]time.Time
}

// New builds an Authenticator for the given owner identity and admin token.
func New(token string, owner nostr.PublicKey) *Authenticator {
	return &Authenticator{
		token:  token,
		owner:  owner,
		now:    time.Now,
		issued: make(map[string]time.Time),
	}
}

// TokenPath returns the admin token path inside a data directory.
func TokenPath(dataDir string) string { return filepath.Join(dataDir, TokenFileName) }

// LoadOrCreateToken reads the admin token, generating one on first run.
//
// The token is regenerated if the file is unreadable rather than failing
// startup: a server that will not boot is worse than one that invalidates a
// token the user can simply re-read.
func LoadOrCreateToken(dataDir string) (string, error) {
	path := TokenPath(dataDir)

	if raw, err := os.ReadFile(path); err == nil {
		if token := strings.TrimSpace(string(raw)); len(token) == tokenBytes*2 {
			return token, nil
		}
	}

	raw, err := nostr.RandomBytes(tokenBytes)
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)

	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("writing admin token: %w", err)
	}
	return token, nil
}

// Challenge is a one-time value the caller must sign.
type Challenge struct {
	Value     string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewChallenge issues a single-use challenge.
func (a *Authenticator) NewChallenge() (Challenge, error) {
	raw, err := nostr.RandomBytes(32)
	if err != nil {
		return Challenge{}, err
	}
	value := hex.EncodeToString(raw)
	now := a.now()

	a.mu.Lock()
	defer a.mu.Unlock()

	a.pruneLocked(now)
	if len(a.issued) >= maxChallenges {
		// Every remaining entry is unexpired, so the caller is flooding us.
		// Refuse rather than evicting a challenge someone is mid-way through
		// signing.
		return Challenge{}, errors.New("too many outstanding challenges; try again shortly")
	}
	a.issued[value] = now.Add(ChallengeTTL)

	return Challenge{Value: value, ExpiresAt: now.Add(ChallengeTTL)}, nil
}

// VerifyChallenge consumes a challenge and checks its signature against the
// owner's key. A challenge is valid at most once, so a captured Authorization
// header cannot be replayed.
func (a *Authenticator) VerifyChallenge(value, signatureHex string) error {
	a.mu.Lock()
	expiry, ok := a.issued[value]
	if ok {
		delete(a.issued, value) // single use, even if the signature fails
	}
	a.mu.Unlock()

	if !ok || a.now().After(expiry) {
		return ErrChallengeUnknown
	}

	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("%w: signature is not hex", ErrUnauthorized)
	}

	digest := sha256.Sum256([]byte(value))
	if err := a.owner.Verify(digest[:], sig); err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return nil
}

// SignChallenge produces the signature a client must send. It lives here so
// the CLI and the tests exercise exactly the same construction the server
// verifies.
func SignChallenge(sk *nostr.PrivateKey, value string) (string, error) {
	digest := sha256.Sum256([]byte(value))
	sig, err := sk.Sign(digest[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

// Authenticate reports whether a request may perform admin actions.
func (a *Authenticator) Authenticate(r *http.Request) error {
	scheme, credential := parseAuthorization(r.Header.Get("Authorization"))

	switch strings.ToLower(scheme) {
	case "bearer":
		// The token alone is not enough from off-machine: anything that could
		// read it could also read the identity key, but a token can also leak
		// through proxies, logs, and browser history in a way loopback cannot.
		if !isLoopback(r) {
			return fmt.Errorf("%w: token auth is only accepted from localhost; sign a challenge instead", ErrUnauthorized)
		}
		if subtle.ConstantTimeCompare([]byte(credential), []byte(a.token)) != 1 {
			return fmt.Errorf("%w: bad admin token", ErrUnauthorized)
		}
		return nil

	case "nostr":
		// "Nostr <challenge>:<signature>"
		parts := strings.SplitN(credential, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%w: expected `Nostr <challenge>:<signature>`", ErrUnauthorized)
		}
		return a.VerifyChallenge(parts[0], parts[1])

	case "":
		return fmt.Errorf("%w: no credentials supplied", ErrUnauthorized)

	default:
		return fmt.Errorf("%w: unsupported authorization scheme %q", ErrUnauthorized, scheme)
	}
}

// Middleware rejects unauthenticated requests before the handler runs.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := a.Authenticate(r); err != nil {
			// Advertise both routes so a client knows how to proceed, but do
			// not say which part of the credential was wrong.
			w.Header().Set("WWW-Authenticate", `Bearer realm="denly", Nostr realm="denly"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// pruneLocked drops expired challenges. Callers must hold the mutex.
func (a *Authenticator) pruneLocked(now time.Time) {
	for value, expiry := range a.issued {
		if now.After(expiry) {
			delete(a.issued, value)
		}
	}
}

func parseAuthorization(header string) (scheme, credential string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return parts[0], ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}

// isLoopback reports whether the request came from this machine.
//
// It deliberately reads RemoteAddr and ignores X-Forwarded-For: a proxy header
// is attacker-controlled, and trusting it would let anyone on the internet
// claim to be localhost.
func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
