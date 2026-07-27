// Package identity binds a denly instance to open-protocol identifiers.
//
// NIP-05 is the first: a name like you@denly.xyz that resolves, over HTTPS, to
// a Nostr public key. It is a claim made by whoever controls the domain, not a
// cryptographic proof of personhood — this package treats it that way, and the
// only assertion it will make is "this domain currently says this name maps to
// this key".
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fomothy/denly.xyz/internal/nostr"
)

// ProtocolNIP05 names the NIP-05 protocol in stored bindings.
const ProtocolNIP05 = "nip05"

// WellKnownPath is where a NIP-05 document lives.
const WellKnownPath = "/.well-known/nostr.json"

// maxDocumentBytes bounds what we will read from a remote host. A NIP-05
// document is a few hundred bytes; anything larger is a mistake or an attempt
// to make us allocate.
const maxDocumentBytes = 256 << 10

var (
	// ErrNameNotFound means the domain served a document without the name.
	ErrNameNotFound = errors.New("nip05: name not listed at that domain")
	// ErrKeyMismatch means the domain lists the name under a different key.
	ErrKeyMismatch = errors.New("nip05: name resolves to a different key")
	// ErrInvalidAddress means the input was not a name@domain address.
	ErrInvalidAddress = errors.New("nip05: address must look like name@domain")
)

// localPartPattern is the character set NIP-05 permits in the local part.
var localPartPattern = regexp.MustCompile(`^[a-z0-9\-_.]+$`)

// Document is the JSON served at /.well-known/nostr.json.
type Document struct {
	Names  map[string]string   `json:"names"`
	Relays map[string][]string `json:"relays,omitempty"`
}

// Address is a parsed NIP-05 identifier.
type Address struct {
	Name   string
	Domain string
}

// String renders the address, collapsing the reserved "_" name to the bare
// domain the way clients display it.
func (a Address) String() string {
	if a.Name == "_" {
		return a.Domain
	}
	return a.Name + "@" + a.Domain
}

// ParseAddress splits a NIP-05 address.
//
// A bare domain is accepted and treated as the reserved "_" name, which NIP-05
// defines as the root identity for that domain.
func ParseAddress(s string) (Address, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return Address{}, fmt.Errorf("%w: empty", ErrInvalidAddress)
	}

	name, domain := "_", s
	if at := strings.LastIndex(s, "@"); at >= 0 {
		name, domain = s[:at], s[at+1:]
	}

	if name == "" || !localPartPattern.MatchString(name) {
		return Address{}, fmt.Errorf("%w: %q is not a valid name", ErrInvalidAddress, name)
	}
	if domain == "" || strings.ContainsAny(domain, "/\\ ") || !strings.Contains(domain, ".") {
		return Address{}, fmt.Errorf("%w: %q is not a valid domain", ErrInvalidAddress, domain)
	}
	return Address{Name: name, Domain: domain}, nil
}

// Resolver looks up NIP-05 addresses over HTTPS.
type Resolver struct {
	client *http.Client
	// baseURL, when set, replaces https://<domain> — used by tests. Never set
	// it in production: it would let a caller redirect verification.
	baseURL string
}

// NewResolver builds a resolver with defensible network limits.
func NewResolver() *Resolver {
	return &Resolver{
		client: &http.Client{
			Timeout: 10 * time.Second,
			// NIP-05 verification is an assertion by a specific domain. If it
			// redirects elsewhere, that other host's answer is not the one we
			// asked for, so do not follow.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				MaxIdleConnsPerHost:   2,
			},
		},
	}
}

// Resolve fetches the public key a domain publishes for an address.
func (r *Resolver) Resolve(ctx context.Context, addr Address) (nostr.PublicKey, error) {
	var zero nostr.PublicKey

	endpoint := fmt.Sprintf("https://%s%s?name=%s",
		addr.Domain, WellKnownPath, url.QueryEscape(addr.Name))
	if r.baseURL != "" {
		endpoint = fmt.Sprintf("%s%s?name=%s", r.baseURL, WellKnownPath, url.QueryEscape(addr.Name))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return zero, fmt.Errorf("nip05: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return zero, fmt.Errorf("nip05: fetching %s: %w", addr.Domain, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("nip05: %s returned HTTP %d", addr.Domain, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return zero, fmt.Errorf("nip05: reading response from %s: %w", addr.Domain, err)
	}

	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return zero, fmt.Errorf("nip05: %s served invalid JSON: %w", addr.Domain, err)
	}

	// NIP-05 names are case-insensitive in practice; compare accordingly
	// rather than failing on a capitalised entry.
	for name, keyHex := range doc.Names {
		if !strings.EqualFold(name, addr.Name) {
			continue
		}
		pk, err := nostr.PublicKeyFromHex(strings.TrimSpace(keyHex))
		if err != nil {
			return zero, fmt.Errorf("nip05: %s lists an unusable key for %q: %w", addr.Domain, addr.Name, err)
		}
		return pk, nil
	}
	return zero, fmt.Errorf("%w: %s", ErrNameNotFound, addr)
}

// Verify checks that an address resolves to the expected key.
func (r *Resolver) Verify(ctx context.Context, addr Address, want nostr.PublicKey) error {
	got, err := r.Resolve(ctx, addr)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: %s lists %s, expected %s",
			ErrKeyMismatch, addr, got.Hex(), want.Hex())
	}
	return nil
}

// BuildDocument renders the NIP-05 document this instance serves.
//
// The reserved "_" name is always present so that the bare domain resolves to
// the owner, and any additional names are aliases for the same key. denly hosts
// one identity, so there is nothing else to list.
func BuildDocument(owner nostr.PublicKey, extraNames []string) Document {
	doc := Document{Names: map[string]string{"_": owner.Hex()}}
	for _, name := range extraNames {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || !localPartPattern.MatchString(name) {
			continue
		}
		doc.Names[name] = owner.Hex()
	}
	return doc
}
