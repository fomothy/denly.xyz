package deadhand

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Where a fired payload goes.
//
// The plan's promise is that a switch outlives the server it was armed on, so
// releasing to local disk alone is not a release at all. Two destinations:
//
//   - IPFS, via the pinner denly already uses for the presence page. Content
//     addressed and cheap, but it stays available only while something pins it.
//   - Arweave, via a bundler service. Pay once, stored for the long term —
//     which is the actual requirement for a switch that may not fire for
//     decades.
//
// Both are optional and independent. A switch released to neither stays on the
// server and the engine says so loudly rather than pretending it published.

// Pinner is the IPFS interface, matching internal/backup.Pinner so the same
// client serves both. Duplicated as a local interface rather than imported to
// keep the dependency pointing one way.
type Pinner interface {
	Pin(ctx context.Context, name string, content []byte) (string, error)
}

// Permanence writes bytes somewhere that does not require ongoing payment.
type Permanence interface {
	Store(ctx context.Context, name string, content []byte) (txID string, err error)
}

// ErrNoDestination is returned when a release has nowhere to go.
var ErrNoDestination = errors.New(
	"deadhand: no release destination configured; set an IPFS endpoint or an Arweave bundler, " +
		"or the payload will only ever exist on this server")

// Publisher releases payloads to IPFS and, optionally, Arweave.
type Publisher struct {
	pinner     Pinner
	permanence Permanence
}

// NewPublisher builds a Releaser. Either destination may be nil.
func NewPublisher(pinner Pinner, permanence Permanence) *Publisher {
	return &Publisher{pinner: pinner, permanence: permanence}
}

// Configured reports whether a release can actually leave this machine.
func (p *Publisher) Configured() bool { return p.pinner != nil || p.permanence != nil }

// Release publishes a sealed payload, returning where it landed.
//
// Arweave failing does not fail the release when IPFS succeeded: the payload
// is out and reachable, which is what matters at the moment a switch fires.
// The reverse is also true. Only both failing is a failure.
func (p *Publisher) Release(ctx context.Context, switchID string, payload []byte) (string, string, error) {
	if !p.Configured() {
		return "", "", ErrNoDestination
	}

	name := "denly-deadhand-" + switchID + ".json"

	var (
		cid, txID string
		problems  []string
	)

	if p.pinner != nil {
		c, err := p.pinner.Pin(ctx, name, payload)
		if err != nil {
			problems = append(problems, "ipfs: "+err.Error())
		} else {
			cid = c
		}
	}

	if p.permanence != nil {
		t, err := p.permanence.Store(ctx, name, payload)
		if err != nil {
			problems = append(problems, "arweave: "+err.Error())
		} else {
			txID = t
		}
	}

	if cid == "" && txID == "" {
		return "", "", fmt.Errorf("deadhand: every release destination failed: %s",
			strings.Join(problems, "; "))
	}
	return cid, txID, nil
}

/* ----------------------------------------------------------- arweave ----- */

// ArweaveBundler uploads through a bundler service such as Irys, which accepts
// a signed HTTP upload and settles onto Arweave.
//
// denly deliberately does not hold an Arweave wallet or sign transactions
// itself: that would mean carrying a second kind of key with real money
// attached, inside a binary whose entire pitch is that it holds nothing
// valuable. A bundler token is revocable and buys exactly one capability.
type ArweaveBundler struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

// NewArweaveBundler builds a permanence client.
func NewArweaveBundler(endpoint, token string) *ArweaveBundler {
	return &ArweaveBundler{
		Endpoint: strings.TrimRight(endpoint, "/"),
		Token:    token,
		// Generous: a permanence upload settles on-chain and is the last thing
		// standing between a fired switch and it being lost.
		Client: &http.Client{Timeout: 5 * time.Minute},
	}
}

// Configured reports whether uploads can be attempted.
func (a *ArweaveBundler) Configured() bool { return a.Endpoint != "" && a.Token != "" }

// Store uploads content and returns the transaction ID.
func (a *ArweaveBundler) Store(ctx context.Context, name string, content []byte) (string, error) {
	if !a.Configured() {
		return "", errors.New("deadhand: Arweave bundler is not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Endpoint, bytes.NewReader(content))
	if err != nil {
		return "", fmt.Errorf("deadhand: building upload: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Name", name)

	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("deadhand: reaching the Arweave bundler: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("deadhand: reading bundler response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The token can appear in a service's error text; report the status
		// only, since these logs get pasted into issues.
		return "", fmt.Errorf("deadhand: Arweave bundler returned HTTP %d", resp.StatusCode)
	}

	var parsed struct {
		ID     string `json:"id"`
		TxID   string `json:"txId"`
		Tx     string `json:"transaction"`
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("deadhand: bundler returned unreadable JSON: %w", err)
	}
	for _, candidate := range []string{parsed.ID, parsed.TxID, parsed.Tx, parsed.Result.ID} {
		if candidate != "" {
			return candidate, nil
		}
	}
	return "", errors.New("deadhand: bundler did not return a transaction id")
}

// ArweaveURL renders a gateway link for a transaction.
func ArweaveURL(txID string) string {
	if txID == "" {
		return ""
	}
	return "https://arweave.net/" + txID
}
