package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// IPFS publishing for the presence page.
//
// denly does not embed an IPFS node. It talks to one the user already trusts:
// either a local Kubo daemon, or a pinning service that accepts uploads. That
// keeps the binary small and, more importantly, keeps the choice of who sees
// your published content in the user's hands rather than ours.

// ErrPinnerNotConfigured is returned when no IPFS endpoint has been set.
var ErrPinnerNotConfigured = errors.New("no IPFS endpoint configured")

// Pinner publishes bytes to IPFS and returns the resulting CID.
type Pinner interface {
	Pin(ctx context.Context, name string, content []byte) (string, error)
}

// KuboPinner talks to a Kubo (go-ipfs) HTTP API, typically a local daemon at
// http://127.0.0.1:5001.
type KuboPinner struct {
	Endpoint string
	Client   *http.Client
}

// NewKuboPinner builds a pinner for a Kubo API endpoint.
func NewKuboPinner(endpoint string) *KuboPinner {
	return &KuboPinner{
		Endpoint: strings.TrimRight(endpoint, "/"),
		Client:   &http.Client{Timeout: 60 * time.Second},
	}
}

// kuboAddResponse is the subset of /api/v0/add we care about.
type kuboAddResponse struct {
	Name string `json:"Name"`
	Hash string `json:"Hash"`
	Size string `json:"Size"`
}

// Pin uploads content and pins it, returning the CID.
func (k *KuboPinner) Pin(ctx context.Context, name string, content []byte) (string, error) {
	if k.Endpoint == "" {
		return "", ErrPinnerNotConfigured
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", name)
	if err != nil {
		return "", fmt.Errorf("building IPFS upload: %w", err)
	}
	if _, err := part.Write(content); err != nil {
		return "", fmt.Errorf("building IPFS upload: %w", err)
	}
	if err := mw.Close(); err != nil {
		return "", fmt.Errorf("building IPFS upload: %w", err)
	}

	url := k.Endpoint + "/api/v0/add?pin=true&cid-version=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		return "", fmt.Errorf("building IPFS request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := k.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("reaching the IPFS node at %s: %w", k.Endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("reading IPFS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IPFS node returned HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	// Kubo streams newline-delimited JSON, one object per added object. The
	// last line is the root, which is the CID we want.
	var last kuboAddResponse
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r kuboAddResponse
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return "", fmt.Errorf("IPFS node returned unreadable JSON: %w", err)
		}
		last, found = r, true
	}
	if !found || last.Hash == "" {
		return "", errors.New("IPFS node did not return a CID")
	}
	return last.Hash, nil
}

func (k *KuboPinner) client() *http.Client {
	if k.Client != nil {
		return k.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// ServicePinner talks to an IPFS pinning service that accepts uploads with a
// bearer token — the shape web3.storage and similar hosts use.
type ServicePinner struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

// NewServicePinner builds a pinner for a token-authenticated upload endpoint.
func NewServicePinner(endpoint, token string) *ServicePinner {
	return &ServicePinner{
		Endpoint: strings.TrimRight(endpoint, "/"),
		Token:    token,
		Client:   &http.Client{Timeout: 60 * time.Second},
	}
}

// Pin uploads content and returns the CID the service reports.
func (s *ServicePinner) Pin(ctx context.Context, name string, content []byte) (string, error) {
	if s.Endpoint == "" || s.Token == "" {
		return "", ErrPinnerNotConfigured
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(content))
	if err != nil {
		return "", fmt.Errorf("building pin request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Name", name)

	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("reaching the pinning service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("reading pinning response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The token may appear in the service's error text; do not echo the
		// body verbatim into logs the user might share.
		return "", fmt.Errorf("pinning service returned HTTP %d", resp.StatusCode)
	}

	// Accept the common shapes without pretending to support every service.
	var parsed struct {
		CID   string `json:"cid"`
		Value struct {
			CID string `json:"cid"`
		} `json:"value"`
		Hash string `json:"Hash"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("pinning service returned unreadable JSON: %w", err)
	}
	for _, candidate := range []string{parsed.CID, parsed.Value.CID, parsed.Hash} {
		if candidate != "" {
			return candidate, nil
		}
	}
	return "", errors.New("pinning service did not return a CID")
}
