// Package publish pins the presence page to IPFS.
//
// This is the "auto-archival" half of the plan's anti-lock-in promise: the
// export bundle is content-addressed and pinned, so the page survives this
// server going away. denly does not run an IPFS node — it talks to one the
// user already trusts, either a local Kubo daemon or a pinning service, which
// keeps the choice of who sees published content with the user.
//
// Only published content is pinned. Drafts stay local: pinning is effectively
// irreversible, and quietly making someone's unpublished writing
// content-addressed and public would be the worst kind of surprise.
package publish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fomothy/denly.xyz/internal/backup"
	"github.com/fomothy/denly.xyz/internal/profile"
	"github.com/fomothy/denly.xyz/internal/store"
)

// Meta keys recording the most recent pin.
const (
	MetaLastCID       = "ipfs_last_cid"
	MetaLastPublished = "ipfs_last_published_at"
)

// ErrNotConfigured is returned when no IPFS endpoint has been set.
var ErrNotConfigured = errors.New(
	"no IPFS endpoint configured; set DENLY_IPFS_API to a Kubo node (e.g. http://127.0.0.1:5001) " +
		"or DENLY_IPFS_SERVICE and DENLY_IPFS_TOKEN for a pinning service")

// Record describes the last successful publish.
type Record struct {
	CID         string    `json:"cid"`
	PublishedAt time.Time `json:"published_at"`
	GatewayURL  string    `json:"gateway_url,omitempty"`
}

// Service pins presence content.
type Service struct {
	store   *store.Store
	profile *profile.Service
	pinner  backup.Pinner
	now     func() time.Time
}

// New builds a Service. pinner may be nil, in which case Publish reports
// ErrNotConfigured rather than failing at startup — an instance with no IPFS
// endpoint is a perfectly normal instance.
func New(st *store.Store, prof *profile.Service, pinner backup.Pinner) *Service {
	return &Service{
		store:   st,
		profile: prof,
		pinner:  pinner,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// Configured reports whether an IPFS endpoint is available.
func (s *Service) Configured() bool { return s.pinner != nil }

// Publish exports the public presence page and pins it, returning the CID.
//
// The bundle pinned here is the *public* view — published posts only — unlike
// the owner's export, which includes drafts.
func (s *Service) Publish(ctx context.Context, publicKey string) (Record, error) {
	if s.pinner == nil {
		return Record{}, ErrNotConfigured
	}

	bundle, err := s.publicBundle(ctx, publicKey)
	if err != nil {
		return Record{}, err
	}

	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return Record{}, fmt.Errorf("encoding presence bundle: %w", err)
	}

	cid, err := s.pinner.Pin(ctx, "denly-presence.json", raw)
	if err != nil {
		return Record{}, err
	}

	now := s.now()
	if err := s.store.SetMeta(ctx, MetaLastCID, cid); err != nil {
		// The pin succeeded; failing to record it is worth reporting but the
		// content is safely stored either way.
		return Record{}, fmt.Errorf("pinned as %s but could not record it: %w", cid, err)
	}
	if err := s.store.SetMeta(ctx, MetaLastPublished, now.Format(time.RFC3339)); err != nil {
		return Record{}, fmt.Errorf("pinned as %s but could not record the time: %w", cid, err)
	}

	return Record{CID: cid, PublishedAt: now, GatewayURL: GatewayURL(cid)}, nil
}

// Last returns the most recent publish, if there has been one.
func (s *Service) Last(ctx context.Context) (Record, bool, error) {
	cid, err := s.store.Meta(ctx, MetaLastCID)
	if errors.Is(err, store.ErrNotFound) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}

	rec := Record{CID: cid, GatewayURL: GatewayURL(cid)}
	if ts, err := s.store.Meta(ctx, MetaLastPublished); err == nil {
		rec.PublishedAt, _ = time.Parse(time.RFC3339, ts)
	}
	return rec, true, nil
}

// publicBundle builds the export with drafts excluded.
func (s *Service) publicBundle(ctx context.Context, publicKey string) (profile.Bundle, error) {
	p, err := s.profile.Get(ctx)
	if err != nil {
		return profile.Bundle{}, err
	}
	links, err := s.profile.Links(ctx)
	if err != nil {
		return profile.Bundle{}, err
	}
	posts, err := s.profile.Posts(ctx, true) // published only
	if err != nil {
		return profile.Bundle{}, err
	}

	return profile.Bundle{
		Version:    1,
		ExportedAt: s.now(),
		PublicKey:  publicKey,
		Profile:    p,
		Links:      links,
		Posts:      posts,
	}, nil
}

// GatewayURL renders a public gateway link for a CID.
//
// ipfs.io is a convenience for sharing, not where the content lives — the CID
// resolves through any gateway or a local node, which is the point.
func GatewayURL(cid string) string {
	if cid == "" {
		return ""
	}
	return "https://ipfs.io/ipfs/" + cid
}
