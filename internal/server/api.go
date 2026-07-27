package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/fomothy/denly.xyz/internal/drop"
	"github.com/fomothy/denly.xyz/internal/identity"
	"github.com/fomothy/denly.xyz/internal/profile"
	"github.com/fomothy/denly.xyz/internal/publish"
)

// JSON API for Phase 1. No HTML is rendered here — the presence page's markup
// lands in a later pass; these endpoints are the functionality beneath it.
//
// Routing rule: everything that changes state sits behind the admin
// authenticator, and everything public is read-only. The two groups are
// registered separately in routes.go so a new endpoint has to make a
// deliberate choice about which side it is on.

// writeJSON sends a value with a status code.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Error("writing json response", "error", err)
	}
}

// writeError sends a message the caller can act on, without leaking internals.
func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}

/* ----------------------------------------------------------- NIP-05 ------ */

// handleWellKnownNostr serves the NIP-05 document.
//
// It is unauthenticated and cacheable: the whole point is that other people's
// clients can fetch it. Cross-origin reads are explicitly allowed because NIP-05
// verification is performed by browser-based clients on other domains.
func (s *Server) handleWellKnownNostr(w http.ResponseWriter, r *http.Request) {
	if s.owner == nil {
		s.writeError(w, http.StatusNotFound, "this instance has no identity yet; run `denly init`")
		return
	}

	doc := identity.BuildDocument(*s.owner, s.nip05Names)

	// A client may ask for one name; NIP-05 allows returning only that entry.
	if name := r.URL.Query().Get("name"); name != "" {
		filtered := identity.Document{Names: map[string]string{}}
		if key, ok := doc.Names[name]; ok {
			filtered.Names[name] = key
		}
		doc = filtered
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		s.log.Error("writing nip05 document", "error", err)
	}
}

/* ------------------------------------------------------------ public ----- */

// handleGetProfile returns the public presence data: profile, links, and
// published posts. Drafts are excluded — that is the difference between this
// and the export.
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	p, err := s.profile.Get(ctx)
	if err != nil {
		s.log.Error("reading profile", "error", err)
		s.writeError(w, http.StatusInternalServerError, "could not read the profile")
		return
	}
	links, err := s.profile.Links(ctx)
	if err != nil {
		s.log.Error("reading links", "error", err)
		s.writeError(w, http.StatusInternalServerError, "could not read links")
		return
	}
	posts, err := s.profile.Posts(ctx, true)
	if err != nil {
		s.log.Error("reading posts", "error", err)
		s.writeError(w, http.StatusInternalServerError, "could not read posts")
		return
	}

	out := map[string]any{"profile": p, "links": links, "posts": posts}
	if s.owner != nil {
		out["public_key"] = s.owner.Hex()
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleGetPost returns one published post.
func (s *Server) handleGetPost(w http.ResponseWriter, r *http.Request) {
	post, err := s.profile.PostBySlug(r.Context(), r.PathValue("slug"))
	if errors.Is(err, profile.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no such post")
		return
	}
	if err != nil {
		s.log.Error("reading post", "error", err)
		s.writeError(w, http.StatusInternalServerError, "could not read the post")
		return
	}
	// A draft must not be readable by URL guess just because it exists.
	if !post.Published() {
		s.writeError(w, http.StatusNotFound, "no such post")
		return
	}
	s.writeJSON(w, http.StatusOK, post)
}

// handleFetchDrop serves ciphertext to whoever holds the link.
//
// There is no authentication here by design: possession of the unguessable ID
// is the capability, and the key needed to read the bytes never reaches this
// server at all.
func (s *Server) handleFetchDrop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	ciphertext, meta, err := s.drops.Fetch(r.Context(), id)
	switch {
	case errors.Is(err, drop.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "no such drop")
		return
	case errors.Is(err, drop.ErrGone):
		// 410 rather than 404: the link was real and is now spent, which is a
		// different thing for the sender to debug.
		s.writeError(w, http.StatusGone, "this drop has expired or been used up")
		return
	case err != nil:
		s.log.Error("fetching drop", "error", err)
		s.writeError(w, http.StatusInternalServerError, "could not fetch the drop")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	// The body is attacker-influenced opaque bytes. Forcing a download stops a
	// browser ever rendering it inline, whatever a sniffer decides it is.
	w.Header().Set("Content-Disposition", `attachment; filename="drop.bin"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(ciphertext)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Denly-Downloads", strconv.Itoa(meta.DownloadCount))
	// Not XSS: the body is opaque ciphertext, the content type is
	// application/octet-stream, nosniff is set globally, and Content-Disposition
	// above forces a download rather than inline rendering.
	if _, err := w.Write(ciphertext); err != nil { //nolint:gosec // G705: opaque bytes served as an attachment
		s.log.Error("writing drop body", "error", err)
	}
}

// handleRequestReceive lets a stranger ask to send a file.
//
// Unauthenticated on purpose — that is what a receive box is — but it stores
// only a note, and no bytes can be uploaded until the owner approves.
func (s *Server) handleRequestReceive(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Note     string `json:"note"`
		SizeHint int64  `json:"size_hint"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	req, err := s.drops.RequestReceive(r.Context(), body.Note, body.SizeHint)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, req)
}

// handleUploadToRequest accepts ciphertext against an approved request.
func (s *Server) handleUploadToRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	ciphertext, err := io.ReadAll(io.LimitReader(r.Body, drop.MaxCiphertext+1))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "could not read the upload")
		return
	}
	if len(ciphertext) > drop.MaxCiphertext {
		s.writeError(w, http.StatusRequestEntityTooLarge, "that file is too large")
		return
	}

	created, err := s.drops.FulfilRequest(r.Context(), id, ciphertext, drop.Options{})
	switch {
	case errors.Is(err, drop.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "no such request")
	case errors.Is(err, drop.ErrRequestNotPending):
		s.writeError(w, http.StatusForbidden, "this request has not been approved")
	case errors.Is(err, drop.ErrGone):
		s.writeError(w, http.StatusGone, "this request has expired")
	case err != nil:
		s.writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.writeJSON(w, http.StatusCreated, created)
	}
}

// handleChallenge issues an auth challenge. Public because you need one before
// you can authenticate.
func (s *Server) handleChallenge(w http.ResponseWriter, _ *http.Request) {
	ch, err := s.auth.NewChallenge()
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, ch)
}

/* ------------------------------------------------------------- admin ----- */

func (s *Server) handleSaveProfile(w http.ResponseWriter, r *http.Request) {
	var p profile.Profile
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		s.writeError(w, http.StatusBadRequest, "could not read the profile")
		return
	}
	if err := s.profile.Save(r.Context(), p); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) handleAddLink(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label    string `json:"label"`
		URL      string `json:"url"`
		Position int    `json:"position"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "could not read the link")
		return
	}
	link, err := s.profile.AddLink(r.Context(), body.Label, body.URL, body.Position)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, link)
}

func (s *Server) handleDeleteLink(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "link id must be a number")
		return
	}
	if err := s.profile.DeleteLink(r.Context(), id); errors.Is(err, profile.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no such link")
		return
	} else if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not delete the link")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSavePost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Title   string `json:"title"`
		Body    string `json:"body"`
		Publish bool   `json:"publish"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "could not read the post")
		return
	}
	post, err := s.profile.SavePost(r.Context(), body.Title, body.Body, body.Publish)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, post)
}

func (s *Server) handleListPostsAdmin(w http.ResponseWriter, r *http.Request) {
	posts, err := s.profile.Posts(r.Context(), false) // drafts included
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read posts")
		return
	}
	s.writeJSON(w, http.StatusOK, posts)
}

func (s *Server) handleDeletePost(w http.ResponseWriter, r *http.Request) {
	if err := s.profile.DeletePost(r.Context(), r.PathValue("slug")); errors.Is(err, profile.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no such post")
		return
	} else if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not delete the post")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleExport returns the whole presence page as a portable bundle, drafts
// included. This is the anti-lock-in promise, so it is one request with no
// pagination and no format negotiation.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	var pubkey string
	if s.owner != nil {
		pubkey = s.owner.Hex()
	}

	raw, err := s.profile.ExportJSON(r.Context(), pubkey)
	if err != nil {
		s.log.Error("building export", "error", err)
		s.writeError(w, http.StatusInternalServerError, "could not build the export")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="denly-export-`+time.Now().UTC().Format("2006-01-02")+`.json"`)
	if _, err := w.Write(raw); err != nil {
		s.log.Error("writing export", "error", err)
	}
}

func (s *Server) handleCreateDrop(w http.ResponseWriter, r *http.Request) {
	ciphertext, err := io.ReadAll(io.LimitReader(r.Body, drop.MaxCiphertext+1))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "could not read the upload")
		return
	}
	if len(ciphertext) > drop.MaxCiphertext {
		s.writeError(w, http.StatusRequestEntityTooLarge, "that file is too large")
		return
	}

	opts := drop.Options{}
	if v := r.URL.Query().Get("expires"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "expires must be a duration like 24h")
			return
		}
		opts.TTL = d
	}
	if v := r.URL.Query().Get("burn_after"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "burn_after must be a number")
			return
		}
		opts.MaxDownloads = n
	}

	created, err := s.drops.Create(r.Context(), ciphertext, opts)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleListDrops(w http.ResponseWriter, r *http.Request) {
	drops, err := s.drops.List(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not list drops")
		return
	}
	s.writeJSON(w, http.StatusOK, drops)
}

func (s *Server) handleDeleteDrop(w http.ResponseWriter, r *http.Request) {
	if err := s.drops.Delete(r.Context(), r.PathValue("id")); errors.Is(err, drop.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no such drop")
		return
	} else if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not delete the drop")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	reqs, err := s.drops.PendingRequests(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not list requests")
		return
	}
	s.writeJSON(w, http.StatusOK, reqs)
}

func (s *Server) handleDecideRequest(w http.ResponseWriter, r *http.Request) {
	approve := r.PathValue("decision") == "approve"

	req, err := s.drops.Decide(r.Context(), r.PathValue("id"), approve)
	switch {
	case errors.Is(err, drop.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "no such request")
	case errors.Is(err, drop.ErrRequestNotPending):
		s.writeError(w, http.StatusConflict, "that request has already been decided")
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "could not record the decision")
	default:
		s.writeJSON(w, http.StatusOK, req)
	}
}

// handleVerifyIdentity checks a NIP-05 address against this instance's key.
func (s *Server) handleVerifyIdentity(w http.ResponseWriter, r *http.Request) {
	if s.owner == nil {
		s.writeError(w, http.StatusConflict, "this instance has no identity yet")
		return
	}

	var body struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "could not read the request")
		return
	}

	addr, err := identity.ParseAddress(body.Address)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.identities.Verify(r.Context(), addr, *s.owner); err != nil {
		// This is a report on someone else's DNS and web server, not an error
		// in this request — 200 with a verdict is more useful than a 4xx.
		s.writeJSON(w, http.StatusOK, map[string]any{
			"address":  addr.String(),
			"verified": false,
			"error":    err.Error(),
		})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"address":  addr.String(),
		"verified": true,
	})
}

// handlePublish pins the public presence page to IPFS.
//
// Only the published view is pinned. Drafts stay local: pinning is effectively
// irreversible, and content-addressing someone's unpublished writing without
// asking would be the worst kind of surprise.
func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	var pubkey string
	if s.owner != nil {
		pubkey = s.owner.Hex()
	}

	rec, err := s.publisher.Publish(r.Context(), pubkey)
	if errors.Is(err, publish.ErrNotConfigured) {
		s.writeError(w, http.StatusPreconditionFailed, err.Error())
		return
	}
	if err != nil {
		s.log.Error("publishing to ipfs", "error", err)
		s.writeError(w, http.StatusBadGateway, "could not pin to IPFS: "+err.Error())
		return
	}

	s.log.Info("pinned presence page", "cid", rec.CID)
	s.writeJSON(w, http.StatusOK, rec)
}

// handlePublishStatus reports the most recent pin.
func (s *Server) handlePublishStatus(w http.ResponseWriter, r *http.Request) {
	rec, ok, err := s.publisher.Last(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read publish status")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"configured": s.publisher.Configured(),
		"published":  ok,
		"last":       rec,
	})
}
