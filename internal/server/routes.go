package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fomothy/denly.xyz/internal/buildinfo"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Go 1.22+ patterns: "GET /{$}" matches only the exact root path, so
	// unknown paths fall through to a 404 instead of rendering the home page.
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("GET /static/", http.StripPrefix("/static/", s.staticHandler()))

	return s.recoverMiddleware(s.logMiddleware(securityHeaders(mux)))
}

// indexData is the template model for the status page.
type indexData struct {
	Build         buildinfo.Info
	ShortCommit   string
	IsRelease     bool
	Addr          string
	DataDir       string
	SchemaVersion int
	JournalMode   string
	Uptime        string
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	info := buildinfo.Get()

	schemaVersion, err := s.store.SchemaVersion(ctx)
	if err != nil {
		s.log.Error("reading schema version", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	journal, err := s.store.JournalMode(ctx)
	if err != nil {
		s.log.Error("reading journal mode", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := indexData{
		Build:         info,
		ShortCommit:   shortCommit(info.Commit),
		IsRelease:     buildinfo.IsRelease(),
		Addr:          s.cfg.Addr,
		DataDir:       s.cfg.DataDir,
		SchemaVersion: schemaVersion,
		JournalMode:   strings.ToUpper(journal),
		Uptime:        humanDuration(time.Since(s.started)),
	}

	// Render into a buffer first: a template error midway through a direct
	// write would emit a 200 with a truncated page.
	var buf strings.Builder
	if err := s.templates.ExecuteTemplate(&buf, "index.html", data); err != nil {
		s.log.Error("rendering index", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, buf.String())
}

// healthResponse is the /healthz body. Kept small and stable: monitoring and
// the install script both parse it.
type healthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	SchemaVersion int    `json:"schema_version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Bound the check so a wedged database cannot make health checks hang and
	// pile up connections.
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	info := buildinfo.Get()
	resp := healthResponse{
		Status:        "ok",
		Version:       info.Version,
		Commit:        shortCommit(info.Commit),
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
	}

	status := http.StatusOK
	if err := s.store.Ping(ctx); err != nil {
		s.log.Error("health check: database unreachable", "error", err)
		resp.Status = "degraded"
		status = http.StatusServiceUnavailable
	} else if v, err := s.store.SchemaVersion(ctx); err == nil {
		resp.SchemaVersion = v
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Error("writing health response", "error", err)
	}
}

// staticHandler serves embedded assets. Assets are immutable per build, but
// they are versioned only by the binary, so a short cache lifetime keeps an
// upgrade from serving stale CSS.
func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		fileServer.ServeHTTP(w, r)
	})
}

// securityHeaders applies a strict baseline. The CSP is deliberately tight:
// denly ships no inline scripts and no third-party assets, so nothing here
// needs loosening, and Phase 1's client-side crypto benefits from the page
// being unable to load foreign code.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self' data:; "+
				"script-src 'self'; connect-src 'self'; form-action 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	if c == "" {
		return "none"
	}
	return c
}

// humanDuration renders a coarse, readable uptime.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}
