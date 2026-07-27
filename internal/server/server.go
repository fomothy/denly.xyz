// Package server implements denly's HTTP surface.
package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/fomothy/denly.xyz/internal/auth"
	"github.com/fomothy/denly.xyz/internal/buildinfo"
	"github.com/fomothy/denly.xyz/internal/config"
	"github.com/fomothy/denly.xyz/internal/drop"
	"github.com/fomothy/denly.xyz/internal/identity"
	"github.com/fomothy/denly.xyz/internal/nostr"
	"github.com/fomothy/denly.xyz/internal/profile"
	"github.com/fomothy/denly.xyz/internal/publish"
	"github.com/fomothy/denly.xyz/internal/store"
	"github.com/fomothy/denly.xyz/web"
)

// Server owns the HTTP listener and its dependencies.
type Server struct {
	cfg       config.Config
	store     *store.Store
	log       *slog.Logger
	templates *template.Template
	static    fs.FS
	started   time.Time

	// owner is nil until `denly init` has run. Endpoints that need an identity
	// check for that rather than assuming one exists.
	owner      *nostr.PublicKey
	nip05Names []string

	// ownerKey is set only by tests that need to sign as the owner. Production
	// code never holds the secret key in the server.
	ownerKey *nostr.PrivateKey

	auth       *auth.Authenticator
	profile    *profile.Service
	drops      *drop.Service
	identities *identity.Resolver
	publisher  *publish.Service

	http *http.Server
}

// Deps are the collaborators a Server needs beyond its configuration.
type Deps struct {
	Owner      *nostr.PublicKey
	NIP05Names []string
	Auth       *auth.Authenticator
	Profile    *profile.Service
	Drops      *drop.Service
	Identities *identity.Resolver
	Publisher  *publish.Service
}

// New builds a Server. Template parsing and asset mounting happen here so that
// a malformed build fails at startup rather than on a user's first request.
func New(cfg config.Config, st *store.Store, log *slog.Logger, deps Deps) (*Server, error) {
	tmpl, err := web.Templates()
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}
	static, err := web.Static()
	if err != nil {
		return nil, fmt.Errorf("mounting static assets: %w", err)
	}

	s := &Server{
		cfg:        cfg,
		store:      st,
		log:        log,
		templates:  tmpl,
		static:     static,
		started:    time.Now(),
		owner:      deps.Owner,
		nip05Names: deps.NIP05Names,
		auth:       deps.Auth,
		profile:    deps.Profile,
		drops:      deps.Drops,
		identities: deps.Identities,
		publisher:  deps.Publisher,
	}

	s.http = &http.Server{
		Addr:    cfg.Addr,
		Handler: s.routes(),

		// A public-facing instance is exposed to slow-loris style abuse, and
		// self-hosters will not tune these. Set defensible defaults here.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KiB

		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	return s, nil
}

// Handler exposes the routed handler for testing.
func (s *Server) Handler() http.Handler { return s.http.Handler }

// Serve listens and serves until ctx is cancelled, then shuts down gracefully.
// It returns only after in-flight requests finish or the drain deadline passes.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.Addr, err)
	}

	s.log.Info("denly is listening",
		"addr", ln.Addr().String(),
		"url", displayURL(ln.Addr().String()),
		"data_dir", s.cfg.DataDir,
		"version", buildinfo.Get().Version,
	)

	errCh := make(chan error, 1)
	go func() {
		err := s.http.Serve(ln)
		// A graceful Shutdown makes Serve return ErrServerClosed; that is a
		// normal exit, not a failure.
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := s.http.Shutdown(shutdownCtx); err != nil {
			// Drain deadline exceeded: force the listener closed so the
			// process can still exit rather than hanging forever.
			s.log.Warn("graceful shutdown timed out, closing connections", "error", err)
			if closeErr := s.http.Close(); closeErr != nil {
				return fmt.Errorf("forcing shutdown: %w", closeErr)
			}
		}
		<-errCh
		return nil
	}
}

// displayURL turns a listen address into something clickable in a terminal.
func displayURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	// An unspecified bind (0.0.0.0 / ::) is not a usable destination.
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + port
}
