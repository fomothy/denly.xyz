// Command denly is the server, CLI client, and admin tool for a denly
// instance — one binary, per the plan's "CLI is first-class" commitment.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fomothy/denly.xyz/internal/auth"
	"github.com/fomothy/denly.xyz/internal/backup"
	"github.com/fomothy/denly.xyz/internal/buildinfo"
	"github.com/fomothy/denly.xyz/internal/config"
	"github.com/fomothy/denly.xyz/internal/drop"
	"github.com/fomothy/denly.xyz/internal/identity"
	"github.com/fomothy/denly.xyz/internal/keyring"
	"github.com/fomothy/denly.xyz/internal/nostr"
	"github.com/fomothy/denly.xyz/internal/profile"
	"github.com/fomothy/denly.xyz/internal/publish"
	"github.com/fomothy/denly.xyz/internal/server"
	"github.com/fomothy/denly.xyz/internal/store"
)

const usage = `denly — your own corner of the internet.

Usage:
  denly <command> [flags]

Commands:
  init       Create this instance's identity key
  serve      Run the denly server
  whoami     Print this instance's identity
  drop       Encrypt a file locally and upload the ciphertext
  publish    Pin the public presence page to IPFS
  backup     Write an encrypted archive of the data directory
  restore    Restore an encrypted archive
  version    Print version information
  help       Show this message

Run "denly <command> -h" for command-specific flags.

Environment:
  DENLY_DATA_DIR   Override the data directory
  DENLY_ADDR       Override the listen address

Docs: https://denly.xyz
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Signal-initiated shutdown is a normal exit, not a failure.
		if errors.Is(err, context.Canceled) {
			return
		}
		fmt.Fprintf(os.Stderr, "denly: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "serve":
		return runServe(args[1:])
	case "whoami":
		return runWhoami(args[1:])
	case "drop":
		return runDrop(args[1:])
	case "publish":
		return runPublish(args[1:])
	case "backup":
		return runBackup(args[1:])
	case "restore":
		return runRestore(args[1:])
	case "version", "--version", "-v":
		return runVersion(args[1:])
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var (
		addr    = fs.String("addr", "", "listen address (default "+config.DefaultAddr+")")
		dataDir = fs.String("data-dir", "", "data directory (default: platform-specific)")
		logJSON = fs.Bool("log-json", false, "emit structured JSON logs")
		verbose = fs.Bool("v", false, "verbose (debug) logging")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: denly serve [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Resolve(*dataDir, *addr)
	if err != nil {
		return err
	}
	if err := config.EnsureDataDir(cfg.DataDir); err != nil {
		return err
	}

	log := newLogger(*logJSON, *verbose)

	// Cancel on SIGINT/SIGTERM so the server drains in-flight requests and the
	// database closes cleanly — important when systemd restarts the unit.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, config.DBPath(cfg.DataDir))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }() // checked explicitly below; this covers early returns

	// The identity is optional at boot. `denly serve` before `denly init` is a
	// legitimate state — the instance runs, serves nothing identity-shaped, and
	// says so — rather than refusing to start.
	var owner *nostr.PublicKey
	if keyring.Exists(cfg.DataDir) {
		k, err := keyring.Load(cfg.DataDir)
		if err != nil {
			return err
		}
		pk := k.PublicKey()
		owner = &pk
		log.Info("identity loaded", "pubkey", pk.Hex())
	} else {
		log.Warn("no identity yet; run `denly init` to create one")
	}

	token, err := auth.LoadOrCreateToken(cfg.DataDir)
	if err != nil {
		return err
	}
	var ownerKey nostr.PublicKey
	if owner != nil {
		ownerKey = *owner
	}

	prof := profile.New(st)
	pinner := newPinner(cfg, log)

	srv, err := server.New(cfg, st, log, server.Deps{
		Owner:      owner,
		Auth:       auth.New(token, ownerKey),
		Profile:    prof,
		Drops:      drop.New(st),
		Identities: identity.NewResolver(),
		Publisher:  publish.New(st, prof, pinner),
	})
	if err != nil {
		return err
	}

	// Retention is a promise, so something has to enforce it on a schedule
	// rather than only when a request happens to arrive.
	go runSweeper(ctx, drop.New(st), log)

	if err := srv.Serve(ctx); err != nil {
		return err
	}

	// Serve returns on shutdown; close the database before the process exits
	// so WAL is checkpointed rather than left for recovery on next start.
	if err := st.Close(); err != nil {
		return fmt.Errorf("closing database: %w", err)
	}
	log.Info("stopped cleanly")
	return nil
}

func runVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print version information as JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: denly version [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	info := buildinfo.Get()
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	fmt.Println(info.String())
	return nil
}

func newLogger(asJSON, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}

	if asJSON {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// runSweeper deletes expired drops, spent receive requests, and access-log rows
// past their retention window. It runs on a timer because "logs rot after 24h"
// has to be true on an idle instance too, not only on a busy one.
func runSweeper(ctx context.Context, drops *drop.Service, log *slog.Logger) {
	const interval = 15 * time.Minute

	sweep := func() {
		if n, err := drops.SweepExpired(ctx); err != nil {
			log.Error("sweeping expired drops", "error", err)
		} else if n > 0 {
			log.Info("deleted expired drops", "count", n)
		}
		if n, err := drops.SweepAccessLog(ctx); err != nil {
			log.Error("sweeping access log", "error", err)
		} else if n > 0 {
			log.Info("rotated access log entries", "count", n)
		}
		if n, err := drops.SweepRequests(ctx); err != nil {
			log.Error("sweeping receive requests", "error", err)
		} else if n > 0 {
			log.Info("deleted expired receive requests", "count", n)
		}
	}

	sweep() // once at boot, so a long downtime does not leave stale data served

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// newPinner builds the IPFS client from configuration, or returns nil when
// none is set. A nil pinner is a normal state: publishing simply reports that
// it is unconfigured rather than the server refusing to start.
func newPinner(cfg config.Config, log *slog.Logger) backup.Pinner {
	switch {
	case cfg.IPFS.KuboAPI != "":
		log.Info("IPFS publishing enabled", "via", "kubo", "endpoint", cfg.IPFS.KuboAPI)
		return backup.NewKuboPinner(cfg.IPFS.KuboAPI)
	case cfg.IPFS.ServiceURL != "" && cfg.IPFS.ServiceToken != "":
		// Endpoint only — never the token, which would otherwise end up in
		// journald and in any log the user pastes into an issue.
		log.Info("IPFS publishing enabled", "via", "pinning service", "endpoint", cfg.IPFS.ServiceURL)
		return backup.NewServicePinner(cfg.IPFS.ServiceURL, cfg.IPFS.ServiceToken)
	default:
		return nil
	}
}
