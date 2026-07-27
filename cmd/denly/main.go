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

	"github.com/fomothy/denly.xyz/internal/buildinfo"
	"github.com/fomothy/denly.xyz/internal/config"
	"github.com/fomothy/denly.xyz/internal/server"
	"github.com/fomothy/denly.xyz/internal/store"
)

const usage = `denly — your own corner of the internet.

Usage:
  denly <command> [flags]

Commands:
  serve      Run the denly server
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
	case "serve":
		return runServe(args[1:])
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

	srv, err := server.New(cfg, st, log)
	if err != nil {
		return err
	}

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
