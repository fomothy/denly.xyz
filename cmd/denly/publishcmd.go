package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fomothy/denly.xyz/internal/backup"
	"github.com/fomothy/denly.xyz/internal/config"
	"github.com/fomothy/denly.xyz/internal/keyring"
	"github.com/fomothy/denly.xyz/internal/profile"
	"github.com/fomothy/denly.xyz/internal/publish"
	"github.com/fomothy/denly.xyz/internal/store"
)

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	var (
		dataDir = fs.String("data-dir", "", "data directory (default: platform-specific)")
		status  = fs.Bool("status", false, "show the last publish instead of publishing")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: denly publish [flags]

Pins the public presence page to IPFS so it survives this server going away.
Only published posts are included; drafts stay local.

Configure one of:
  DENLY_IPFS_API      a Kubo node, e.g. http://127.0.0.1:5001
  DENLY_IPFS_SERVICE  a pinning service upload endpoint
  DENLY_IPFS_TOKEN    bearer token for that service

Flags:
`)
		fs.PrintDefaults()
	}
	if _, err := parsePermuted(fs, args); err != nil {
		return err
	}

	cfg, err := config.Resolve(*dataDir, "")
	if err != nil {
		return err
	}

	// Operates on the database directly rather than through the HTTP API, so
	// it works whether or not `denly serve` is running.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	st, err := store.Open(ctx, config.DBPath(cfg.DataDir))
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	var pinner backup.Pinner
	switch {
	case cfg.IPFS.KuboAPI != "":
		pinner = backup.NewKuboPinner(cfg.IPFS.KuboAPI)
	case cfg.IPFS.ServiceURL != "" && cfg.IPFS.ServiceToken != "":
		pinner = backup.NewServicePinner(cfg.IPFS.ServiceURL, cfg.IPFS.ServiceToken)
	}

	svc := publish.New(st, profile.New(st), pinner)

	if *status {
		rec, ok, err := svc.Last(ctx)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Never published.")
			if !svc.Configured() {
				fmt.Println()
				fmt.Println("No IPFS endpoint is configured; see `denly publish -h`.")
			}
			return nil
		}
		fmt.Printf("Last published %s\n", rec.PublishedAt.Format(time.RFC1123))
		fmt.Printf("  cid      %s\n", rec.CID)
		fmt.Printf("  gateway  %s\n", rec.GatewayURL)
		return nil
	}

	var pubkey string
	if keyring.Exists(cfg.DataDir) {
		k, err := keyring.Load(cfg.DataDir)
		if err != nil {
			return err
		}
		pubkey = k.PublicKey().Hex()
	}

	rec, err := svc.Publish(ctx, pubkey)
	if errors.Is(err, publish.ErrNotConfigured) {
		// Not an internal failure — the user simply has not chosen where to
		// pin yet, so say what to do rather than printing a stack of causes.
		fmt.Fprintln(os.Stderr, err)
		return errors.New("nothing published")
	}
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Pinned the public presence page to IPFS.")
	fmt.Fprintf(os.Stderr, "  gateway  %s\n", rec.GatewayURL)
	fmt.Fprintln(os.Stderr)

	// The CID alone on stdout, so it can be piped into a DNSLink update or a
	// commit message without stripping commentary.
	fmt.Println(rec.CID)
	return nil
}
