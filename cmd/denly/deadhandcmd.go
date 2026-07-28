package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/fomothy/denly.xyz/internal/config"
	"github.com/fomothy/denly.xyz/internal/deadhand"
	"github.com/fomothy/denly.xyz/internal/keyring"
	"github.com/fomothy/denly.xyz/internal/nostr"
	"github.com/fomothy/denly.xyz/internal/store"
)

const deadhandUsage = `Usage: denly deadhand <subcommand> [flags]

A dead man's switch: content encrypted to people you choose, released only if
you stop checking in.

Subcommands:
  list                    Show every switch and when each one fires
  create                  Create a switch (disarmed)
  show <id>               Show one switch and its history
  arm <id>                Start the countdown
  disarm <id>             Stop the countdown
  checkin [id]            Prove you are alive; with no id, checks in everywhere
  drill <id>              Test-fire: notifies contacts, releases nothing
  fire <id>               Release now (irreversible)
  delete <id>             Delete a switch and its payload

Run "denly deadhand <subcommand> -h" for flags.
`

func runDeadhand(args []string) error {
	if len(args) == 0 {
		fmt.Print(deadhandUsage)
		return nil
	}

	switch args[0] {
	case "list":
		return deadhandList(args[1:])
	case "create":
		return deadhandCreate(args[1:])
	case "show":
		return deadhandShow(args[1:])
	case "arm":
		return deadhandSetState(args[1:], "arm")
	case "disarm":
		return deadhandSetState(args[1:], "disarm")
	case "checkin":
		return deadhandCheckIn(args[1:])
	case "drill":
		return deadhandDrill(args[1:])
	case "fire":
		return deadhandFire(args[1:])
	case "delete":
		return deadhandDelete(args[1:])
	case "help", "-h", "--help":
		fmt.Print(deadhandUsage)
		return nil
	default:
		fmt.Fprint(os.Stderr, deadhandUsage)
		return fmt.Errorf("unknown deadhand subcommand %q", args[0])
	}
}

// openDeadhand connects to the local data directory.
//
// Every subcommand works directly against the database rather than the HTTP
// API, so checking in does not depend on `denly serve` running — which matters
// when the consequence of a failed check-in is publication.
func openDeadhand(dataDir string) (*deadhand.Store, context.Context, func(), error) {
	cfg, err := config.Resolve(dataDir, "")
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)

	st, err := store.Open(ctx, config.DBPath(cfg.DataDir))
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	cleanup := func() {
		_ = st.Close()
		cancel()
	}
	return deadhand.NewStore(st), ctx, cleanup, nil
}

func deadhandList(args []string) error {
	fs := flag.NewFlagSet("deadhand list", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	if _, err := parsePermuted(fs, args); err != nil {
		return err
	}

	switches, ctx, done, err := openDeadhand(*dataDir)
	if err != nil {
		return err
	}
	defer done()

	all, err := switches.List(ctx)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Println("No switches. Create one with `denly deadhand create`.")
		return nil
	}

	for _, sw := range all {
		fmt.Printf("%s  %s\n", sw.ID, sw.Name)
		fmt.Printf("  state       %s\n", sw.State)
		fmt.Printf("  recipients  %d", len(sw.Recipients))
		if sw.Threshold > 0 {
			fmt.Printf(", guardian threshold %d", sw.Threshold)
		}
		fmt.Println()

		switch sw.State {
		case deadhand.StateArmed:
			fmt.Printf("  checks in   every %s (grace %s)\n",
				humanDuration(time.Duration(sw.Interval)*time.Second),
				humanDuration(time.Duration(sw.Grace)*time.Second))
			fmt.Printf("  fires       %s\n", describeDeadline(sw.Deadline()))
		case deadhand.StateFired:
			if sw.FiredAt != nil {
				fmt.Printf("  fired       %s\n", sw.FiredAt.Format(time.RFC1123))
			}
			if sw.ReleaseCID != "" {
				fmt.Printf("  ipfs        %s\n", sw.ReleaseCID)
			}
			if sw.ReleaseTx != "" {
				fmt.Printf("  arweave     %s\n", deadhand.ArweaveURL(sw.ReleaseTx))
			}
		}
		fmt.Println()
	}
	return nil
}

func deadhandCreate(args []string) error {
	fs := flag.NewFlagSet("deadhand create", flag.ContinueOnError)
	var (
		dataDir    = fs.String("data-dir", "", "data directory")
		name       = fs.String("name", "", "a name for this switch")
		message    = fs.String("message", "", "the message to release")
		file       = fs.String("file", "", "a file to include (use - for stdin)")
		recipients = fs.String("to", "", "comma-separated recipient npubs or hex keys")
		guardians  = fs.String("guardians", "", "comma-separated guardian npubs or hex keys")
		threshold  = fs.Int("threshold", 0, "how many guardians are needed to open it")
		interval   = fs.Duration("every", deadhand.DefaultInterval, "how often you must check in")
		grace      = fs.Duration("grace", deadhand.DefaultGrace, "extra time after a missed check-in")
		email      = fs.String("notify", "", "comma-separated email addresses to warn you")
		trusted    = fs.String("trusted", "", "comma-separated emails nudged last, before firing")
		notice     = fs.Bool("public-notice", false, "publish a content-free notice when it fires")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: denly deadhand create [flags]

Encrypts a message and optional file to the recipients you name, and stores it
disarmed. Nothing counts down until you run `+"`denly deadhand arm`"+`.

Flags:
`)
		fs.PrintDefaults()
	}
	if _, err := parsePermuted(fs, args); err != nil {
		return err
	}

	if *name == "" {
		return errors.New("a switch needs a name: --name \"estate\"")
	}
	if *message == "" && *file == "" {
		return errors.New("a switch needs something to release: --message or --file")
	}
	if *recipients == "" && *threshold == 0 {
		return errors.New("a switch needs recipients (--to) or a guardian threshold (--guardians and --threshold)")
	}

	cfg, err := config.Resolve(*dataDir, "")
	if err != nil {
		return err
	}
	k, err := keyring.Load(cfg.DataDir)
	if err != nil {
		return err
	}

	recipientKeys, err := parseKeyList(*recipients)
	if err != nil {
		return fmt.Errorf("reading --to: %w", err)
	}
	guardianKeys, err := parseKeyList(*guardians)
	if err != nil {
		return fmt.Errorf("reading --guardians: %w", err)
	}

	content := deadhand.Content{Message: *message}
	if *file != "" {
		data, filename, err := readDropSource(*file, "")
		if err != nil {
			return err
		}
		content.Files = append(content.Files, deadhand.File{
			Filename: filename, ContentType: guessContentType(filename), Data: data,
		})
	}

	// Sealed here, on this machine, before anything is written. The database
	// never sees the plaintext.
	sealed, err := deadhand.Seal(content, k.PrivateKey(), deadhand.SealOptions{
		Recipients: recipientKeys,
		Guardians:  guardianKeys,
		Threshold:  *threshold,
	})
	if err != nil {
		return err
	}

	switches, ctx, done, err := openDeadhand(*dataDir)
	if err != nil {
		return err
	}
	defer done()

	opts := deadhand.CreateOptions{
		Name:         *name,
		Payload:      sealed,
		Interval:     *interval,
		Grace:        *grace,
		PublicNotice: *notice,
	}
	for _, addr := range splitList(*email) {
		opts.Contacts = append(opts.Contacts, deadhand.Contact{Kind: deadhand.ContactEmail, Address: addr})
	}
	for _, addr := range splitList(*trusted) {
		opts.Contacts = append(opts.Contacts,
			deadhand.Contact{Kind: deadhand.ContactEmail, Address: addr, Trusted: true})
	}

	sw, err := switches.Create(ctx, opts)
	if err != nil {
		return err
	}

	fmt.Printf("Created switch %s (%s).\n\n", sw.Name, sw.ID)
	fmt.Printf("  recipients  %d\n", len(sw.Recipients))
	if sw.Threshold > 0 {
		fmt.Printf("  guardians   %d of %d needed\n", sw.Threshold, len(guardianKeys))
	}
	fmt.Printf("  schedule    check in every %s, %s grace\n",
		humanDuration(*interval), humanDuration(*grace))
	fmt.Println()
	fmt.Println("It is disarmed and nothing is counting down. When you are ready:")
	fmt.Printf("    denly deadhand drill %s     # confirm your contacts work\n", sw.ID)
	fmt.Printf("    denly deadhand arm %s\n", sw.ID)
	return nil
}

func deadhandShow(args []string) error {
	fs := flag.NewFlagSet("deadhand show", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	positional, err := parsePermuted(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("show needs a switch id")
	}

	switches, ctx, done, err := openDeadhand(*dataDir)
	if err != nil {
		return err
	}
	defer done()

	sw, err := switches.Get(ctx, positional[0])
	if err != nil {
		return err
	}
	contacts, err := switches.Contacts(ctx, sw.ID)
	if err != nil {
		return err
	}
	events, err := switches.Events(ctx, sw.ID, 20)
	if err != nil {
		return err
	}

	fmt.Printf("%s  %s\n\n", sw.ID, sw.Name)
	fmt.Printf("  state        %s\n", sw.State)
	fmt.Printf("  payload      %s sealed\n", humanBytes(sw.PayloadBytes))
	fmt.Printf("  recipients   %d\n", len(sw.Recipients))
	for _, r := range sw.Recipients {
		if npub, err := npubOf(r); err == nil {
			fmt.Printf("               %s\n", npub)
		} else {
			fmt.Printf("               %s\n", r)
		}
	}
	if sw.Threshold > 0 {
		fmt.Printf("  guardians    %d needed to open\n", sw.Threshold)
	}
	if sw.State == deadhand.StateArmed {
		fmt.Printf("  next due     %s\n", describeDeadline(sw.DueAt()))
		fmt.Printf("  fires        %s\n", describeDeadline(sw.Deadline()))
	}

	if len(contacts) > 0 {
		fmt.Println("\n  contacts")
		for _, c := range contacts {
			label := ""
			if c.Trusted {
				label = "  (trusted, nudged last)"
			}
			fmt.Printf("    %-8s %s%s\n", c.Kind, c.Address, label)
		}
	}

	if len(events) > 0 {
		fmt.Println("\n  history")
		for _, e := range events {
			detail := ""
			if e.Detail != "" {
				detail = "  " + e.Detail
			}
			fmt.Printf("    %s  %-9s%s\n", e.At.Format("2006-01-02 15:04"), e.Kind, detail)
		}
	}
	return nil
}

func deadhandSetState(args []string, action string) error {
	fs := flag.NewFlagSet("deadhand "+action, flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	positional, err := parsePermuted(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("%s needs a switch id", action)
	}

	switches, ctx, done, err := openDeadhand(*dataDir)
	if err != nil {
		return err
	}
	defer done()

	var sw deadhand.Switch
	if action == "arm" {
		sw, err = switches.Arm(ctx, positional[0])
	} else {
		sw, err = switches.Disarm(ctx, positional[0])
	}
	if err != nil {
		return err
	}

	if action == "arm" {
		fmt.Printf("Armed %q.\n\n", sw.Name)
		fmt.Printf("  check in by  %s\n", describeDeadline(sw.DueAt()))
		fmt.Printf("  fires        %s\n\n", describeDeadline(sw.Deadline()))
		fmt.Printf("Check in with:  denly deadhand checkin %s\n", sw.ID)
	} else {
		fmt.Printf("Disarmed %q. Nothing is counting down.\n", sw.Name)
	}
	return nil
}

func deadhandCheckIn(args []string) error {
	fs := flag.NewFlagSet("deadhand checkin", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	positional, err := parsePermuted(fs, args)
	if err != nil {
		return err
	}

	switches, ctx, done, err := openDeadhand(*dataDir)
	if err != nil {
		return err
	}
	defer done()

	// With no id, check in everywhere. Someone proving they are alive almost
	// never means "alive for one switch only", and making them repeat it per
	// switch invites missing one.
	ids := positional
	if len(ids) == 0 {
		all, err := switches.List(ctx)
		if err != nil {
			return err
		}
		for _, sw := range all {
			if sw.State == deadhand.StateArmed {
				ids = append(ids, sw.ID)
			}
		}
		if len(ids) == 0 {
			fmt.Println("No armed switches to check in on.")
			return nil
		}
	}

	for _, id := range ids {
		sw, err := switches.CheckIn(ctx, id, "cli")
		if err != nil {
			return err
		}
		fmt.Printf("Checked in on %q. Next due %s.\n", sw.Name, describeDeadline(sw.DueAt()))
	}
	return nil
}

func deadhandDrill(args []string) error {
	fs := flag.NewFlagSet("deadhand drill", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	positional, err := parsePermuted(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("drill needs a switch id")
	}

	cfg, err := config.Resolve(*dataDir, "")
	if err != nil {
		return err
	}
	switches, ctx, done, err := openDeadhand(*dataDir)
	if err != nil {
		return err
	}
	defer done()

	engine := deadhand.NewEngine(switches, buildNotifier(cfg), nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	result, err := engine.Drill(ctx, positional[0])
	if err != nil {
		return err
	}

	fmt.Printf("Drill for %q — nothing was released and the switch is untouched.\n\n", result.Name)
	fmt.Printf("  payload      %s would be published\n", humanBytes(result.PayloadBytes))
	fmt.Printf("  recipients   %d\n", len(result.Recipients))
	if result.Threshold > 0 {
		fmt.Printf("  guardians    %d needed\n", result.Threshold)
	}
	fmt.Printf("  state after  %s\n", result.StateAfter)

	if len(result.Notified) > 0 {
		fmt.Println("\n  reached")
		for _, n := range result.Notified {
			fmt.Printf("    %s\n", n)
		}
	}
	if len(result.Failures) > 0 {
		fmt.Println("\n  FAILED — these would not have been warned:")
		for _, f := range result.Failures {
			fmt.Printf("    %s\n", f)
		}
		return errors.New("some contacts could not be reached")
	}
	if len(result.Notified) == 0 {
		fmt.Println("\n  No contacts are configured, so nobody would be warned before this fires.")
	}
	return nil
}

func deadhandFire(args []string) error {
	fs := flag.NewFlagSet("deadhand fire", flag.ContinueOnError)
	var (
		dataDir = fs.String("data-dir", "", "data directory")
		confirm = fs.Bool("confirm", false, "required: firing is irreversible")
	)
	positional, err := parsePermuted(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("fire needs a switch id")
	}
	if !*confirm {
		// The single irreversible action in denly. It publishes someone's
		// private papers; a typo must not be enough.
		return errors.New("firing releases the payload permanently and cannot be undone; re-run with --confirm")
	}

	cfg, err := config.Resolve(*dataDir, "")
	if err != nil {
		return err
	}
	switches, ctx, done, err := openDeadhand(*dataDir)
	if err != nil {
		return err
	}
	defer done()

	engine := deadhand.NewEngine(switches, buildNotifier(cfg), buildReleaser(cfg),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	if err := engine.Fire(ctx, positional[0]); err != nil {
		return err
	}

	sw, err := switches.Get(ctx, positional[0])
	if err != nil {
		return err
	}
	fmt.Printf("Fired %q.\n", sw.Name)
	if sw.ReleaseCID != "" {
		fmt.Printf("  ipfs     %s\n", sw.ReleaseCID)
	}
	if sw.ReleaseTx != "" {
		fmt.Printf("  arweave  %s\n", deadhand.ArweaveURL(sw.ReleaseTx))
	}
	return nil
}

func deadhandDelete(args []string) error {
	fs := flag.NewFlagSet("deadhand delete", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	positional, err := parsePermuted(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("delete needs a switch id")
	}

	switches, ctx, done, err := openDeadhand(*dataDir)
	if err != nil {
		return err
	}
	defer done()

	if err := switches.Delete(ctx, positional[0]); err != nil {
		return err
	}
	fmt.Println("Deleted. The payload is gone and cannot be recovered.")
	return nil
}

/* ------------------------------------------------------------ helpers ---- */

func parseKeyList(s string) ([]nostr.PublicKey, error) {
	items := splitList(s)
	out := make([]nostr.PublicKey, 0, len(items))
	for _, item := range items {
		pk, err := nostr.DecodePublicKey(item)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", item, err)
		}
		out = append(out, pk)
	}
	return out, nil
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func npubOf(hexKey string) (string, error) {
	pk, err := nostr.PublicKeyFromHex(hexKey)
	if err != nil {
		return "", err
	}
	return nostr.EncodeNpub(pk)
}

// describeDeadline renders an absolute time with how far away it is, because
// "fires in 9 days" is what a person actually needs to know.
func describeDeadline(t time.Time) string {
	if t.IsZero() {
		return "never (not armed)"
	}
	until := time.Until(t)
	switch {
	case until < 0:
		return fmt.Sprintf("%s (overdue by %s)", t.Format(time.RFC1123), humanDuration(-until))
	default:
		return fmt.Sprintf("%s (in %s)", t.Format(time.RFC1123), humanDuration(until))
	}
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		days := int(d.Hours()) / 24
		hours := int(d.Hours()) % 24
		if hours == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd %dh", days, hours)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}
