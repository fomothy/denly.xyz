package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/fomothy/denly.xyz/internal/backup"
	"github.com/fomothy/denly.xyz/internal/config"
)

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	var (
		dataDir = fs.String("data-dir", "", "data directory to archive")
		out     = fs.String("out", "", "output file (default: denly-backup-<date>.age)")
		verify  = fs.String("verify", "", "verify an existing archive instead of creating one")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(),
			"Usage: denly backup [flags]\n\nWrites an encrypted archive of the data directory.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *verify != "" {
		return verifyBackup(*verify)
	}

	dir, err := config.ResolveDataDir(*dataDir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("nothing to back up: %s does not exist", dir)
	}

	target := *out
	if target == "" {
		target = fmt.Sprintf("denly-backup-%s.denlybk", time.Now().UTC().Format("2006-01-02"))
	}
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("%s already exists; choose another path with --out", target)
	}

	passphrase, err := readNewPassphrase()
	if err != nil {
		return err
	}

	// Write to a temporary file and rename, so an interrupted backup never
	// leaves a truncated archive that looks complete.
	tmp := target + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}

	if err := backup.Create(dir, passphrase, f); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finishing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("installing %s: %w", target, err)
	}

	// Verify what was just written. A backup that has never been read back is
	// a hope, not a backup.
	rf, err := os.Open(target)
	if err != nil {
		return fmt.Errorf("re-opening %s to verify: %w", target, err)
	}
	defer func() { _ = rf.Close() }()

	names, err := backup.Verify(rf, passphrase)
	if err != nil {
		return fmt.Errorf("the archive was written but did not verify: %w", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat %s: %w", target, err)
	}

	fmt.Printf("Wrote %s (%.1f KiB, %d entries, verified)\n",
		target, float64(info.Size())/1024, len(names))
	fmt.Println()
	fmt.Println("Restore it with:")
	fmt.Printf("    denly restore %s --data-dir <empty-directory>\n", filepath.Base(target))
	return nil
}

func verifyBackup(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	passphrase, err := readPassphrase("Passphrase: ")
	if err != nil {
		return err
	}

	names, err := backup.Verify(f, passphrase)
	if err != nil {
		return err
	}

	fmt.Printf("%s verifies. %d entries:\n", path, len(names))
	for _, n := range names {
		fmt.Printf("  %s\n", n)
	}
	return nil
}

func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "directory to restore into (must be empty)")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(),
			"Usage: denly restore <archive> [flags]\n\nRestores an encrypted archive into a data directory.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	positional, err := parsePermuted(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		fs.Usage()
		return errors.New("restore needs exactly one archive path")
	}

	archive := positional[0]
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("opening %s: %w", archive, err)
	}
	defer func() { _ = f.Close() }()

	dir, err := config.ResolveDataDir(*dataDir)
	if err != nil {
		return err
	}

	passphrase, err := readPassphrase("Passphrase: ")
	if err != nil {
		return err
	}

	if err := backup.Restore(f, dir, passphrase); err != nil {
		return err
	}

	fmt.Printf("Restored %s into %s\n", archive, dir)
	fmt.Println()
	fmt.Println("Start it with:")
	fmt.Printf("    denly serve --data-dir %s\n", dir)
	return nil
}

// readPassphrase reads without echoing when attached to a terminal.
//
// When stdin is a pipe it reads a line instead, so backups can be scripted —
// but it says so, because a passphrase on a pipe usually means it is also in
// a shell history or a CI log.
func readPassphrase(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		var line string
		if _, err := fmt.Scanln(&line); err != nil {
			return "", fmt.Errorf("reading passphrase from stdin: %w", err)
		}
		fmt.Fprintln(os.Stderr, "note: passphrase read from a pipe, not a terminal")
		return line, nil
	}

	fmt.Fprint(os.Stderr, prompt)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	return string(raw), nil
}

// readNewPassphrase asks twice, because a typo in a backup passphrase is only
// discovered when the backup is needed.
func readNewPassphrase() (string, error) {
	first, err := readPassphrase(fmt.Sprintf(
		"Choose a passphrase (at least %d characters): ", backup.MinPassphraseLen))
	if err != nil {
		return "", err
	}
	if len(first) < backup.MinPassphraseLen {
		return "", fmt.Errorf("passphrase must be at least %d characters", backup.MinPassphraseLen)
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return first, nil // no way to ask twice on a pipe
	}

	second, err := readPassphrase("Repeat it: ")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(first) != strings.TrimSpace(second) {
		return "", errors.New("those passphrases do not match")
	}
	return first, nil
}
