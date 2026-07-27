package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fomothy/denly.xyz/internal/config"
	"github.com/fomothy/denly.xyz/internal/keyring"
)

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var (
		dataDir  = fs.String("data-dir", "", "data directory (default: platform-specific)")
		noSeed   = fs.Bool("no-mnemonic", false, "generate a key without a recovery phrase")
		importIn = fs.String("import", "", "recover an identity from a BIP-39 recovery phrase")
		showSeed = fs.Bool("show-mnemonic", false, "print the recovery phrase for an existing identity")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: denly init [flags]\n\nCreates this instance's identity key.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir, err := config.ResolveDataDir(*dataDir)
	if err != nil {
		return err
	}
	if err := config.EnsureDataDir(dir); err != nil {
		return err
	}

	if *showSeed {
		return showMnemonic(dir)
	}

	var k *keyring.Keyring
	if *importIn != "" {
		k, err = keyring.ImportMnemonic(dir, strings.TrimSpace(*importIn))
	} else {
		k, err = keyring.Create(dir, !*noSeed)
	}
	if err != nil {
		return err
	}

	npub, err := k.Npub()
	if err != nil {
		return err
	}

	fmt.Println("Identity created.")
	fmt.Println()
	fmt.Printf("  public key   %s\n", npub)
	fmt.Printf("  stored at    %s\n", keyring.Path(dir))
	fmt.Println()

	if phrase := k.Mnemonic(); phrase != "" && *importIn == "" {
		// Printed once, at creation, because this is the only moment the user
		// is guaranteed to be paying attention. Losing it means losing the
		// identity if the machine dies.
		fmt.Println("Recovery phrase — write this down and keep it offline:")
		fmt.Println()
		for i, word := range strings.Fields(phrase) {
			fmt.Printf("  %2d. %-12s", i+1, word)
			if (i+1)%3 == 0 {
				fmt.Println()
			}
		}
		fmt.Println()
		fmt.Println()
		fmt.Println("Anyone with these words controls this identity. Anyone without")
		fmt.Println("them cannot recover it — not even you.")
		fmt.Println()
	}

	fmt.Println("Next: denly serve")
	return nil
}

func showMnemonic(dir string) error {
	k, err := keyring.Load(dir)
	if err != nil {
		return err
	}
	phrase := k.Mnemonic()
	if phrase == "" {
		return fmt.Errorf("this identity was created without a recovery phrase; back up %s instead",
			keyring.Path(dir))
	}
	// Straight to stdout with no decoration, so it can be piped somewhere the
	// user controls without capturing surrounding chatter.
	fmt.Println(phrase)
	return nil
}

func runWhoami(args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	var (
		dataDir  = fs.String("data-dir", "", "data directory (default: platform-specific)")
		showNsec = fs.Bool("show-secret", false, "also print the secret key (nsec)")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: denly whoami [flags]\n\nPrints this instance's identity.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir, err := config.ResolveDataDir(*dataDir)
	if err != nil {
		return err
	}
	k, err := keyring.Load(dir)
	if err != nil {
		return err
	}

	npub, err := k.Npub()
	if err != nil {
		return err
	}
	fmt.Printf("npub    %s\n", npub)
	fmt.Printf("hex     %s\n", k.PublicKey().Hex())
	fmt.Printf("created %s\n", k.CreatedAt().Format("2006-01-02 15:04:05 MST"))

	if *showNsec {
		nsec, err := k.Nsec()
		if err != nil {
			return err
		}
		// Only ever on an explicit flag, and only to stderr-adjacent warning
		// so it is obvious what just happened.
		fmt.Fprintln(os.Stderr, "\nSecret key follows. Anyone who sees it controls this identity.")
		fmt.Printf("nsec    %s\n", nsec)
	}
	return nil
}
