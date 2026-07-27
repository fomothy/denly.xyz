package main

import "flag"

// parsePermuted parses flags that may appear before or after positional
// arguments, and returns the positionals.
//
// Go's flag package stops at the first non-flag argument, so `denly drop
// file.txt --burn-after 1` would silently ignore everything after file.txt —
// including the flag that makes a drop burn. Since `denly drop ./file.zip` is
// the form the docs lead with, the parser has to tolerate flags on either side
// rather than the CLI quietly doing the wrong thing.
func parsePermuted(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string

	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
}
