// Package buildinfo carries release identity into the binary.
//
// GoReleaser overwrites these via -ldflags at build time. The zero values are
// what a plain `go build` or `go run` produces, and they are deliberately
// obvious so an unversioned binary is never mistaken for a release.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var (
	// Version is the semver tag, e.g. "v0.1.0".
	Version = "dev"
	// Commit is the git SHA the binary was built from.
	Commit = "none"
	// Date is the RFC3339 build timestamp.
	Date = "unknown"
)

// Info is a snapshot of build identity.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the current build identity, filling in the commit from the Go
// build info when ldflags were not supplied (a plain `go build` of a checkout).
func Get() Info {
	commit := Commit
	if commit == "none" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					commit = s.Value
					break
				}
			}
		}
	}
	return Info{
		Version:   Version,
		Commit:    commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// IsRelease reports whether this binary carries real release metadata.
func IsRelease() bool { return Version != "dev" }

// String renders a one-line human-readable summary.
func (i Info) String() string {
	return fmt.Sprintf("denly %s (commit %s, built %s, %s, %s)",
		i.Version, i.shortCommit(), i.Date, i.GoVersion, i.Platform)
}

func (i Info) shortCommit() string {
	if len(i.Commit) > 12 {
		return i.Commit[:12]
	}
	return i.Commit
}
