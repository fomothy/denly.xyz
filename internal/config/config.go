// Package config resolves runtime configuration for denly.
//
// Precedence, highest first: explicit flag, environment variable, platform
// default. The data directory deliberately does NOT default to the working
// directory: install.sh, the Docker image, and `denly backup` all need a
// stable, predictable location, and a binary dropped in ~/Downloads should not
// scatter a database beside itself.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	// EnvDataDir overrides the platform-default data directory.
	EnvDataDir = "DENLY_DATA_DIR"
	// EnvAddr overrides the default listen address.
	EnvAddr = "DENLY_ADDR"

	// EnvIPFSAPI names a Kubo HTTP API endpoint, e.g. http://127.0.0.1:5001.
	// A local node takes precedence over a pinning service when both are set,
	// because a node the user runs beats a third party they merely have an
	// account with.
	EnvIPFSAPI = "DENLY_IPFS_API"

	// EnvIPFSService names a pinning service upload endpoint.
	EnvIPFSService = "DENLY_IPFS_SERVICE"

	// EnvIPFSToken names the bearer token for that service. This is the name
	// of an environment variable, not a credential — gosec's G101 pattern
	// match on "TOKEN" is what the nolint below answers.
	EnvIPFSToken = "DENLY_IPFS_TOKEN" //nolint:gosec // G101: an env var name, not a secret

	// DefaultAddr binds loopback only. Deployment mode 1 in the plan is
	// "local only"; exposing a fresh install to the network by default would
	// be the wrong failure mode for a tool that holds someone's keys.
	DefaultAddr = "127.0.0.1:8737"

	// dirName is the per-platform subdirectory name.
	dirName = "denly"
)

// Config is the resolved runtime configuration.
type Config struct {
	// DataDir holds the SQLite database, keyring, and user files.
	DataDir string
	// Addr is the TCP address the HTTP server binds.
	Addr string
	// IPFS holds the publishing endpoint, if one is configured.
	IPFS IPFSConfig
}

// IPFSConfig describes where published content is pinned.
type IPFSConfig struct {
	// KuboAPI is a local or trusted Kubo HTTP API endpoint.
	KuboAPI string
	// ServiceURL and ServiceToken describe a pinning service upload endpoint.
	ServiceURL   string
	ServiceToken string
}

// Configured reports whether publishing is possible.
func (c IPFSConfig) Configured() bool {
	return c.KuboAPI != "" || (c.ServiceURL != "" && c.ServiceToken != "")
}

// Resolve builds a Config from flag values, falling back to environment
// variables and then platform defaults. Empty flag values mean "not set".
func Resolve(flagDataDir, flagAddr string) (Config, error) {
	dataDir, err := ResolveDataDir(flagDataDir)
	if err != nil {
		return Config{}, err
	}
	return Config{
		DataDir: dataDir,
		Addr:    firstNonEmpty(flagAddr, os.Getenv(EnvAddr), DefaultAddr),
		IPFS: IPFSConfig{
			KuboAPI:      os.Getenv(EnvIPFSAPI),
			ServiceURL:   os.Getenv(EnvIPFSService),
			ServiceToken: os.Getenv(EnvIPFSToken),
		},
	}, nil
}

// ResolveDataDir returns the absolute data directory path. It does not create
// the directory; call EnsureDataDir for that.
func ResolveDataDir(flagValue string) (string, error) {
	if dir := firstNonEmpty(flagValue, os.Getenv(EnvDataDir)); dir != "" {
		abs, err := filepath.Abs(expandHome(dir))
		if err != nil {
			return "", fmt.Errorf("resolving data dir %q: %w", dir, err)
		}
		return abs, nil
	}
	return defaultDataDir()
}

// EnsureDataDir creates the data directory if needed, with 0700 permissions.
// The directory holds private keys and ciphertext; group and world must never
// be able to read it.
func EnsureDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating data dir %q: %w", dir, err)
	}
	// MkdirAll is a no-op on an existing directory, so an inherited loose mode
	// (for example a bind-mounted Docker volume) would survive unnoticed.
	//nolint:gosec // G302 targets file modes; a directory needs 0700 to be traversable
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("securing data dir %q: %w", dir, err)
	}
	return nil
}

// defaultDataDir returns the platform-conventional location.
func defaultDataDir() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locating home dir: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", dirName), nil

	case "windows":
		// os.UserConfigDir maps to %AppData% (roaming). Application state that
		// is large and machine-specific belongs in %LocalAppData%.
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			return filepath.Join(local, dirName), nil
		}
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("locating app data dir: %w", err)
		}
		return filepath.Join(dir, dirName), nil

	default:
		// Linux, BSDs: XDG Base Directory spec.
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, dirName), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locating home dir: %w", err)
		}
		return filepath.Join(home, ".local", "share", dirName), nil
	}
}

// DBPath is the SQLite database path inside a data directory.
func DBPath(dataDir string) string {
	return filepath.Join(dataDir, "denly.db")
}

// expandHome expands a leading ~ so DENLY_DATA_DIR=~/denly behaves as a user
// expects even when set in a context where the shell did not expand it.
func expandHome(path string) string {
	if path != "~" && !hasPrefix(path, "~"+string(os.PathSeparator)) && !hasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ErrNoDataDir is returned when no data directory could be determined.
var ErrNoDataDir = errors.New("could not determine a data directory")
