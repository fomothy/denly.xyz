// Package store owns the embedded SQLite database.
//
// The driver is modernc.org/sqlite, a pure-Go translation of SQLite. It is
// slower than the cgo-based mattn/go-sqlite3, but it lets `denly` cross-compile
// to every target from one machine with CGO_ENABLED=0 and ship as a genuinely
// static binary. For a single-user personal server that trade is obviously
// right; revisit only if profiling says otherwise.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Store wraps the database handle and its migration state.
type Store struct {
	db *sql.DB
}

// Open opens (creating if absent) the SQLite database at path and brings the
// schema up to the latest version. The caller must Close the result.
func Open(ctx context.Context, path string) (*Store, error) {
	// _txlock=immediate avoids SQLITE_BUSY on write-after-read upgrades.
	// busy_timeout keeps concurrent writers waiting instead of erroring.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database %q: %w", path, err)
	}

	// SQLite permits one writer at a time. Leaving the pool unbounded produces
	// lock contention that looks like random slowness under load; a single
	// connection plus WAL readers is the well-trodden configuration.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to database %q: %w", path, err)
	}

	s := &Store{db: db}
	if err := s.applyPragmas(ctx); err != nil {
		db.Close()
		return nil, err
	}
	// Restrict permissions after the pragmas, because enabling WAL is what
	// creates the -wal and -shm sidecar files.
	if err := secureDBFiles(path); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.Migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// secureDBFiles tightens the database and its WAL sidecars to owner-only.
//
// SQLite creates files with 0644 modified by the process umask, which leaves
// them world-readable under a default umask. The data directory is already
// 0700, so this is defense in depth — it matters when a data dir is bind
// mounted, copied, or restored from a backup into a looser parent.
func secureDBFiles(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		err := os.Chmod(p, 0o600)
		if errors.Is(err, os.ErrNotExist) {
			// Sidecars are absent until WAL is active; not an error.
			continue
		}
		if err != nil {
			return fmt.Errorf("securing %q: %w", p, err)
		}
	}
	return nil
}

// applyPragmas sets the durability and concurrency configuration. WAL is
// persistent in the database file; the rest are per-connection, which is safe
// because the pool is capped at one connection.
func (s *Store) applyPragmas(ctx context.Context) error {
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := s.db.ExecContext(ctx, p); err != nil {
			return fmt.Errorf("applying %q: %w", p, err)
		}
	}
	return nil
}

// DB exposes the underlying handle for packages that need direct access.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Ping verifies the database is reachable. Used by the health endpoint.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// JournalMode reports the active journal mode, so tests and `denly version`
// can assert WAL is really on rather than assume it.
func (s *Store) JournalMode(ctx context.Context) (string, error) {
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return "", fmt.Errorf("reading journal mode: %w", err)
	}
	return mode, nil
}

// Meta reads a value from the key/value metadata table.
func (s *Store) Meta(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("reading meta %q: %w", key, err)
	}
	return value, nil
}

// SetMeta writes a value to the key/value metadata table.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO meta (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("writing meta %q: %w", key, err)
	}
	return nil
}

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("not found")
