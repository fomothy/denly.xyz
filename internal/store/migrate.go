package store

import (
	"context"
	"fmt"
)

// migration is one forward schema step. Migrations are append-only: once a
// version has shipped in a release, its SQL is frozen forever. Changing it
// would silently diverge the schema of existing installs from new ones, and
// self-hosters upgrade on their own schedule — sometimes across many versions
// at once.
type migration struct {
	version int
	name    string
	sql     string
}

// migrations must stay sorted by version with no gaps.
var migrations = []migration{
	{
		version: 1,
		name:    "meta",
		sql: `
			CREATE TABLE meta (
				key        TEXT PRIMARY KEY,
				value      TEXT NOT NULL,
				updated_at TEXT NOT NULL
			) STRICT;
		`,
	},
}

// SchemaVersion returns the version the database is currently migrated to.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("reading schema version: %w", err)
	}
	return v, nil
}

// LatestSchemaVersion is the version this binary expects.
func LatestSchemaVersion() int {
	if len(migrations) == 0 {
		return 0
	}
	return migrations[len(migrations)-1].version
}

// Migrate applies every migration newer than the database's current version.
// Each migration runs in its own transaction together with its version bump,
// so an interrupted upgrade leaves the database at a valid earlier version
// rather than half-migrated.
func (s *Store) Migrate(ctx context.Context) error {
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}

	if latest := LatestSchemaVersion(); current > latest {
		// The data dir was last touched by a newer denly. Applying older
		// migrations or writing with an older binary risks corrupting data the
		// running binary does not understand, so refuse rather than guess.
		return fmt.Errorf(
			"database schema version %d is newer than this binary supports (%d); upgrade denly",
			current, latest,
		)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %d (%s): begin: %w", m.version, m.name, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
	}

	// PRAGMA does not accept bound parameters. m.version is an int constant
	// from this file, never user input, so the formatting is safe.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
		return fmt.Errorf("migration %d (%s): recording version: %w", m.version, m.name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %d (%s): commit: %w", m.version, m.name, err)
	}
	return nil
}
