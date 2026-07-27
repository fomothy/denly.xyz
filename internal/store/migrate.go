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
	{
		version: 2,
		name:    "profile_identity_drops",
		sql: `
			-- The presence page. A single row; id is pinned to 1 so there can
			-- never be a second profile to disagree with the first.
			CREATE TABLE profile (
				id          INTEGER PRIMARY KEY CHECK (id = 1),
				display_name TEXT NOT NULL DEFAULT '',
				bio          TEXT NOT NULL DEFAULT '',
				updated_at   TEXT NOT NULL
			) STRICT;

			CREATE TABLE links (
				id         INTEGER PRIMARY KEY AUTOINCREMENT,
				label      TEXT NOT NULL,
				url        TEXT NOT NULL,
				position   INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			) STRICT;
			CREATE INDEX idx_links_position ON links (position, id);

			CREATE TABLE posts (
				id           INTEGER PRIMARY KEY AUTOINCREMENT,
				slug         TEXT NOT NULL UNIQUE,
				title        TEXT NOT NULL,
				body         TEXT NOT NULL,
				published_at TEXT,
				created_at   TEXT NOT NULL,
				updated_at   TEXT NOT NULL
			) STRICT;
			CREATE INDEX idx_posts_published ON posts (published_at DESC);

			-- External identities bound to this instance (NIP-05 names,
			-- ATProto DIDs later). verified_at is null until proven.
			CREATE TABLE identities (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				protocol    TEXT NOT NULL,
				handle      TEXT NOT NULL,
				public_key  TEXT NOT NULL,
				verified_at TEXT,
				last_error  TEXT NOT NULL DEFAULT '',
				created_at  TEXT NOT NULL,
				UNIQUE (protocol, handle)
			) STRICT;

			-- Drops hold ciphertext and nothing else. There is deliberately no
			-- column for a filename, a content type, or a decryption key: the
			-- client encrypts a metadata envelope into the blob, and the key
			-- lives in the URL fragment, which never reaches the server.
			CREATE TABLE drops (
				id             TEXT PRIMARY KEY,
				ciphertext     BLOB NOT NULL,
				size_bytes     INTEGER NOT NULL,
				created_at     TEXT NOT NULL,
				expires_at     TEXT,
				max_downloads  INTEGER,
				download_count INTEGER NOT NULL DEFAULT 0,
				burned_at      TEXT
			) STRICT;
			CREATE INDEX idx_drops_expires ON drops (expires_at);

			-- Access records exist to enforce burn-after-N and to let the owner
			-- see recent activity. They carry no requester identity, and a
			-- sweeper deletes them after 24h — the retention promise is kept by
			-- not storing anything worth keeping.
			CREATE TABLE drop_access (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				drop_id     TEXT NOT NULL REFERENCES drops(id) ON DELETE CASCADE,
				accessed_at TEXT NOT NULL
			) STRICT;
			CREATE INDEX idx_drop_access_time ON drop_access (accessed_at);

			-- Receive box: a stranger asks to send you a file, you approve
			-- before any bytes are stored. This is what stops an open upload
			-- endpoint filling your disk.
			CREATE TABLE receive_requests (
				id           TEXT PRIMARY KEY,
				note         TEXT NOT NULL DEFAULT '',
				size_hint    INTEGER,
				status       TEXT NOT NULL DEFAULT 'pending',
				drop_id      TEXT REFERENCES drops(id) ON DELETE SET NULL,
				created_at   TEXT NOT NULL,
				decided_at   TEXT,
				expires_at   TEXT NOT NULL
			) STRICT;
			CREATE INDEX idx_receive_status ON receive_requests (status, created_at);
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
