package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "denly.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenCreatesDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "denly.db")

	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("database file not created: %v", err)
	}
}

// WAL is what lets reads proceed during writes. If a future refactor drops the
// pragma the app still works but gets mysteriously slow, so assert it.
func TestOpenEnablesWAL(t *testing.T) {
	s := openTestStore(t)

	mode, err := s.JournalMode(context.Background())
	if err != nil {
		t.Fatalf("JournalMode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

// The database holds metadata and, from Phase 1 on, key material. It must not
// be world-readable even if the parent directory is later loosened.
func TestOpenRestrictsDatabasePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on windows")
	}
	path := filepath.Join(t.TempDir(), "denly.db")

	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("Stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %04o, want 0600", filepath.Base(p), perm)
		}
	}
}

func TestMigrateReachesLatestVersion(t *testing.T) {
	s := openTestStore(t)

	got, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if want := LatestSchemaVersion(); got != want {
		t.Errorf("schema version = %d, want %d", got, want)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "denly.db")

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Re-running migrations on an up-to-date database must be a no-op, not an
	// error and not a duplicate-table failure.
	if err := s.Migrate(ctx); err != nil {
		t.Errorf("second Migrate: %v", err)
	}
	s.Close()

	// Reopening an existing database exercises the same path a restart takes.
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got, err := s2.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if want := LatestSchemaVersion(); got != want {
		t.Errorf("schema version after reopen = %d, want %d", got, want)
	}
}

// Downgrades must fail loudly. A newer denly may have written data this binary
// cannot represent; opening it read-write would risk silent loss.
func TestMigrateRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	future := LatestSchemaVersion() + 10
	if _, err := s.db.ExecContext(ctx, "PRAGMA user_version = "+itoa(future)); err != nil {
		t.Fatalf("setting future version: %v", err)
	}

	err := s.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted a newer schema version, want error")
	}
	if !strings.Contains(err.Error(), "newer than this binary") {
		t.Errorf("error = %v, want it to mention the version mismatch", err)
	}
}

func TestMigrationsAreSequentialAndFrozen(t *testing.T) {
	for i, m := range migrations {
		if want := i + 1; m.version != want {
			t.Errorf("migrations[%d].version = %d, want %d (append-only, no gaps)", i, m.version, want)
		}
		if strings.TrimSpace(m.sql) == "" {
			t.Errorf("migration %d (%s) has empty SQL", m.version, m.name)
		}
		if m.name == "" {
			t.Errorf("migration %d has no name", m.version)
		}
	}
}

func TestMetaRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	if err := s.SetMeta(ctx, "instance_id", "abc123"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	got, err := s.Meta(ctx, "instance_id")
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	if got != "abc123" {
		t.Errorf("Meta = %q, want %q", got, "abc123")
	}
}

func TestMetaUpsertOverwrites(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	if err := s.SetMeta(ctx, "k", "first"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := s.SetMeta(ctx, "k", "second"); err != nil {
		t.Fatalf("SetMeta overwrite: %v", err)
	}

	got, err := s.Meta(ctx, "k")
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	if got != "second" {
		t.Errorf("Meta = %q, want %q", got, "second")
	}
}

func TestMetaMissingReturnsErrNotFound(t *testing.T) {
	s := openTestStore(t)

	_, err := s.Meta(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCloseIsSafeOnNilStore(t *testing.T) {
	var s *Store
	if err := s.Close(); err != nil {
		t.Errorf("Close on nil store: %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
