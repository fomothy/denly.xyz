package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testPassphrase = "correct horse battery staple"

func seedDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte(`{"private_key":"deadbeef"}`), 0o600); err != nil {
		t.Fatalf("writing identity: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "denly.db"), []byte("fake database"), 0o600); err != nil {
		t.Fatalf("writing db: %v", err)
	}
	// These are regenerated on start and should not be archived.
	if err := os.WriteFile(filepath.Join(dir, "denly.db-wal"), []byte("wal"), 0o600); err != nil {
		t.Fatalf("writing wal: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", "one.bin"), []byte("blob contents"), 0o600); err != nil {
		t.Fatalf("writing blob: %v", err)
	}
	return dir
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	src := seedDataDir(t)

	var archive bytes.Buffer
	if err := Create(src, testPassphrase, &archive); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if archive.Len() == 0 {
		t.Fatal("archive is empty")
	}

	dst := filepath.Join(t.TempDir(), "restored")
	if err := Restore(bytes.NewReader(archive.Bytes()), dst, testPassphrase); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	for _, rel := range []string{"identity.json", "denly.db", filepath.Join("blobs", "one.bin")} {
		want, err := os.ReadFile(filepath.Join(src, rel))
		if err != nil {
			t.Fatalf("reading source %s: %v", rel, err)
		}
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil {
			t.Errorf("restored file %s missing: %v", rel, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("restored %s differs from the original", rel)
		}
	}

	// WAL sidecars are rebuilt by SQLite and must not be carried over.
	if _, err := os.Stat(filepath.Join(dst, "denly.db-wal")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the WAL sidecar was archived and restored")
	}
}

// An archive is exactly the kind of file that ends up in cloud storage. The
// wrong passphrase must never produce plaintext.
func TestRestoreWithWrongPassphraseFails(t *testing.T) {
	src := seedDataDir(t)

	var archive bytes.Buffer
	if err := Create(src, testPassphrase, &archive); err != nil {
		t.Fatalf("Create: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "restored")
	err := Restore(bytes.NewReader(archive.Bytes()), dst, "not the passphrase")
	if !errors.Is(err, ErrBadPassphrase) {
		t.Errorf("err = %v, want ErrBadPassphrase", err)
	}
	if _, statErr := os.Stat(filepath.Join(dst, "identity.json")); statErr == nil {
		t.Error("a failed restore still wrote files")
	}
}

// The header carries the salt and version and is authenticated; flipping a bit
// anywhere must fail the open rather than silently changing the key.
func TestTamperedArchiveIsRejected(t *testing.T) {
	src := seedDataDir(t)

	var archive bytes.Buffer
	if err := Create(src, testPassphrase, &archive); err != nil {
		t.Fatalf("Create: %v", err)
	}
	raw := archive.Bytes()

	positions := map[string]int{
		"salt":       len(Magic) + 2,
		"nonce":      len(Magic) + saltLen + 2,
		"ciphertext": len(raw) - 10,
	}
	for name, pos := range positions {
		tampered := make([]byte, len(raw))
		copy(tampered, raw)
		tampered[pos] ^= 0xff

		dst := filepath.Join(t.TempDir(), "restored-"+name)
		if err := Restore(bytes.NewReader(tampered), dst, testPassphrase); err == nil {
			t.Errorf("a corrupted %s was accepted", name)
		}
	}
}

func TestRestoreRejectsNonArchive(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "restored")
	err := Restore(strings.NewReader("this is just a text file, not an archive at all"), dst, testPassphrase)
	if !errors.Is(err, ErrNotAnArchive) {
		t.Errorf("err = %v, want ErrNotAnArchive", err)
	}
}

// Restoring over a live instance would destroy the identity someone was trying
// to recover.
func TestRestoreRefusesNonEmptyDirectory(t *testing.T) {
	src := seedDataDir(t)

	var archive bytes.Buffer
	if err := Create(src, testPassphrase, &archive); err != nil {
		t.Fatalf("Create: %v", err)
	}

	occupied := t.TempDir()
	if err := os.WriteFile(filepath.Join(occupied, "identity.json"), []byte("precious"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	err := Restore(bytes.NewReader(archive.Bytes()), occupied, testPassphrase)
	if err == nil {
		t.Fatal("Restore overwrote a non-empty data directory")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Errorf("err = %v, want it to explain the directory is occupied", err)
	}

	got, _ := os.ReadFile(filepath.Join(occupied, "identity.json"))
	if string(got) != "precious" {
		t.Error("the existing identity was overwritten")
	}
}

// The classic tar extraction attack: a path that climbs out of the destination.
func TestRestoreRejectsPathTraversal(t *testing.T) {
	var plain bytes.Buffer
	gz := gzip.NewWriter(&plain)
	tw := tar.NewWriter(gz)

	evil := "../../escaped.txt"
	if err := tw.WriteHeader(&tar.Header{
		Name: evil, Mode: 0o600, Size: int64(len("pwned")), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write([]byte("pwned")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	tw.Close()
	gz.Close()

	archive := sealForTest(t, plain.Bytes(), testPassphrase)

	dst := filepath.Join(t.TempDir(), "restored")
	err := Restore(bytes.NewReader(archive), dst, testPassphrase)
	if !errors.Is(err, ErrUnsafePath) {
		t.Errorf("err = %v, want ErrUnsafePath", err)
	}
}

func TestRestoreRejectsSymlinkEntries(t *testing.T) {
	var plain bytes.Buffer
	gz := gzip.NewWriter(&plain)
	tw := tar.NewWriter(gz)

	if err := tw.WriteHeader(&tar.Header{
		Name: "sneaky", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd",
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	tw.Close()
	gz.Close()

	archive := sealForTest(t, plain.Bytes(), testPassphrase)

	dst := filepath.Join(t.TempDir(), "restored")
	if err := Restore(bytes.NewReader(archive), dst, testPassphrase); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("err = %v, want ErrUnsafePath for a symlink entry", err)
	}
}

func TestRestoredFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on windows")
	}
	src := seedDataDir(t)

	var archive bytes.Buffer
	if err := Create(src, testPassphrase, &archive); err != nil {
		t.Fatalf("Create: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "restored")
	if err := Restore(bytes.NewReader(archive.Bytes()), dst, testPassphrase); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	info, err := os.Stat(filepath.Join(dst, "identity.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("restored identity mode = %04o, want owner-only", perm)
	}
}

func TestCreateRequiresStrongPassphrase(t *testing.T) {
	src := seedDataDir(t)
	var archive bytes.Buffer
	if err := Create(src, "short", &archive); err == nil {
		t.Error("Create accepted a passphrase below the minimum length")
	}
}

// A backup nobody has verified is a hope, not a backup.
func TestVerifyListsContentsWithoutWriting(t *testing.T) {
	src := seedDataDir(t)

	var archive bytes.Buffer
	if err := Create(src, testPassphrase, &archive); err != nil {
		t.Fatalf("Create: %v", err)
	}

	names, err := Verify(bytes.NewReader(archive.Bytes()), testPassphrase)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var sawIdentity bool
	for _, n := range names {
		if n == "identity.json" {
			sawIdentity = true
		}
	}
	if !sawIdentity {
		t.Errorf("Verify listed %v, expected identity.json among them", names)
	}

	if _, err := Verify(bytes.NewReader(archive.Bytes()), "wrong passphrase entirely"); !errors.Is(err, ErrBadPassphrase) {
		t.Error("Verify accepted the wrong passphrase")
	}
}

func TestSafeJoin(t *testing.T) {
	dest := filepath.Join(string(filepath.Separator), "data")

	bad := []string{"../escape", "../../escape", "/absolute", "", "a/../../escape"}
	for _, name := range bad {
		if _, err := safeJoin(dest, name); err == nil {
			t.Errorf("safeJoin accepted %q", name)
		}
	}

	good := []string{"file.txt", "dir/file.txt", "./file.txt", "a/b/../c.txt"}
	for _, name := range good {
		if _, err := safeJoin(dest, name); err != nil {
			t.Errorf("safeJoin rejected %q: %v", name, err)
		}
	}
}

/* ------------------------------------------------------------------ ipfs -- */

func TestKuboPinnerReturnsRootCID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v0/add" {
			t.Errorf("path = %q, want /api/v0/add", r.URL.Path)
		}
		if got := r.URL.Query().Get("pin"); got != "true" {
			t.Errorf("pin = %q, want true", got)
		}
		// Kubo streams one JSON object per added object; the last is the root.
		_, _ = w.Write([]byte(
			`{"Name":"nested","Hash":"bafyNESTED","Size":"10"}` + "\n" +
				`{"Name":"profile.json","Hash":"bafyROOT","Size":"42"}` + "\n"))
	}))
	defer srv.Close()

	cid, err := NewKuboPinner(srv.URL).Pin(context.Background(), "profile.json", []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if cid != "bafyROOT" {
		t.Errorf("cid = %q, want the last (root) hash", cid)
	}
}

func TestKuboPinnerReportsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "daemon not ready", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := NewKuboPinner(srv.URL).Pin(context.Background(), "x", []byte("y")); err == nil {
		t.Error("Pin ignored an error response")
	}
}

func TestPinnersRequireConfiguration(t *testing.T) {
	if _, err := NewKuboPinner("").Pin(context.Background(), "x", []byte("y")); !errors.Is(err, ErrPinnerNotConfigured) {
		t.Errorf("Kubo err = %v, want ErrPinnerNotConfigured", err)
	}
	if _, err := NewServicePinner("", "").Pin(context.Background(), "x", []byte("y")); !errors.Is(err, ErrPinnerNotConfigured) {
		t.Errorf("service err = %v, want ErrPinnerNotConfigured", err)
	}
}

func TestServicePinnerSendsTokenAndParsesCID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"cid":"bafySERVICE"}`))
	}))
	defer srv.Close()

	cid, err := NewServicePinner(srv.URL, "test-token").Pin(context.Background(), "profile.json", []byte("{}"))
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if cid != "bafySERVICE" {
		t.Errorf("cid = %q, want bafySERVICE", cid)
	}
}

// The service's error body can echo the token; it must not reach the message.
func TestServicePinnerDoesNotLeakTokenOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"bad token: test-token-secret"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := NewServicePinner(srv.URL, "test-token-secret").Pin(context.Background(), "x", []byte("y"))
	if err == nil {
		t.Fatal("Pin ignored a 401")
	}
	if strings.Contains(err.Error(), "test-token-secret") {
		t.Errorf("the error message leaked the token: %v", err)
	}
}
