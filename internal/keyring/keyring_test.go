package keyring

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestCreateAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	created, err := Create(dir, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if created.PublicKey() != loaded.PublicKey() {
		t.Error("loaded identity has a different public key than the created one")
	}
	if created.PrivateKey().Hex() != loaded.PrivateKey().Hex() {
		t.Error("loaded identity has a different secret key than the created one")
	}
}

// The key file is the identity. Anything short of owner-only is a problem.
func TestCreateWritesOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on windows")
	}
	dir := t.TempDir()

	if _, err := Create(dir, false); err != nil {
		t.Fatalf("Create: %v", err)
	}

	info, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity file mode = %04o, want 0600", perm)
	}
}

func TestLoadRejectsWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits do not apply on windows")
	}
	dir := t.TempDir()
	if _, err := Create(dir, false); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := os.Chmod(Path(dir), 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load accepted a world-readable identity file")
	}
	if !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("error = %v, want it to name the permission problem", err)
	}
}

// Overwriting an identity destroys it irrecoverably unless the user wrote down
// a mnemonic. Refusing is the only safe default.
func TestCreateRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, false); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	_, err := Create(dir, false)
	if !errors.Is(err, ErrIdentityExists) {
		t.Errorf("second Create returned %v, want ErrIdentityExists", err)
	}
}

func TestLoadWithoutIdentity(t *testing.T) {
	_, err := Load(t.TempDir())
	if !errors.Is(err, ErrNoIdentity) {
		t.Errorf("Load = %v, want ErrNoIdentity", err)
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	if Exists(dir) {
		t.Error("Exists reported true for an empty data dir")
	}
	if _, err := Create(dir, false); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !Exists(dir) {
		t.Error("Exists reported false after Create")
	}
}

func TestMnemonicRecoveryProducesTheSameKey(t *testing.T) {
	dir := t.TempDir()

	original, err := Create(dir, true)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	phrase := original.Mnemonic()
	if phrase == "" {
		t.Fatal("Create(withMnemonic) stored no mnemonic")
	}
	if words := len(strings.Fields(phrase)); words != 12 {
		t.Errorf("mnemonic has %d words, want 12", words)
	}

	// Recover into a different data dir, as someone would on a new machine.
	recovered, err := ImportMnemonic(t.TempDir(), phrase)
	if err != nil {
		t.Fatalf("ImportMnemonic: %v", err)
	}

	if original.PublicKey() != recovered.PublicKey() {
		t.Error("recovering from the mnemonic produced a different identity")
	}
}

func TestImportMnemonicRejectsGarbage(t *testing.T) {
	_, err := ImportMnemonic(t.TempDir(), "not actually a valid bip39 phrase at all")
	if err == nil {
		t.Fatal("ImportMnemonic accepted an invalid phrase")
	}
}

// A hand-edited file whose halves disagree must fail loudly rather than
// silently operating under the wrong identity.
func TestLoadRejectsMismatchedKeyPair(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, false); err != nil {
		t.Fatalf("Create: %v", err)
	}

	other, err := Create(t.TempDir(), false)
	if err != nil {
		t.Fatalf("Create other: %v", err)
	}

	raw, err := os.ReadFile(Path(dir))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tampered := strings.Replace(string(raw), loaded.PublicKey().Hex(), other.PublicKey().Hex(), 1)
	if err := os.WriteFile(Path(dir), []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted an identity whose public and secret keys disagree")
	}
}

func TestNpubAndNsecEncoding(t *testing.T) {
	k, err := Create(t.TempDir(), false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	npub, err := k.Npub()
	if err != nil {
		t.Fatalf("Npub: %v", err)
	}
	if !strings.HasPrefix(npub, "npub1") {
		t.Errorf("npub = %q, want an npub1 prefix", npub)
	}

	nsec, err := k.Nsec()
	if err != nil {
		t.Fatalf("Nsec: %v", err)
	}
	if !strings.HasPrefix(nsec, "nsec1") {
		t.Errorf("nsec = %q, want an nsec1 prefix", nsec)
	}
	if npub == nsec {
		t.Error("npub and nsec are identical")
	}
}
