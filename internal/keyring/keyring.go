// Package keyring owns the user's identity key.
//
// The key is generated on the machine, written to the data directory at 0600,
// and never transmitted. Nothing in denly sends it anywhere — the server side
// only ever handles public keys and ciphertext. That is the whole product
// promise, so this package is deliberately small and boring.
package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tyler-smith/go-bip39"

	"github.com/fomothy/denly.xyz/internal/nostr"
)

// FileName is the key file inside the data directory.
const FileName = "identity.json"

// ErrNoIdentity is returned when no key has been created yet.
var ErrNoIdentity = errors.New("no identity found; run `denly init` first")

// ErrIdentityExists is returned when creating would overwrite an existing key.
var ErrIdentityExists = errors.New("an identity already exists")

// Identity is the stored key material.
//
// The secret is held as hex rather than the nsec form so the file is obviously
// sensitive at a glance, and so a reader cannot mistake it for a shareable
// public identifier.
//
// this struct IS the local key file, written to the data directory at 0600 and
// never transmitted. The alternative would be storing the key somewhere less
// obviously sensitive.
//
//nolint:gosec // G117 flags the secret-shaped field, which is the entire point:
type Identity struct {
	PrivateKeyHex string    `json:"private_key"`
	PublicKeyHex  string    `json:"public_key"`
	CreatedAt     time.Time `json:"created_at"`

	// Mnemonic is stored only when the identity was created from one, so a
	// user who chose seed backup can recover without a separate note. Users
	// who want the key on paper only can delete this field; nothing reads it
	// except `denly init --show-mnemonic`.
	Mnemonic string `json:"mnemonic,omitempty"`
}

// Keyring is a loaded identity plus its location on disk.
type Keyring struct {
	path     string
	identity Identity
	private  *nostr.PrivateKey
}

// Path returns the key file path inside a data directory.
func Path(dataDir string) string { return filepath.Join(dataDir, FileName) }

// Create generates a fresh identity and writes it to the data directory.
//
// It refuses to overwrite an existing key: losing an identity key means losing
// the ability to prove you are you, and there is no recovery from a clobbered
// file beyond a mnemonic the user may not have written down.
func Create(dataDir string, withMnemonic bool) (*Keyring, error) {
	path := Path(dataDir)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("%w at %s", ErrIdentityExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("checking for existing identity: %w", err)
	}

	var (
		priv     *nostr.PrivateKey
		mnemonic string
		err      error
	)

	if withMnemonic {
		priv, mnemonic, err = generateFromMnemonic()
	} else {
		priv, err = nostr.GeneratePrivateKey()
	}
	if err != nil {
		return nil, err
	}

	id := Identity{
		PrivateKeyHex: priv.Hex(),
		PublicKeyHex:  priv.PublicKey().Hex(),
		CreatedAt:     time.Now().UTC(),
		Mnemonic:      mnemonic,
	}
	if err := write(path, id); err != nil {
		return nil, err
	}
	return &Keyring{path: path, identity: id, private: priv}, nil
}

// ImportMnemonic recreates an identity from a BIP-39 phrase.
func ImportMnemonic(dataDir, mnemonic string) (*Keyring, error) {
	path := Path(dataDir)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("%w at %s", ErrIdentityExists, path)
	}

	priv, err := privateKeyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	id := Identity{
		PrivateKeyHex: priv.Hex(),
		PublicKeyHex:  priv.PublicKey().Hex(),
		CreatedAt:     time.Now().UTC(),
		Mnemonic:      mnemonic,
	}
	if err := write(path, id); err != nil {
		return nil, err
	}
	return &Keyring{path: path, identity: id, private: priv}, nil
}

// Load reads the identity from the data directory.
func Load(dataDir string) (*Keyring, error) {
	path := Path(dataDir)

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}

	// A key file that other users can read is a real problem, not a style
	// point — say so rather than carrying on silently.
	if err := checkFilePermissions(path); err != nil {
		return nil, err
	}

	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("parsing identity file %s: %w", path, err)
	}

	priv, err := nostr.PrivateKeyFromHex(id.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("identity file %s holds an invalid key: %w", path, err)
	}

	// Guard against a hand-edited file where the two halves disagree.
	if got := priv.PublicKey().Hex(); got != id.PublicKeyHex {
		return nil, fmt.Errorf(
			"identity file %s is inconsistent: public key %s does not match the secret key",
			path, id.PublicKeyHex)
	}

	return &Keyring{path: path, identity: id, private: priv}, nil
}

// Exists reports whether an identity has been created.
func Exists(dataDir string) bool {
	_, err := os.Stat(Path(dataDir))
	return err == nil
}

// PrivateKey returns the secret key. Callers must not log or transmit it.
func (k *Keyring) PrivateKey() *nostr.PrivateKey { return k.private }

// PublicKey returns the identity's public key.
func (k *Keyring) PublicKey() nostr.PublicKey { return k.private.PublicKey() }

// Npub returns the shareable bech32 identifier.
func (k *Keyring) Npub() (string, error) { return nostr.EncodeNpub(k.PublicKey()) }

// Nsec returns the secret key in bech32 form, for a user who explicitly asks
// to back it up.
func (k *Keyring) Nsec() (string, error) { return nostr.EncodeNsec(k.private) }

// Mnemonic returns the stored recovery phrase, if the identity has one.
func (k *Keyring) Mnemonic() string { return k.identity.Mnemonic }

// CreatedAt reports when the identity was generated.
func (k *Keyring) CreatedAt() time.Time { return k.identity.CreatedAt }

// generateFromMnemonic creates a key derived from a fresh 128-bit BIP-39
// phrase — twelve words, which people can realistically write down.
func generateFromMnemonic() (*nostr.PrivateKey, string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return nil, "", fmt.Errorf("generating entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, "", fmt.Errorf("generating mnemonic: %w", err)
	}
	priv, err := privateKeyFromMnemonic(mnemonic)
	if err != nil {
		return nil, "", err
	}
	return priv, mnemonic, nil
}

// privateKeyFromMnemonic derives the secret key from a phrase.
//
// The BIP-39 seed is used directly (first 32 bytes) rather than through a
// BIP-32 derivation path. Nostr has no widely-agreed derivation standard, and
// a simple, documented rule is easier to reimplement from this source than a
// path someone has to guess. Recovery therefore depends only on the phrase.
func privateKeyFromMnemonic(mnemonic string) (*nostr.PrivateKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("that is not a valid BIP-39 recovery phrase")
	}
	seed := bip39.NewSeed(mnemonic, "")
	return nostr.PrivateKeyFromBytes(seed[:32])
}

func write(path string, id Identity) error {
	// G117 flags the secret-shaped field, which is the entire point: this is
	// the local key file, written at 0600 and never transmitted.
	raw, err := json.MarshalIndent(id, "", "  ") //nolint:gosec // intentionally serialising the secret key to local disk
	if err != nil {
		return fmt.Errorf("encoding identity: %w", err)
	}

	// Write to a temporary file in the same directory and rename, so an
	// interrupted write cannot leave a truncated key file where a valid one
	// used to be.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("writing identity: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("installing identity file: %w", err)
	}
	return nil
}

func checkFilePermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil // POSIX mode bits do not describe access there
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("checking identity permissions: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf(
			"identity file %s is readable by other users (mode %04o); fix it with: chmod 600 %s",
			path, perm, path)
	}
	return nil
}
