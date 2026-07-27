// Package nostr implements the pieces of the Nostr protocol denly needs:
// secp256k1 keys, NIP-19 bech32 encoding, schnorr signing, and NIP-44 v2
// payload encryption.
//
// This is deliberately hand-rolled on top of focused primitives rather than
// pulling in a full Nostr client library. denly's pitch is that you can audit
// it; the standard Go library brings 127 transitive modules to supply three
// small subpackages, and a relay client is not something this binary needs.
// The crypto here is validated against the NIP-44 specification's own
// published test vectors — see nip44_vectors_test.go.
package nostr

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	// BIP-340 schnorr, which is what Nostr signatures are. Deliberately NOT
	// dcrd's schnorr package: that implements Decred's own EC-Schnorr-DCRv0
	// scheme, whose signatures are structurally similar and completely
	// incompatible — it verifies against itself and against nothing else in
	// the Nostr ecosystem.
	//
	// btcec/v2 type-aliases dcrd's secp256k1 types, so the ECDH code below
	// interoperates with these signatures without conversion.
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// PrivateKeyLen and PublicKeyLen are the byte lengths of the raw key material.
// Nostr public keys are x-only: 32 bytes, with the y-coordinate implied.
const (
	PrivateKeyLen = 32
	PublicKeyLen  = 32
)

var (
	// ErrInvalidKeyLength is returned for key material of the wrong size.
	ErrInvalidKeyLength = errors.New("invalid key length")
	// ErrInvalidSignature is returned when a signature does not verify.
	ErrInvalidSignature = errors.New("invalid signature")
)

// PrivateKey is a secp256k1 secret key.
type PrivateKey struct {
	key *secp256k1.PrivateKey
}

// PublicKey is an x-only secp256k1 public key, as Nostr uses.
type PublicKey [PublicKeyLen]byte

// GeneratePrivateKey creates a new key from the system CSPRNG.
func GeneratePrivateKey() (*PrivateKey, error) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return &PrivateKey{key: key}, nil
}

// PrivateKeyFromBytes interprets 32 bytes as a secret key.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeyLen {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKeyLength, len(b), PrivateKeyLen)
	}
	// secp256k1.PrivKeyFromBytes does not reject out-of-range scalars; it
	// reduces them. Check explicitly so a malformed key is an error rather
	// than silently becoming a different valid key.
	var overflow secp256k1.ModNScalar
	if overflow.SetByteSlice(b) {
		return nil, fmt.Errorf("%w: scalar out of range", ErrInvalidKeyLength)
	}
	if overflow.IsZero() {
		return nil, fmt.Errorf("%w: zero key", ErrInvalidKeyLength)
	}
	return &PrivateKey{key: secp256k1.NewPrivateKey(&overflow)}, nil
}

// PrivateKeyFromHex parses a 64-character hex secret key.
func PrivateKeyFromHex(s string) (*PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding private key hex: %w", err)
	}
	return PrivateKeyFromBytes(b)
}

// Bytes returns the raw 32-byte secret.
func (p *PrivateKey) Bytes() []byte {
	b := p.key.Serialize()
	out := make([]byte, PrivateKeyLen)
	// Serialize can return fewer than 32 bytes for small scalars; left-pad so
	// the encoding is fixed width.
	copy(out[PrivateKeyLen-len(b):], b)
	return out
}

// Hex returns the secret key as lowercase hex.
func (p *PrivateKey) Hex() string { return hex.EncodeToString(p.Bytes()) }

// PublicKey derives the x-only public key.
func (p *PrivateKey) PublicKey() PublicKey {
	var out PublicKey
	// PubKey().SerializeCompressed() is 33 bytes: a parity prefix followed by
	// the x coordinate. Nostr uses the x coordinate alone.
	copy(out[:], p.key.PubKey().SerializeCompressed()[1:])
	return out
}

// Sign produces a BIP-340 schnorr signature over a 32-byte message digest.
func (p *PrivateKey) Sign(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("signing: digest must be 32 bytes, got %d", len(digest))
	}
	sig, err := schnorr.Sign(p.key, digest)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	return sig.Serialize(), nil
}

// PublicKeyFromHex parses a 64-character hex x-only public key.
func PublicKeyFromHex(s string) (PublicKey, error) {
	var pk PublicKey
	b, err := hex.DecodeString(s)
	if err != nil {
		return pk, fmt.Errorf("decoding public key hex: %w", err)
	}
	if len(b) != PublicKeyLen {
		return pk, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKeyLength, len(b), PublicKeyLen)
	}
	copy(pk[:], b)
	// Reject a public key that is not on the curve. Without this an attacker
	// could hand us a value that later fails deep inside ECDH.
	if _, err := pk.parse(); err != nil {
		return PublicKey{}, err
	}
	return pk, nil
}

// Hex returns the public key as lowercase hex.
func (pk PublicKey) Hex() string { return hex.EncodeToString(pk[:]) }

// Bytes returns a copy of the raw key.
func (pk PublicKey) Bytes() []byte {
	out := make([]byte, PublicKeyLen)
	copy(out, pk[:])
	return out
}

// parse lifts the x-only key onto the curve, assuming even parity as BIP-340
// specifies.
func (pk PublicKey) parse() (*secp256k1.PublicKey, error) {
	compressed := make([]byte, 0, 33)
	compressed = append(compressed, 0x02) // even-Y prefix
	compressed = append(compressed, pk[:]...)

	key, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("public key is not a valid curve point: %w", err)
	}
	return key, nil
}

// Verify checks a BIP-340 schnorr signature over a 32-byte digest.
func (pk PublicKey) Verify(digest, sig []byte) error {
	if len(digest) != 32 {
		return fmt.Errorf("verifying: digest must be 32 bytes, got %d", len(digest))
	}
	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	key, err := pk.parse()
	if err != nil {
		return err
	}
	if !parsed.Verify(digest, key) {
		return ErrInvalidSignature
	}
	return nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return b, nil
}
