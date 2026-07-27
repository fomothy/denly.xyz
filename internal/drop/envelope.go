package drop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/fomothy/denly.xyz/internal/nostr"
)

// Client-side encryption for drops.
//
// A drop is sealed with a fresh random key that the server never sees. The key
// is handed to the recipient in the URL fragment (`...#key`), which browsers do
// not transmit — so the same link both locates the ciphertext and carries the
// only means of reading it, and the server can serve the transfer while being
// unable to read it.
//
// This deliberately does NOT use the identity key. Drops are frequently sent to
// people who have never heard of Nostr, have no key of their own, and should
// not need one to open a file. Identity-addressed encryption (NIP-44) is the
// right tool for Deadhand payloads and receive-box approvals; it is the wrong
// tool here.

// Envelope is the plaintext structure sealed into a drop. Filename and content
// type live in here rather than in a database column, which is what keeps them
// off the server.
type Envelope struct {
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Content     []byte `json:"content"`
}

// ErrBadKey is returned when a fragment key cannot be used.
var ErrBadKey = errors.New("invalid drop key")

// ErrCannotOpen is returned when a drop will not decrypt with the given key.
var ErrCannotOpen = errors.New("this drop will not open with that key")

// Seal encrypts an envelope under a freshly generated key.
//
// It returns the ciphertext to upload and the key to put in the fragment. The
// caller must never send the key to the server.
func Seal(env Envelope) (ciphertext []byte, fragmentKey string, err error) {
	plain, err := json.Marshal(env)
	if err != nil {
		return nil, "", fmt.Errorf("encoding envelope: %w", err)
	}

	key, err := nostr.RandomBytes(chacha20poly1305.KeySize)
	if err != nil {
		return nil, "", err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, "", fmt.Errorf("initialising cipher: %w", err)
	}
	nonce, err := nostr.RandomBytes(aead.NonceSize())
	if err != nil {
		return nil, "", err
	}

	sealed := aead.Seal(nil, nonce, plain, nil)

	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)

	return out, base64.RawURLEncoding.EncodeToString(key), nil
}

// Open decrypts a drop with the key from the URL fragment.
func Open(ciphertext []byte, fragmentKey string) (Envelope, error) {
	key, err := base64.RawURLEncoding.DecodeString(fragmentKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: not valid base64url", ErrBadKey)
	}
	if len(key) != chacha20poly1305.KeySize {
		return Envelope{}, fmt.Errorf("%w: key is %d bytes, want %d",
			ErrBadKey, len(key), chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Envelope{}, fmt.Errorf("initialising cipher: %w", err)
	}
	if len(ciphertext) < aead.NonceSize()+chacha20poly1305.Overhead {
		return Envelope{}, fmt.Errorf("%w: payload is too short to be a drop", ErrCannotOpen)
	}

	nonce := ciphertext[:aead.NonceSize()]
	body := ciphertext[aead.NonceSize():]

	plain, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return Envelope{}, ErrCannotOpen
	}

	var env Envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return Envelope{}, fmt.Errorf("%w: envelope is unreadable", ErrCannotOpen)
	}
	return env, nil
}
