package backup

import (
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/fomothy/denly.xyz/internal/nostr"
)

// sealForTest wraps raw tar.gz bytes in the archive envelope, so extraction
// hardening can be tested against entries Create would never produce.
func sealForTest(t *testing.T, plain []byte, passphrase string) []byte {
	t.Helper()

	salt, err := nostr.RandomBytes(saltLen)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	nonce, err := nostr.RandomBytes(aead.NonceSize())
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}

	header := append(append(append([]byte{}, Magic...), salt...), nonce...)
	return append(header, aead.Seal(nil, nonce, plain, header)...)
}
