package nostr

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// NIP-44 version 2 payload encryption.
//
// Layout, base64-encoded:
//
//	version(1) || nonce(32) || ciphertext(...) || mac(32)
//
// Plaintext is padded to a power-of-two-derived length before encryption so
// that ciphertext size leaks only a coarse bucket rather than the exact
// message length. The MAC covers nonce || ciphertext, so a payload cannot be
// truncated or have its nonce swapped without detection.
//
// Everything here is checked against the specification's published test
// vectors in nip44_vectors_test.go. Do not "clean up" this file without
// re-running those.
const (
	nip44Version = 2

	nip44MinPlaintext = 1
	nip44MaxPlaintext = 65535

	nip44NonceLen = 32
	nip44MACLen   = 32
	nip44KeyLen   = 32
)

var (
	// ErrPayloadMalformed is returned when a payload cannot be parsed.
	ErrPayloadMalformed = errors.New("nip44: malformed payload")
	// ErrPayloadAuth is returned when the MAC does not match. The payload was
	// corrupted or tampered with; the plaintext is never returned.
	ErrPayloadAuth = errors.New("nip44: authentication failed")
	// ErrUnsupportedVersion is returned for a version byte we do not implement.
	ErrUnsupportedVersion = errors.New("nip44: unsupported version")
	// ErrPlaintextSize is returned for plaintext outside the allowed range.
	ErrPlaintextSize = errors.New("nip44: plaintext size out of range")

	nip44Salt = []byte("nip44-v2")
)

// ConversationKey derives the long-term shared secret between two identities.
//
// It is the HKDF-extract of the ECDH x-coordinate, so it depends only on the
// key pair and can be cached. It must never be used directly as an encryption
// key — Encrypt derives per-message keys from it and a random nonce.
func ConversationKey(sk *PrivateKey, pk PublicKey) ([]byte, error) {
	pub, err := pk.parse()
	if err != nil {
		return nil, err
	}

	// NIP-44 uses only the x coordinate of the ECDH point, discarding y.
	var point secp256k1.JacobianPoint
	pub.AsJacobian(&point)

	var result secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&sk.key.Key, &point, &result)
	result.ToAffine()

	shared := result.X.Bytes()
	return hkdf.Extract(sha256.New, shared[:], nip44Salt), nil
}

// messageKeys expands the conversation key and nonce into the per-message
// ChaCha20 key, ChaCha20 nonce, and HMAC key.
func messageKeys(conversationKey, nonce []byte) (chachaKey, chachaNonce, hmacKey []byte, err error) {
	if len(conversationKey) != nip44KeyLen {
		return nil, nil, nil, fmt.Errorf("nip44: conversation key must be %d bytes", nip44KeyLen)
	}
	if len(nonce) != nip44NonceLen {
		return nil, nil, nil, fmt.Errorf("nip44: nonce must be %d bytes", nip44NonceLen)
	}

	r := hkdf.Expand(sha256.New, conversationKey, nonce)
	out := make([]byte, 76) // 32 key + 12 nonce + 32 hmac key
	if _, err := r.Read(out); err != nil {
		return nil, nil, nil, fmt.Errorf("nip44: expanding message keys: %w", err)
	}
	return out[0:32], out[32:44], out[44:76], nil
}

// calcPaddedLen returns the padded plaintext length for a message of len bytes.
//
// Messages up to 32 bytes all pad to 32. Beyond that, the length is rounded up
// to the next multiple of an eighth of the enclosing power of two, which keeps
// the padding overhead bounded while still collapsing many distinct lengths
// into the same bucket.
func calcPaddedLen(length int) int {
	if length <= 32 {
		return 32
	}
	nextPower := 1 << (int(math.Floor(math.Log2(float64(length-1)))) + 1)
	chunk := 32
	if nextPower > 256 {
		chunk = nextPower / 8
	}
	return chunk * ((length-1)/chunk + 1)
}

// pad prefixes the plaintext with its big-endian uint16 length and zero-fills
// to the padded length.
func pad(plaintext []byte) ([]byte, error) {
	size := len(plaintext)
	if size < nip44MinPlaintext || size > nip44MaxPlaintext {
		return nil, fmt.Errorf("%w: %d bytes", ErrPlaintextSize, size)
	}
	padded := make([]byte, 2+calcPaddedLen(size))
	binary.BigEndian.PutUint16(padded[0:2], uint16(size))
	copy(padded[2:], plaintext)
	return padded, nil
}

// unpad recovers the plaintext, rejecting any padding that does not match what
// pad would have produced. A lenient unpad would let an attacker vary the
// payload without changing the plaintext.
func unpad(padded []byte) ([]byte, error) {
	if len(padded) < 2 {
		return nil, fmt.Errorf("%w: padded plaintext too short", ErrPayloadMalformed)
	}
	size := int(binary.BigEndian.Uint16(padded[0:2]))
	if size < nip44MinPlaintext {
		return nil, fmt.Errorf("%w: declared length is zero", ErrPayloadMalformed)
	}
	if 2+size > len(padded) {
		return nil, fmt.Errorf("%w: declared length %d exceeds payload", ErrPayloadMalformed, size)
	}
	if len(padded) != 2+calcPaddedLen(size) {
		return nil, fmt.Errorf("%w: padding length does not match declared size", ErrPayloadMalformed)
	}
	return padded[2 : 2+size], nil
}

// Encrypt seals plaintext to the conversation key, returning a base64 payload.
func Encrypt(plaintext string, conversationKey []byte) (string, error) {
	nonce, err := RandomBytes(nip44NonceLen)
	if err != nil {
		return "", err
	}
	return encryptWithNonce(plaintext, conversationKey, nonce)
}

// encryptWithNonce is Encrypt with the nonce supplied, so the test vectors can
// reproduce exact ciphertexts. Never call this with a reused nonce.
func encryptWithNonce(plaintext string, conversationKey, nonce []byte) (string, error) {
	chachaKey, chachaNonce, hmacKey, err := messageKeys(conversationKey, nonce)
	if err != nil {
		return "", err
	}

	padded, err := pad([]byte(plaintext))
	if err != nil {
		return "", err
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(chachaKey, chachaNonce)
	if err != nil {
		return "", fmt.Errorf("nip44: initialising cipher: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.XORKeyStream(ciphertext, padded)

	mac, err := messageMAC(hmacKey, nonce, ciphertext)
	if err != nil {
		return "", err
	}

	payload := make([]byte, 0, 1+nip44NonceLen+len(ciphertext)+nip44MACLen)
	payload = append(payload, nip44Version)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	payload = append(payload, mac...)

	return base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt opens a base64 NIP-44 payload.
func Decrypt(payload string, conversationKey []byte) (string, error) {
	// A leading '#' marks a payload from a future, unknown version. The spec
	// reserves it so clients can say "I cannot read this" rather than fail
	// with a confusing parse error.
	if len(payload) > 0 && payload[0] == '#' {
		return "", fmt.Errorf("%w: reserved future version", ErrUnsupportedVersion)
	}

	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("%w: invalid base64: %w", ErrPayloadMalformed, err)
	}

	// version + nonce + at least one padded block + mac
	const minLen = 1 + nip44NonceLen + 34 + nip44MACLen
	if len(raw) < minLen {
		return "", fmt.Errorf("%w: payload is %d bytes, minimum is %d", ErrPayloadMalformed, len(raw), minLen)
	}
	if raw[0] != nip44Version {
		return "", fmt.Errorf("%w: version %d", ErrUnsupportedVersion, raw[0])
	}

	nonce := raw[1 : 1+nip44NonceLen]
	ciphertext := raw[1+nip44NonceLen : len(raw)-nip44MACLen]
	mac := raw[len(raw)-nip44MACLen:]

	chachaKey, chachaNonce, hmacKey, err := messageKeys(conversationKey, nonce)
	if err != nil {
		return "", err
	}

	// Authenticate before decrypting. Touching attacker-controlled ciphertext
	// with a real key before the MAC checks out is how padding oracles happen.
	expected, err := messageMAC(hmacKey, nonce, ciphertext)
	if err != nil {
		return "", err
	}
	if !hmac.Equal(mac, expected) {
		return "", ErrPayloadAuth
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(chachaKey, chachaNonce)
	if err != nil {
		return "", fmt.Errorf("nip44: initialising cipher: %w", err)
	}
	padded := make([]byte, len(ciphertext))
	cipher.XORKeyStream(padded, ciphertext)

	plaintext, err := unpad(padded)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// messageMAC authenticates the nonce alongside the ciphertext, which is what
// stops a payload being replayed under a different nonce.
func messageMAC(key, aad, ciphertext []byte) ([]byte, error) {
	if len(aad) != nip44NonceLen {
		return nil, fmt.Errorf("nip44: aad must be %d bytes", nip44NonceLen)
	}
	h := hmac.New(sha256.New, key)
	h.Write(aad)
	h.Write(ciphertext)
	return h.Sum(nil), nil
}
