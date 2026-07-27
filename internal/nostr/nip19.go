package nostr

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// NIP-19 bech32 human-readable prefixes.
const (
	HRPPublicKey  = "npub"
	HRPPrivateKey = "nsec"
)

// EncodeNpub renders a public key in the npub form people paste around.
func EncodeNpub(pk PublicKey) (string, error) { return encodeBech32(HRPPublicKey, pk[:]) }

// EncodeNsec renders a secret key in nsec form.
//
// Callers should think twice before putting the result anywhere but a
// clipboard or a file the user asked for — it is the whole identity.
func EncodeNsec(sk *PrivateKey) (string, error) { return encodeBech32(HRPPrivateKey, sk.Bytes()) }

// DecodeNpub parses an npub into a public key.
func DecodeNpub(s string) (PublicKey, error) {
	var pk PublicKey
	data, err := decodeBech32(HRPPublicKey, s)
	if err != nil {
		return pk, err
	}
	if len(data) != PublicKeyLen {
		return pk, fmt.Errorf("%w: npub holds %d bytes, want %d", ErrInvalidKeyLength, len(data), PublicKeyLen)
	}
	copy(pk[:], data)
	if _, err := pk.parse(); err != nil {
		return PublicKey{}, err
	}
	return pk, nil
}

// DecodeNsec parses an nsec into a secret key.
func DecodeNsec(s string) (*PrivateKey, error) {
	data, err := decodeBech32(HRPPrivateKey, s)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromBytes(data)
}

// DecodePublicKey accepts either an npub or bare hex, since people paste both.
func DecodePublicKey(s string) (PublicKey, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, HRPPublicKey+"1") {
		return DecodeNpub(s)
	}
	return PublicKeyFromHex(s)
}

func encodeBech32(hrp string, data []byte) (string, error) {
	converted, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("converting bits for %s: %w", hrp, err)
	}
	encoded, err := bech32.Encode(hrp, converted)
	if err != nil {
		return "", fmt.Errorf("encoding %s: %w", hrp, err)
	}
	return encoded, nil
}

func decodeBech32(wantHRP, s string) ([]byte, error) {
	hrp, data, err := bech32.Decode(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decoding bech32: %w", err)
	}
	if hrp != wantHRP {
		return nil, fmt.Errorf("expected a %s value, got %q", wantHRP, hrp)
	}
	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("converting bits from %s: %w", wantHRP, err)
	}
	return converted, nil
}
