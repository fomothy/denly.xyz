package nostr

import (
	"encoding/csv"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// Verifies signatures from the BIP-340 specification's own test vectors.
//
// This exists because the first implementation here used dcrd's schnorr
// package, which signs with Decred's EC-Schnorr-DCRv0 scheme. It is
// self-consistent — sign and verify round-tripped perfectly — and completely
// incompatible with every other Nostr implementation. Round-trip tests cannot
// catch that; only a foreign vector can.
func TestBIP340SpecificationVectors(t *testing.T) {
	f, err := os.Open("testdata/bip340.vectors.csv")
	if err != nil {
		t.Fatalf("opening BIP-340 vectors: %v", err)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("parsing BIP-340 vectors: %v", err)
	}
	if len(rows) < 2 {
		t.Fatal("BIP-340 vector file is empty")
	}

	// index,secret key,public key,aux_rand,message,signature,verification result,comment
	header := rows[0]
	col := func(name string) int {
		for i, h := range header {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				return i
			}
		}
		t.Fatalf("column %q missing from the vector file", name)
		return -1
	}
	iPub, iMsg, iSig := col("public key"), col("message"), col("signature")
	iResult, iComment, iIndex := col("verification result"), col("comment"), col("index")

	checked := 0
	for _, row := range rows[1:] {
		name := "vector " + row[iIndex]
		if c := strings.TrimSpace(row[iComment]); c != "" {
			name += ": " + c
		}

		t.Run(name, func(t *testing.T) {
			pkBytes, err := hex.DecodeString(row[iPub])
			if err != nil {
				t.Fatalf("decoding public key: %v", err)
			}
			// Vectors carrying an oversized key exercise the parser, not the
			// verifier; PublicKeyFromHex rejects them by length.
			if len(pkBytes) != PublicKeyLen {
				if _, err := PublicKeyFromHex(row[iPub]); err == nil {
					t.Error("a public key of the wrong length was accepted")
				}
				return
			}
			msg, err := hex.DecodeString(row[iMsg])
			if err != nil {
				t.Fatalf("decoding message: %v", err)
			}
			// BIP-340 permits messages of any length, but every signature in
			// denly covers a 32-byte digest — an event ID or a challenge hash.
			// Verify enforces that deliberately: it makes signing arbitrary
			// attacker-supplied bytes a compile-time impossibility rather than
			// a review question. Vectors with other lengths are out of scope.
			if len(msg) != 32 {
				t.Skipf("message is %d bytes; denly only signs 32-byte digests", len(msg))
			}
			sig, err := hex.DecodeString(row[iSig])
			if err != nil {
				t.Fatalf("decoding signature: %v", err)
			}

			var pk PublicKey
			copy(pk[:], pkBytes)

			wantValid := strings.EqualFold(strings.TrimSpace(row[iResult]), "TRUE")
			err = pk.Verify(msg, sig)

			if wantValid && err != nil {
				t.Errorf("spec says this signature is valid, we rejected it: %v", err)
			}
			if !wantValid && err == nil {
				t.Error("spec says this signature is invalid, we accepted it")
			}
		})
		checked++
	}

	// Guard against the file silently becoming empty or unparseable.
	if checked < 15 {
		t.Errorf("only %d BIP-340 vectors ran, expected the full set", checked)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	sk, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	digest := make([]byte, 32)
	copy(digest, "a 32-byte digest for signing....")

	sig, err := sk.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sk.PublicKey().Verify(digest, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	sk, _ := GeneratePrivateKey()
	digest := make([]byte, 32)

	sig, err := sk.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	digest[0] ^= 0xff
	if err := sk.PublicKey().Verify(digest, sig); err == nil {
		t.Error("a signature verified against a modified message")
	}
}

func TestVerifyRejectsOtherKey(t *testing.T) {
	sk, _ := GeneratePrivateKey()
	other, _ := GeneratePrivateKey()
	digest := make([]byte, 32)

	sig, _ := sk.Sign(digest)
	if err := other.PublicKey().Verify(digest, sig); err == nil {
		t.Error("a signature verified against an unrelated key")
	}
}

func TestSignRejectsWrongDigestLength(t *testing.T) {
	sk, _ := GeneratePrivateKey()
	if _, err := sk.Sign([]byte("too short")); err == nil {
		t.Error("Sign accepted a digest that was not 32 bytes")
	}
}

func TestPrivateKeyRoundTripsThroughHex(t *testing.T) {
	sk, _ := GeneratePrivateKey()

	back, err := PrivateKeyFromHex(sk.Hex())
	if err != nil {
		t.Fatalf("PrivateKeyFromHex: %v", err)
	}
	if back.Hex() != sk.Hex() {
		t.Error("private key changed through a hex round trip")
	}
	if back.PublicKey() != sk.PublicKey() {
		t.Error("public key changed through a hex round trip")
	}
}

func TestPrivateKeyFromBytesRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"too short", make([]byte, 31)},
		{"too long", make([]byte, 33)},
		{"zero key", make([]byte, 32)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PrivateKeyFromBytes(tt.in); err == nil {
				t.Error("accepted invalid key material")
			}
		})
	}
}

func TestPublicKeyFromHexRejectsOffCurvePoint(t *testing.T) {
	// From BIP-340 vector 5: a valid-looking x coordinate with no curve point.
	_, err := PublicKeyFromHex("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
	if err == nil {
		t.Error("an off-curve public key was accepted")
	}
}

func TestNIP19RoundTrip(t *testing.T) {
	sk, _ := GeneratePrivateKey()
	pk := sk.PublicKey()

	npub, err := EncodeNpub(pk)
	if err != nil {
		t.Fatalf("EncodeNpub: %v", err)
	}
	if !strings.HasPrefix(npub, "npub1") {
		t.Errorf("npub = %q, want npub1 prefix", npub)
	}
	backPub, err := DecodeNpub(npub)
	if err != nil {
		t.Fatalf("DecodeNpub: %v", err)
	}
	if backPub != pk {
		t.Error("public key changed through an npub round trip")
	}

	nsec, err := EncodeNsec(sk)
	if err != nil {
		t.Fatalf("EncodeNsec: %v", err)
	}
	backSec, err := DecodeNsec(nsec)
	if err != nil {
		t.Fatalf("DecodeNsec: %v", err)
	}
	if backSec.Hex() != sk.Hex() {
		t.Error("secret key changed through an nsec round trip")
	}
}

// Decoding an nsec as an npub must fail — otherwise a user who pastes the
// wrong one gets a confusing success instead of an error.
func TestNIP19RejectsWrongPrefix(t *testing.T) {
	sk, _ := GeneratePrivateKey()
	nsec, _ := EncodeNsec(sk)

	if _, err := DecodeNpub(nsec); err == nil {
		t.Error("DecodeNpub accepted an nsec")
	}

	npub, _ := EncodeNpub(sk.PublicKey())
	if _, err := DecodeNsec(npub); err == nil {
		t.Error("DecodeNsec accepted an npub")
	}
}

func TestDecodePublicKeyAcceptsBothForms(t *testing.T) {
	sk, _ := GeneratePrivateKey()
	pk := sk.PublicKey()
	npub, _ := EncodeNpub(pk)

	for _, in := range []string{npub, pk.Hex(), "  " + npub + "  "} {
		got, err := DecodePublicKey(in)
		if err != nil {
			t.Errorf("DecodePublicKey(%q): %v", in, err)
			continue
		}
		if got != pk {
			t.Errorf("DecodePublicKey(%q) returned a different key", in)
		}
	}
}

func TestNIP44RoundTripBetweenTwoParties(t *testing.T) {
	alice, _ := GeneratePrivateKey()
	bob, _ := GeneratePrivateKey()

	aliceKey, err := ConversationKey(alice, bob.PublicKey())
	if err != nil {
		t.Fatalf("ConversationKey (alice): %v", err)
	}
	bobKey, err := ConversationKey(bob, alice.PublicKey())
	if err != nil {
		t.Fatalf("ConversationKey (bob): %v", err)
	}

	payload, err := Encrypt("the fox knows", aliceKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(payload, bobKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "the fox knows" {
		t.Errorf("decrypted %q, want %q", got, "the fox knows")
	}
}

func TestNIP44RejectsTamperedPayload(t *testing.T) {
	alice, _ := GeneratePrivateKey()
	bob, _ := GeneratePrivateKey()
	key, _ := ConversationKey(alice, bob.PublicKey())

	payload, err := Encrypt("secret", key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a character in the middle of the base64 body.
	mid := len(payload) / 2
	swap := byte('A')
	if payload[mid] == 'A' {
		swap = 'B'
	}
	tampered := payload[:mid] + string(swap) + payload[mid+1:]

	if _, err := Decrypt(tampered, key); err == nil {
		t.Error("Decrypt accepted a tampered payload")
	}
}

func TestNIP44RejectsThirdParty(t *testing.T) {
	alice, _ := GeneratePrivateKey()
	bob, _ := GeneratePrivateKey()
	eve, _ := GeneratePrivateKey()

	aliceBob, _ := ConversationKey(alice, bob.PublicKey())
	eveAlice, _ := ConversationKey(eve, alice.PublicKey())

	payload, _ := Encrypt("for bob only", aliceBob)

	if _, err := Decrypt(payload, eveAlice); !errors.Is(err, ErrPayloadAuth) {
		t.Errorf("err = %v, want ErrPayloadAuth for a third party", err)
	}
}

// Two encryptions of the same plaintext must differ, or the nonce is not doing
// its job and identical messages become linkable.
func TestNIP44EncryptionIsNondeterministic(t *testing.T) {
	sk, _ := GeneratePrivateKey()
	other, _ := GeneratePrivateKey()
	key, _ := ConversationKey(sk, other.PublicKey())

	first, _ := Encrypt("same message", key)
	second, _ := Encrypt("same message", key)

	if first == second {
		t.Error("encrypting the same plaintext twice produced identical payloads")
	}
}
