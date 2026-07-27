package nostr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Runs the NIP-44 specification's own published test vectors
// (github.com/paulmillr/nip44). This is the only thing standing between a
// plausible-looking implementation and a subtly broken one, so these must stay
// green — including the "invalid" cases, which check that we reject bad input
// rather than quietly producing a wrong answer.

type nip44Vectors struct {
	V2 struct {
		Valid struct {
			GetConversationKey []struct {
				Sec1            string `json:"sec1"`
				Pub2            string `json:"pub2"`
				ConversationKey string `json:"conversation_key"`
				Note            string `json:"note"`
			} `json:"get_conversation_key"`

			GetMessageKeys struct {
				ConversationKey string `json:"conversation_key"`
				Keys            []struct {
					Nonce       string `json:"nonce"`
					ChachaKey   string `json:"chacha_key"`
					ChachaNonce string `json:"chacha_nonce"`
					HmacKey     string `json:"hmac_key"`
				} `json:"keys"`
			} `json:"get_message_keys"`

			CalcPaddedLen [][2]int `json:"calc_padded_len"`

			EncryptDecrypt []struct {
				Sec1            string `json:"sec1"`
				Sec2            string `json:"sec2"`
				ConversationKey string `json:"conversation_key"`
				Nonce           string `json:"nonce"`
				Plaintext       string `json:"plaintext"`
				Payload         string `json:"payload"`
				Note            string `json:"note"`
			} `json:"encrypt_decrypt"`

			EncryptDecryptLongMsg []struct {
				ConversationKey string `json:"conversation_key"`
				Nonce           string `json:"nonce"`
				Pattern         string `json:"pattern"`
				Repeat          int    `json:"repeat"`
				PlaintextSHA256 string `json:"plaintext_sha256"`
				PayloadSHA256   string `json:"payload_sha256"`
			} `json:"encrypt_decrypt_long_msg"`
		} `json:"valid"`

		Invalid struct {
			EncryptMsgLengths []int `json:"encrypt_msg_lengths"`

			GetConversationKey []struct {
				Sec1 string `json:"sec1"`
				Pub2 string `json:"pub2"`
				Note string `json:"note"`
			} `json:"get_conversation_key"`

			Decrypt []struct {
				ConversationKey string `json:"conversation_key"`
				Nonce           string `json:"nonce"`
				Payload         string `json:"payload"`
				Note            string `json:"note"`
			} `json:"decrypt"`
		} `json:"invalid"`
	} `json:"v2"`
}

func loadVectors(t *testing.T) *nip44Vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/nip44.vectors.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var v nip44Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	return &v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding hex %q: %v", s, err)
	}
	return b
}

func TestVectorsConversationKey(t *testing.T) {
	v := loadVectors(t)
	if len(v.V2.Valid.GetConversationKey) == 0 {
		t.Fatal("no conversation key vectors loaded")
	}

	for i, tc := range v.V2.Valid.GetConversationKey {
		sk, err := PrivateKeyFromHex(tc.Sec1)
		if err != nil {
			t.Errorf("case %d (%s): parsing sec1: %v", i, tc.Note, err)
			continue
		}
		pk, err := PublicKeyFromHex(tc.Pub2)
		if err != nil {
			t.Errorf("case %d (%s): parsing pub2: %v", i, tc.Note, err)
			continue
		}
		got, err := ConversationKey(sk, pk)
		if err != nil {
			t.Errorf("case %d (%s): %v", i, tc.Note, err)
			continue
		}
		if hex.EncodeToString(got) != tc.ConversationKey {
			t.Errorf("case %d (%s):\n got %s\nwant %s", i, tc.Note, hex.EncodeToString(got), tc.ConversationKey)
		}
	}
}

func TestVectorsMessageKeys(t *testing.T) {
	v := loadVectors(t)
	ck := mustHex(t, v.V2.Valid.GetMessageKeys.ConversationKey)
	if len(v.V2.Valid.GetMessageKeys.Keys) == 0 {
		t.Fatal("no message key vectors loaded")
	}

	for i, tc := range v.V2.Valid.GetMessageKeys.Keys {
		chachaKey, chachaNonce, hmacKey, err := messageKeys(ck, mustHex(t, tc.Nonce))
		if err != nil {
			t.Errorf("case %d: %v", i, err)
			continue
		}
		if got := hex.EncodeToString(chachaKey); got != tc.ChachaKey {
			t.Errorf("case %d chacha_key:\n got %s\nwant %s", i, got, tc.ChachaKey)
		}
		if got := hex.EncodeToString(chachaNonce); got != tc.ChachaNonce {
			t.Errorf("case %d chacha_nonce:\n got %s\nwant %s", i, got, tc.ChachaNonce)
		}
		if got := hex.EncodeToString(hmacKey); got != tc.HmacKey {
			t.Errorf("case %d hmac_key:\n got %s\nwant %s", i, got, tc.HmacKey)
		}
	}
}

func TestVectorsCalcPaddedLen(t *testing.T) {
	v := loadVectors(t)
	if len(v.V2.Valid.CalcPaddedLen) == 0 {
		t.Fatal("no padding vectors loaded")
	}
	for _, pair := range v.V2.Valid.CalcPaddedLen {
		if got := calcPaddedLen(pair[0]); got != pair[1] {
			t.Errorf("calcPaddedLen(%d) = %d, want %d", pair[0], got, pair[1])
		}
	}
}

// The strongest check in the suite: encrypting with the vector's nonce must
// reproduce the vector's exact ciphertext, byte for byte.
func TestVectorsEncryptDecrypt(t *testing.T) {
	v := loadVectors(t)
	if len(v.V2.Valid.EncryptDecrypt) == 0 {
		t.Fatal("no encrypt/decrypt vectors loaded")
	}

	for i, tc := range v.V2.Valid.EncryptDecrypt {
		sk1, err := PrivateKeyFromHex(tc.Sec1)
		if err != nil {
			t.Errorf("case %d (%s): sec1: %v", i, tc.Note, err)
			continue
		}
		sk2, err := PrivateKeyFromHex(tc.Sec2)
		if err != nil {
			t.Errorf("case %d (%s): sec2: %v", i, tc.Note, err)
			continue
		}

		// Derived from either side, the conversation key must match.
		ck, err := ConversationKey(sk1, sk2.PublicKey())
		if err != nil {
			t.Errorf("case %d (%s): %v", i, tc.Note, err)
			continue
		}
		if hex.EncodeToString(ck) != tc.ConversationKey {
			t.Errorf("case %d (%s): conversation key mismatch", i, tc.Note)
			continue
		}
		ckReverse, err := ConversationKey(sk2, sk1.PublicKey())
		if err != nil {
			t.Errorf("case %d (%s): reverse: %v", i, tc.Note, err)
			continue
		}
		if hex.EncodeToString(ckReverse) != tc.ConversationKey {
			t.Errorf("case %d (%s): conversation key is not symmetric", i, tc.Note)
		}

		payload, err := encryptWithNonce(tc.Plaintext, ck, mustHex(t, tc.Nonce))
		if err != nil {
			t.Errorf("case %d (%s): encrypt: %v", i, tc.Note, err)
			continue
		}
		if payload != tc.Payload {
			t.Errorf("case %d (%s) payload:\n got %s\nwant %s", i, tc.Note, payload, tc.Payload)
		}

		back, err := Decrypt(tc.Payload, ck)
		if err != nil {
			t.Errorf("case %d (%s): decrypt: %v", i, tc.Note, err)
			continue
		}
		if back != tc.Plaintext {
			t.Errorf("case %d (%s): round trip changed the plaintext", i, tc.Note)
		}
	}
}

func TestVectorsLongMessages(t *testing.T) {
	v := loadVectors(t)
	if len(v.V2.Valid.EncryptDecryptLongMsg) == 0 {
		t.Fatal("no long message vectors loaded")
	}

	for i, tc := range v.V2.Valid.EncryptDecryptLongMsg {
		plaintext := strings.Repeat(tc.Pattern, tc.Repeat)

		sum := sha256.Sum256([]byte(plaintext))
		if hex.EncodeToString(sum[:]) != tc.PlaintextSHA256 {
			t.Errorf("case %d: constructed plaintext does not match the vector's hash", i)
			continue
		}

		payload, err := encryptWithNonce(plaintext, mustHex(t, tc.ConversationKey), mustHex(t, tc.Nonce))
		if err != nil {
			t.Errorf("case %d: encrypt: %v", i, err)
			continue
		}
		psum := sha256.Sum256([]byte(payload))
		if hex.EncodeToString(psum[:]) != tc.PayloadSHA256 {
			t.Errorf("case %d: payload hash mismatch", i)
		}
	}
}

// Rejecting bad input matters as much as accepting good input: a decrypt that
// returns plaintext for a tampered payload is worse than no encryption at all.
func TestVectorsInvalidDecrypt(t *testing.T) {
	v := loadVectors(t)
	if len(v.V2.Invalid.Decrypt) == 0 {
		t.Fatal("no invalid decrypt vectors loaded")
	}

	for i, tc := range v.V2.Invalid.Decrypt {
		if _, err := Decrypt(tc.Payload, mustHex(t, tc.ConversationKey)); err == nil {
			t.Errorf("case %d (%s): Decrypt accepted an invalid payload", i, tc.Note)
		}
	}
}

func TestVectorsInvalidConversationKey(t *testing.T) {
	v := loadVectors(t)
	for i, tc := range v.V2.Invalid.GetConversationKey {
		sk, err := PrivateKeyFromHex(tc.Sec1)
		if err != nil {
			continue // rejected at parse time, which is also correct
		}
		pk, err := PublicKeyFromHex(tc.Pub2)
		if err != nil {
			continue // an off-curve public key is rejected here
		}
		if _, err := ConversationKey(sk, pk); err == nil {
			t.Errorf("case %d (%s): ConversationKey accepted invalid input", i, tc.Note)
		}
	}
}

func TestVectorsInvalidMessageLengths(t *testing.T) {
	v := loadVectors(t)
	ck, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	for _, size := range v.V2.Invalid.EncryptMsgLengths {
		if _, err := Encrypt(strings.Repeat("a", size), ck); err == nil {
			t.Errorf("Encrypt accepted a %d-byte plaintext, which is out of range", size)
		}
	}
}
