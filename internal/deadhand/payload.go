// Package deadhand implements the dead man's switch.
//
// The shape of the crypto matters more here than anywhere else in denly, so it
// is worth stating plainly:
//
//   - The payload is encrypted once, under a fresh random content key.
//   - That content key is wrapped separately to each recipient, using NIP-44
//     against their Nostr public key. Each recipient can open their own wrap
//     and nothing else.
//   - Optionally the content key is also split among guardians with Shamir, so
//     a threshold of them can reconstruct it without any one of them holding it.
//
// The server stores the sealed payload and the wraps. It holds no content key,
// no recipient secret, and — when guardians are used — never enough shares to
// combine. "We host availability, not secrets" is a property of this file.
package deadhand

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/fomothy/denly.xyz/internal/nostr"
	"github.com/fomothy/denly.xyz/internal/shamir"
)

// Limits. A Deadhand payload is a message and some files, not a disk image.
const (
	MaxPayloadBytes = 25 << 20 // 25 MiB
	MaxRecipients   = 32
	MaxGuardians    = shamir.MaxParts
)

var (
	// ErrNoRecipients is returned when a payload would be unopenable.
	ErrNoRecipients = errors.New("deadhand: a switch needs at least one recipient or guardian threshold")
	// ErrTooLarge is returned for an oversized payload.
	ErrTooLarge = errors.New("deadhand: payload exceeds the size limit")
	// ErrCannotOpen is returned when a payload will not decrypt.
	ErrCannotOpen = errors.New("deadhand: this payload will not open with that key")
	// ErrNotARecipient is returned when a key has no wrap in the payload.
	ErrNotARecipient = errors.New("deadhand: no wrapped key for that recipient")
)

// Content is the plaintext a switch releases.
type Content struct {
	Message string `json:"message,omitempty"`
	Files   []File `json:"files,omitempty"`
}

// File is one attachment inside a payload.
type File struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	Data        []byte `json:"data"`
}

// Wrap is the content key encrypted to one recipient.
type Wrap struct {
	// RecipientPubKey identifies who can open this wrap. It is stored in the
	// clear: it is a public key, and the recipient needs to find their own
	// wrap without trial-decrypting every one.
	RecipientPubKey string `json:"recipient"`
	// Ciphertext is the NIP-44 payload carrying the content key.
	Ciphertext string `json:"ciphertext"`
}

// GuardianShare is one guardian's Shamir share of the content key.
type GuardianShare struct {
	// GuardianPubKey identifies the holder.
	GuardianPubKey string `json:"guardian"`
	// Ciphertext is the share, NIP-44-encrypted to that guardian so the server
	// cannot read even the share it is storing.
	Ciphertext string `json:"ciphertext"`
}

// SealedPayload is everything the server keeps for a switch.
type SealedPayload struct {
	// Ciphertext is the content, sealed under the content key.
	Ciphertext []byte `json:"ciphertext"`
	// Wraps lets each named recipient recover the content key alone.
	Wraps []Wrap `json:"wraps,omitempty"`
	// Guardians and Threshold describe the N-of-M release path.
	Guardians []GuardianShare `json:"guardians,omitempty"`
	Threshold int             `json:"threshold,omitempty"`
}

// Recipients lists the public keys that can open this payload directly.
func (p SealedPayload) Recipients() []string {
	out := make([]string, 0, len(p.Wraps))
	for _, w := range p.Wraps {
		out = append(out, w.RecipientPubKey)
	}
	return out
}

// SealOptions describe who may open a payload.
type SealOptions struct {
	// Recipients can each open the payload on their own.
	Recipients []nostr.PublicKey
	// Guardians hold Shamir shares; Threshold of them together can open it.
	// Guardians are independent of Recipients: a switch may have either, or
	// both.
	Guardians []nostr.PublicKey
	Threshold int
}

// Seal encrypts content so that each recipient — and any Threshold of the
// guardians — can open it, and nobody else can.
//
// sender is the switch owner's key, used for the NIP-44 conversation with each
// recipient. Only the owner can create a payload, which is why this needs the
// secret key; opening needs only the recipient's.
func Seal(content Content, sender *nostr.PrivateKey, opts SealOptions) (SealedPayload, error) {
	if len(opts.Recipients) == 0 && opts.Threshold == 0 {
		return SealedPayload{}, ErrNoRecipients
	}
	if len(opts.Recipients) > MaxRecipients {
		return SealedPayload{}, fmt.Errorf("deadhand: %d recipients, limit is %d",
			len(opts.Recipients), MaxRecipients)
	}
	if opts.Threshold > 0 {
		if len(opts.Guardians) < opts.Threshold {
			return SealedPayload{}, fmt.Errorf(
				"deadhand: threshold %d needs at least that many guardians, got %d",
				opts.Threshold, len(opts.Guardians))
		}
		if len(opts.Guardians) > MaxGuardians {
			return SealedPayload{}, fmt.Errorf("deadhand: %d guardians, limit is %d",
				len(opts.Guardians), MaxGuardians)
		}
	}

	plain, err := json.Marshal(content)
	if err != nil {
		return SealedPayload{}, fmt.Errorf("deadhand: encoding content: %w", err)
	}
	if len(plain) > MaxPayloadBytes {
		return SealedPayload{}, fmt.Errorf("%w: %d bytes, limit is %d",
			ErrTooLarge, len(plain), MaxPayloadBytes)
	}

	contentKey, err := nostr.RandomBytes(chacha20poly1305.KeySize)
	if err != nil {
		return SealedPayload{}, err
	}

	ciphertext, err := sealWithKey(plain, contentKey)
	if err != nil {
		return SealedPayload{}, err
	}

	sealed := SealedPayload{Ciphertext: ciphertext, Threshold: opts.Threshold}

	// One wrap per recipient. Each is an independent NIP-44 conversation, so
	// recipients learn nothing about each other beyond the public keys already
	// listed alongside.
	keyB64 := base64.RawStdEncoding.EncodeToString(contentKey)
	for _, pk := range opts.Recipients {
		conversation, err := nostr.ConversationKey(sender, pk)
		if err != nil {
			return SealedPayload{}, fmt.Errorf("deadhand: deriving key for %s: %w", pk.Hex(), err)
		}
		wrapped, err := nostr.Encrypt(keyB64, conversation)
		if err != nil {
			return SealedPayload{}, fmt.Errorf("deadhand: wrapping key for %s: %w", pk.Hex(), err)
		}
		sealed.Wraps = append(sealed.Wraps, Wrap{
			RecipientPubKey: pk.Hex(),
			Ciphertext:      wrapped,
		})
	}

	if opts.Threshold > 0 {
		shares, err := shamir.Split(contentKey, len(opts.Guardians), opts.Threshold)
		if err != nil {
			return SealedPayload{}, fmt.Errorf("deadhand: splitting key: %w", err)
		}
		for i, pk := range opts.Guardians {
			conversation, err := nostr.ConversationKey(sender, pk)
			if err != nil {
				return SealedPayload{}, fmt.Errorf("deadhand: deriving key for guardian %s: %w", pk.Hex(), err)
			}
			// The share is itself encrypted to the guardian, so the server
			// stores shares it cannot read — not merely too few to combine.
			shareB64 := base64.RawStdEncoding.EncodeToString(shares[i])
			enc, err := nostr.Encrypt(shareB64, conversation)
			if err != nil {
				return SealedPayload{}, fmt.Errorf("deadhand: wrapping share for %s: %w", pk.Hex(), err)
			}
			sealed.Guardians = append(sealed.Guardians, GuardianShare{
				GuardianPubKey: pk.Hex(),
				Ciphertext:     enc,
			})
		}
	}

	return sealed, nil
}

// OpenAsRecipient decrypts a payload using a recipient's own key.
func OpenAsRecipient(p SealedPayload, recipient *nostr.PrivateKey, owner nostr.PublicKey) (Content, error) {
	mine := recipient.PublicKey().Hex()

	var wrap *Wrap
	for i := range p.Wraps {
		if p.Wraps[i].RecipientPubKey == mine {
			wrap = &p.Wraps[i]
			break
		}
	}
	if wrap == nil {
		return Content{}, ErrNotARecipient
	}

	conversation, err := nostr.ConversationKey(recipient, owner)
	if err != nil {
		return Content{}, err
	}
	keyB64, err := nostr.Decrypt(wrap.Ciphertext, conversation)
	if err != nil {
		return Content{}, fmt.Errorf("%w: %w", ErrCannotOpen, err)
	}
	contentKey, err := base64.RawStdEncoding.DecodeString(keyB64)
	if err != nil {
		return Content{}, fmt.Errorf("%w: wrapped key is malformed", ErrCannotOpen)
	}
	return openWithKey(p.Ciphertext, contentKey)
}

// OpenWithShares decrypts a payload from a threshold of guardian shares.
//
// Guardians decrypt their own share first — the server cannot, and neither can
// this function — then hand the raw shares here.
func OpenWithShares(p SealedPayload, shares []shamir.Share) (Content, error) {
	if p.Threshold == 0 {
		return Content{}, errors.New("deadhand: this switch has no guardian threshold")
	}
	if len(shares) < p.Threshold {
		return Content{}, fmt.Errorf("deadhand: %d shares supplied, %d required",
			len(shares), p.Threshold)
	}

	contentKey, err := shamir.Combine(shares)
	if err != nil {
		return Content{}, err
	}
	// Shamir has no integrity, so wrong shares yield a wrong key rather than
	// an error. The AEAD below is what actually catches that.
	return openWithKey(p.Ciphertext, contentKey)
}

// DecryptGuardianShare lets a guardian recover their own share.
func DecryptGuardianShare(p SealedPayload, guardian *nostr.PrivateKey, owner nostr.PublicKey) (shamir.Share, error) {
	mine := guardian.PublicKey().Hex()

	for _, g := range p.Guardians {
		if g.GuardianPubKey != mine {
			continue
		}
		conversation, err := nostr.ConversationKey(guardian, owner)
		if err != nil {
			return nil, err
		}
		shareB64, err := nostr.Decrypt(g.Ciphertext, conversation)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCannotOpen, err)
		}
		raw, err := base64.RawStdEncoding.DecodeString(shareB64)
		if err != nil {
			return nil, fmt.Errorf("%w: share is malformed", ErrCannotOpen)
		}
		return raw, nil
	}
	return nil, ErrNotARecipient
}

func sealWithKey(plain, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("deadhand: initialising cipher: %w", err)
	}
	nonce, err := nostr.RandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(plain)+chacha20poly1305.Overhead)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, nil), nil
}

func openWithKey(ciphertext, key []byte) (Content, error) {
	if len(key) != chacha20poly1305.KeySize {
		return Content{}, fmt.Errorf("%w: content key is the wrong size", ErrCannotOpen)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Content{}, fmt.Errorf("deadhand: initialising cipher: %w", err)
	}
	if len(ciphertext) < aead.NonceSize()+chacha20poly1305.Overhead {
		return Content{}, fmt.Errorf("%w: payload is too short", ErrCannotOpen)
	}

	nonce := ciphertext[:aead.NonceSize()]
	plain, err := aead.Open(nil, nonce, ciphertext[aead.NonceSize():], nil)
	if err != nil {
		return Content{}, ErrCannotOpen
	}

	var content Content
	if err := json.Unmarshal(plain, &content); err != nil {
		return Content{}, fmt.Errorf("%w: content is unreadable", ErrCannotOpen)
	}
	return content, nil
}
