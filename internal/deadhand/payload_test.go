package deadhand

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/fomothy/denly.xyz/internal/nostr"
	"github.com/fomothy/denly.xyz/internal/shamir"
)

func key(t *testing.T) *nostr.PrivateKey {
	t.Helper()
	sk, err := nostr.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return sk
}

func testContent() Content {
	return Content{
		Message: "the passwords are in the safe, the combination is our anniversary",
		Files: []File{{
			Filename:    "will.pdf",
			ContentType: "application/pdf",
			Data:        []byte("pretend this is a PDF"),
		}},
	}
}

func TestSealAndOpenAsRecipient(t *testing.T) {
	owner, alice := key(t), key(t)

	sealed, err := Seal(testContent(), owner, SealOptions{
		Recipients: []nostr.PublicKey{alice.PublicKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := OpenAsRecipient(sealed, alice, owner.PublicKey())
	if err != nil {
		t.Fatalf("OpenAsRecipient: %v", err)
	}
	if got.Message != testContent().Message {
		t.Error("the message did not survive the round trip")
	}
	if len(got.Files) != 1 || !bytes.Equal(got.Files[0].Data, testContent().Files[0].Data) {
		t.Error("the attached file did not survive the round trip")
	}
}

// Each recipient must be able to open the payload independently, without
// coordinating with the others.
func TestEveryRecipientOpensIndependently(t *testing.T) {
	owner := key(t)
	recipients := []*nostr.PrivateKey{key(t), key(t), key(t)}

	pubs := make([]nostr.PublicKey, len(recipients))
	for i, r := range recipients {
		pubs[i] = r.PublicKey()
	}

	sealed, err := Seal(testContent(), owner, SealOptions{Recipients: pubs})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed.Wraps) != 3 {
		t.Fatalf("got %d wraps, want 3", len(sealed.Wraps))
	}

	for i, r := range recipients {
		got, err := OpenAsRecipient(sealed, r, owner.PublicKey())
		if err != nil {
			t.Errorf("recipient %d could not open the payload: %v", i, err)
			continue
		}
		if got.Message == "" {
			t.Errorf("recipient %d opened an empty message", i)
		}
	}
}

// The central promise: someone not named cannot read it, even holding the
// entire stored payload.
func TestNonRecipientCannotOpen(t *testing.T) {
	owner, alice, eve := key(t), key(t), key(t)

	sealed, err := Seal(testContent(), owner, SealOptions{
		Recipients: []nostr.PublicKey{alice.PublicKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := OpenAsRecipient(sealed, eve, owner.PublicKey()); !errors.Is(err, ErrNotARecipient) {
		t.Errorf("err = %v, want ErrNotARecipient", err)
	}
}

// A recipient must not be able to open someone else's wrap by pointing at it.
func TestRecipientCannotOpenAnotherWrap(t *testing.T) {
	owner, alice, bob := key(t), key(t), key(t)

	sealed, err := Seal(testContent(), owner, SealOptions{
		Recipients: []nostr.PublicKey{alice.PublicKey(), bob.PublicKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Relabel Alice's wrap as Bob's and hand it to Bob.
	tampered := sealed
	tampered.Wraps = []Wrap{{
		RecipientPubKey: bob.PublicKey().Hex(),
		Ciphertext:      sealed.Wraps[0].Ciphertext, // Alice's
	}}

	if _, err := OpenAsRecipient(tampered, bob, owner.PublicKey()); err == nil {
		t.Error("Bob opened a wrap that was sealed to Alice")
	}
}

// What the server holds must not contain the plaintext anywhere.
func TestSealedPayloadRevealsNothing(t *testing.T) {
	owner, alice := key(t), key(t)
	content := testContent()

	sealed, err := Seal(content, owner, SealOptions{
		Recipients: []nostr.PublicKey{alice.PublicKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if bytes.Contains(sealed.Ciphertext, []byte("passwords are in the safe")) {
		t.Error("the message appears in plaintext in the stored ciphertext")
	}
	if bytes.Contains(sealed.Ciphertext, []byte("will.pdf")) {
		t.Error("the filename appears in plaintext in the stored ciphertext")
	}
	for i, w := range sealed.Wraps {
		if strings.Contains(w.Ciphertext, "passwords") {
			t.Errorf("wrap %d leaks the message", i)
		}
	}
}

/* ------------------------------------------------------- guardians ------- */

func TestGuardianThresholdRelease(t *testing.T) {
	owner := key(t)
	guardians := []*nostr.PrivateKey{key(t), key(t), key(t), key(t), key(t)}

	pubs := make([]nostr.PublicKey, len(guardians))
	for i, g := range guardians {
		pubs[i] = g.PublicKey()
	}

	sealed, err := Seal(testContent(), owner, SealOptions{
		Guardians: pubs,
		Threshold: 3,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed.Guardians) != 5 {
		t.Fatalf("got %d guardian shares, want 5", len(sealed.Guardians))
	}

	// Three guardians each decrypt their own share, then combine.
	var shares []shamir.Share
	for _, g := range guardians[:3] {
		share, err := DecryptGuardianShare(sealed, g, owner.PublicKey())
		if err != nil {
			t.Fatalf("DecryptGuardianShare: %v", err)
		}
		shares = append(shares, share)
	}

	got, err := OpenWithShares(sealed, shares)
	if err != nil {
		t.Fatalf("OpenWithShares: %v", err)
	}
	if got.Message != testContent().Message {
		t.Error("guardian release produced the wrong content")
	}
}

// One guardian short must not open it — that is the entire point of a
// threshold.
func TestBelowThresholdGuardiansCannotOpen(t *testing.T) {
	owner := key(t)
	guardians := []*nostr.PrivateKey{key(t), key(t), key(t), key(t)}

	pubs := make([]nostr.PublicKey, len(guardians))
	for i, g := range guardians {
		pubs[i] = g.PublicKey()
	}

	sealed, err := Seal(testContent(), owner, SealOptions{Guardians: pubs, Threshold: 3})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var shares []shamir.Share
	for _, g := range guardians[:2] {
		share, err := DecryptGuardianShare(sealed, g, owner.PublicKey())
		if err != nil {
			t.Fatalf("DecryptGuardianShare: %v", err)
		}
		shares = append(shares, share)
	}

	if _, err := OpenWithShares(sealed, shares); err == nil {
		t.Fatal("two guardians opened a 3-of-4 switch")
	}
}

// Shamir has no integrity of its own; the AEAD is what catches wrong shares.
func TestWrongGuardianSharesFailClosed(t *testing.T) {
	owner := key(t)
	guardians := []*nostr.PrivateKey{key(t), key(t), key(t)}
	pubs := make([]nostr.PublicKey, len(guardians))
	for i, g := range guardians {
		pubs[i] = g.PublicKey()
	}

	sealed, err := Seal(testContent(), owner, SealOptions{Guardians: pubs, Threshold: 2})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Shares from an unrelated split of the right length.
	bogus, err := shamir.Split(make([]byte, 32), 3, 2)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	if _, err := OpenWithShares(sealed, bogus[:2]); !errors.Is(err, ErrCannotOpen) {
		t.Errorf("err = %v, want ErrCannotOpen for wrong shares", err)
	}
}

func TestGuardianCannotDecryptAnotherShare(t *testing.T) {
	owner := key(t)
	a, b, outsider := key(t), key(t), key(t)

	sealed, err := Seal(testContent(), owner, SealOptions{
		Guardians: []nostr.PublicKey{a.PublicKey(), b.PublicKey()},
		Threshold: 2,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := DecryptGuardianShare(sealed, outsider, owner.PublicKey()); !errors.Is(err, ErrNotARecipient) {
		t.Errorf("err = %v, want ErrNotARecipient", err)
	}
}

// Recipients and guardians are independent paths; a switch may use both.
func TestRecipientsAndGuardiansTogether(t *testing.T) {
	owner, alice := key(t), key(t)
	guardians := []*nostr.PrivateKey{key(t), key(t), key(t)}
	gpubs := make([]nostr.PublicKey, len(guardians))
	for i, g := range guardians {
		gpubs[i] = g.PublicKey()
	}

	sealed, err := Seal(testContent(), owner, SealOptions{
		Recipients: []nostr.PublicKey{alice.PublicKey()},
		Guardians:  gpubs,
		Threshold:  2,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := OpenAsRecipient(sealed, alice, owner.PublicKey()); err != nil {
		t.Errorf("the named recipient could not open it: %v", err)
	}

	var shares []shamir.Share
	for _, g := range guardians[:2] {
		s, err := DecryptGuardianShare(sealed, g, owner.PublicKey())
		if err != nil {
			t.Fatalf("DecryptGuardianShare: %v", err)
		}
		shares = append(shares, s)
	}
	if _, err := OpenWithShares(sealed, shares); err != nil {
		t.Errorf("the guardian threshold could not open it: %v", err)
	}
}

func TestSealRejectsBadOptions(t *testing.T) {
	owner := key(t)

	if _, err := Seal(testContent(), owner, SealOptions{}); !errors.Is(err, ErrNoRecipients) {
		t.Errorf("no recipients: err = %v, want ErrNoRecipients", err)
	}

	if _, err := Seal(testContent(), owner, SealOptions{
		Guardians: []nostr.PublicKey{key(t).PublicKey()},
		Threshold: 3,
	}); err == nil {
		t.Error("Seal accepted a threshold larger than the guardian count")
	}

	tooMany := make([]nostr.PublicKey, MaxRecipients+1)
	for i := range tooMany {
		tooMany[i] = key(t).PublicKey()
	}
	if _, err := Seal(testContent(), owner, SealOptions{Recipients: tooMany}); err == nil {
		t.Error("Seal accepted more recipients than the limit")
	}
}

func TestTamperedCiphertextFailsClosed(t *testing.T) {
	owner, alice := key(t), key(t)

	sealed, err := Seal(testContent(), owner, SealOptions{
		Recipients: []nostr.PublicKey{alice.PublicKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed.Ciphertext[len(sealed.Ciphertext)-1] ^= 0xff

	if _, err := OpenAsRecipient(sealed, alice, owner.PublicKey()); !errors.Is(err, ErrCannotOpen) {
		t.Errorf("err = %v, want ErrCannotOpen for a tampered payload", err)
	}
}

func TestRecipientsListing(t *testing.T) {
	owner, alice, bob := key(t), key(t), key(t)

	sealed, err := Seal(testContent(), owner, SealOptions{
		Recipients: []nostr.PublicKey{alice.PublicKey(), bob.PublicKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got := sealed.Recipients()
	if len(got) != 2 {
		t.Fatalf("Recipients() returned %d, want 2", len(got))
	}
	if got[0] != alice.PublicKey().Hex() || got[1] != bob.PublicKey().Hex() {
		t.Error("Recipients() did not list the sealed recipients")
	}
}
