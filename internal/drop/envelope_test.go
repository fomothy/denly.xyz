package drop

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	env := Envelope{
		Filename:    "report.pdf",
		ContentType: "application/pdf",
		Content:     []byte("the actual bytes"),
	}

	ciphertext, key, err := Seal(env)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(ciphertext, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Filename != env.Filename || got.ContentType != env.ContentType {
		t.Error("envelope metadata did not survive the round trip")
	}
	if !bytes.Equal(got.Content, env.Content) {
		t.Error("content did not survive the round trip")
	}
}

// The filename is the thing a server operator would most like to see. It must
// be inside the ciphertext, not beside it.
func TestFilenameIsNotVisibleInCiphertext(t *testing.T) {
	ciphertext, _, err := Seal(Envelope{
		Filename: "extremely-secret-filename.txt",
		Content:  []byte("x"),
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(ciphertext, []byte("extremely-secret-filename")) {
		t.Error("the filename appears in plaintext inside the ciphertext")
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	ciphertext, _, err := Seal(Envelope{Content: []byte("secret")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, other, err := Seal(Envelope{Content: []byte("decoy")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := Open(ciphertext, other); !errors.Is(err, ErrCannotOpen) {
		t.Errorf("err = %v, want ErrCannotOpen", err)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	ciphertext, key, err := Seal(Envelope{Content: []byte("secret")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff

	if _, err := Open(ciphertext, key); !errors.Is(err, ErrCannotOpen) {
		t.Errorf("err = %v, want ErrCannotOpen", err)
	}
}

func TestOpenRejectsMalformedKeys(t *testing.T) {
	ciphertext, _, err := Seal(Envelope{Content: []byte("x")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for _, key := range []string{"", "not base64url!!", "c2hvcnQ"} {
		if _, err := Open(ciphertext, key); !errors.Is(err, ErrBadKey) {
			t.Errorf("Open with key %q: err = %v, want ErrBadKey", key, err)
		}
	}
}

func TestOpenRejectsShortPayload(t *testing.T) {
	_, key, err := Seal(Envelope{Content: []byte("x")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open([]byte("tiny"), key); !errors.Is(err, ErrCannotOpen) {
		t.Errorf("err = %v, want ErrCannotOpen", err)
	}
}

// Two seals of identical content must differ, or identical files become
// linkable by ciphertext comparison.
func TestSealIsNondeterministic(t *testing.T) {
	a, keyA, _ := Seal(Envelope{Content: []byte("same")})
	b, keyB, _ := Seal(Envelope{Content: []byte("same")})

	if bytes.Equal(a, b) {
		t.Error("sealing identical content twice produced identical ciphertext")
	}
	if keyA == keyB {
		t.Error("two seals produced the same key")
	}
}

// The key rides in a URL fragment, so it has to survive being pasted into one.
func TestFragmentKeyIsURLSafe(t *testing.T) {
	_, key, err := Seal(Envelope{Content: []byte("x")})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.ContainsAny(key, "+/=#?& ") {
		t.Errorf("fragment key %q contains characters that need URL escaping", key)
	}
}
