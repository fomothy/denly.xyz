package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/fomothy/denly.xyz/internal/deadhand"
	"github.com/fomothy/denly.xyz/internal/nostr"
)

func createTestSwitch(t *testing.T, s *Server, body map[string]any) deadhand.Switch {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling request: %v", err)
	}
	rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand", raw))
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating switch returned %d: %s", rec.Code, rec.Body)
	}

	var sw deadhand.Switch
	if err := json.Unmarshal(rec.Body.Bytes(), &sw); err != nil {
		t.Fatalf("decoding switch: %v", err)
	}
	return sw
}

func recipientKey(t *testing.T) (*nostr.PrivateKey, string) {
	t.Helper()
	sk, err := nostr.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	npub, err := nostr.EncodeNpub(sk.PublicKey())
	if err != nil {
		t.Fatalf("EncodeNpub: %v", err)
	}
	return sk, npub
}

func TestCreateSwitchStartsDisarmed(t *testing.T) {
	s := newTestServer(t)
	_, npub := recipientKey(t)

	sw := createTestSwitch(t, s, map[string]any{
		"name":       "estate",
		"message":    "the safe combination is our anniversary",
		"recipients": []string{npub},
	})

	if sw.State != deadhand.StateDisarmed {
		t.Errorf("state = %q, want disarmed", sw.State)
	}
	if len(sw.Recipients) != 1 {
		t.Errorf("got %d recipients, want 1", len(sw.Recipients))
	}
}

// The plaintext must not come back out of any endpoint.
func TestSwitchEndpointsNeverEchoPlaintext(t *testing.T) {
	s := newTestServer(t)
	_, npub := recipientKey(t)

	const secret = "the safe combination is our anniversary"
	sw := createTestSwitch(t, s, map[string]any{
		"name":       "estate",
		"message":    secret,
		"recipients": []string{npub},
	})

	for _, path := range []string{"/api/admin/deadhand", "/api/admin/deadhand/" + sw.ID} {
		rec := do(t, s, authed(http.MethodGet, path, nil))
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("%s echoed the payload plaintext", path)
		}
	}
}

// Before firing, the sealed payload must not be downloadable — otherwise
// anyone guessing an ID could hold the ciphertext and wait for a key to leak.
func TestPayloadIsNotAvailableBeforeFiring(t *testing.T) {
	s := newTestServer(t)
	_, npub := recipientKey(t)

	sw := createTestSwitch(t, s, map[string]any{
		"name":       "estate",
		"message":    "not yet",
		"recipients": []string{npub},
	})

	rec := do(t, s, anon(http.MethodGet, "/api/deadhand/"+sw.ID+"/payload", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 before the switch fires", rec.Code)
	}
}

// After firing, the ciphertext is public and safe to be: only the named
// recipient can open it, and gating it would stop them collecting what was
// left for them.
func TestFiredPayloadIsPubliclyFetchableAndOnlyRecipientCanOpen(t *testing.T) {
	s := newTestServer(t)
	recipient, npub := recipientKey(t)

	const secret = "everything is in the blue folder"
	sw := createTestSwitch(t, s, map[string]any{
		"name":       "estate",
		"message":    secret,
		"recipients": []string{npub},
	})

	rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand/"+sw.ID+"/fire?confirm=yes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("firing returned %d: %s", rec.Code, rec.Body)
	}

	rec = do(t, s, anon(http.MethodGet, "/api/deadhand/"+sw.ID+"/payload", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("fetching a fired payload returned %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("the released payload contains plaintext")
	}

	var sealed deadhand.SealedPayload
	if err := json.Unmarshal(rec.Body.Bytes(), &sealed); err != nil {
		t.Fatalf("decoding sealed payload: %v", err)
	}

	content, err := deadhand.OpenAsRecipient(sealed, recipient, *s.owner)
	if err != nil {
		t.Fatalf("the named recipient could not open the released payload: %v", err)
	}
	if content.Message != secret {
		t.Error("the recipient opened the wrong content")
	}

	// An unrelated key must not.
	stranger, _ := recipientKey(t)
	if _, err := deadhand.OpenAsRecipient(sealed, stranger, *s.owner); err == nil {
		t.Error("a stranger opened the released payload")
	}
}

// Firing is the one irreversible action; a bare request must not do it.
func TestFireRequiresExplicitConfirmation(t *testing.T) {
	s := newTestServer(t)
	_, npub := recipientKey(t)

	sw := createTestSwitch(t, s, map[string]any{
		"name":       "estate",
		"message":    "careful",
		"recipients": []string{npub},
	})

	rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand/"+sw.ID+"/fire", nil))
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("status = %d, want 428 without confirmation", rec.Code)
	}

	after, err := s.switches.Get(t.Context(), sw.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.State == deadhand.StateFired {
		t.Fatal("the switch fired without confirmation")
	}
}

func TestArmDisarmCheckInOverHTTP(t *testing.T) {
	s := newTestServer(t)
	_, npub := recipientKey(t)

	sw := createTestSwitch(t, s, map[string]any{
		"name":       "estate",
		"message":    "hello",
		"recipients": []string{npub},
	})

	rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand/"+sw.ID+"/arm", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("arming returned %d: %s", rec.Code, rec.Body)
	}
	var armed switchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &armed); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if armed.State != deadhand.StateArmed {
		t.Errorf("state = %q, want armed", armed.State)
	}
	if armed.Deadline == nil {
		t.Error("an armed switch reported no deadline")
	}

	if rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand/"+sw.ID+"/checkin", nil)); rec.Code != http.StatusOK {
		t.Errorf("check-in returned %d", rec.Code)
	}
	if rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand/"+sw.ID+"/disarm", nil)); rec.Code != http.StatusOK {
		t.Errorf("disarm returned %d", rec.Code)
	}
}

// A drill must exercise the path without releasing or disturbing anything.
func TestDrillOverHTTPDoesNotFire(t *testing.T) {
	s := newTestServer(t)
	_, npub := recipientKey(t)

	sw := createTestSwitch(t, s, map[string]any{
		"name":       "estate",
		"message":    "drill me",
		"recipients": []string{npub},
	})

	rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand/"+sw.ID+"/drill", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("drill returned %d: %s", rec.Code, rec.Body)
	}

	var result deadhand.DrillResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decoding drill result: %v", err)
	}
	if result.StateAfter != deadhand.StateDisarmed {
		t.Errorf("state after drill = %q, want it unchanged", result.StateAfter)
	}

	after, err := s.switches.Get(t.Context(), sw.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.State == deadhand.StateFired {
		t.Fatal("a drill fired the switch")
	}
}

// Public notices carry the fact, never the content, and only for switches that
// opted in.
func TestPublicNoticeOnlyListsOptedInFiredSwitches(t *testing.T) {
	s := newTestServer(t)
	_, npub := recipientKey(t)

	quiet := createTestSwitch(t, s, map[string]any{
		"name":       "quiet-switch",
		"message":    "private",
		"recipients": []string{npub},
	})
	loud := createTestSwitch(t, s, map[string]any{
		"name":          "loud-switch",
		"message":       "also private",
		"recipients":    []string{npub},
		"public_notice": true,
	})

	for _, id := range []string{quiet.ID, loud.ID} {
		if rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand/"+id+"/fire?confirm=yes", nil)); rec.Code != http.StatusOK {
			t.Fatalf("firing %s returned %d: %s", id, rec.Code, rec.Body)
		}
	}

	rec := do(t, s, anon(http.MethodGet, "/api/deadhand/notices", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("notices returned %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "loud-switch") {
		t.Error("the opted-in switch is missing from the public notice")
	}
	if strings.Contains(body, "quiet-switch") {
		t.Error("a switch without public_notice appeared in the public notice")
	}
	for _, secret := range []string{"private", "also private"} {
		if strings.Contains(body, secret) {
			t.Errorf("the public notice leaked content: %q", secret)
		}
	}
}

func TestCreateSwitchRejectsBadInput(t *testing.T) {
	s := newTestServer(t)
	_, npub := recipientKey(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"no name", map[string]any{"message": "x", "recipients": []string{npub}}},
		{"no recipients", map[string]any{"name": "x", "message": "x"}},
		{"unparseable recipient", map[string]any{"name": "x", "message": "x", "recipients": []string{"not-a-key"}}},
		{"threshold above guardian count", map[string]any{
			"name": "x", "message": "x", "guardians": []string{npub}, "threshold": 5,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, _ := json.Marshal(c.body)
			rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand", raw))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestGuardianSwitchOverHTTP(t *testing.T) {
	s := newTestServer(t)

	guardians := make([]*nostr.PrivateKey, 3)
	npubs := make([]string, 3)
	for i := range guardians {
		guardians[i], npubs[i] = recipientKey(t)
	}

	const secret = "split between the three of them"
	sw := createTestSwitch(t, s, map[string]any{
		"name":      "guarded",
		"message":   secret,
		"guardians": npubs,
		"threshold": 2,
	})
	if sw.Threshold != 2 {
		t.Fatalf("threshold = %d, want 2", sw.Threshold)
	}

	if rec := do(t, s, authed(http.MethodPost, "/api/admin/deadhand/"+sw.ID+"/fire?confirm=yes", nil)); rec.Code != http.StatusOK {
		t.Fatalf("firing returned %d: %s", rec.Code, rec.Body)
	}

	rec := do(t, s, anon(http.MethodGet, "/api/deadhand/"+sw.ID+"/payload", nil))
	var sealed deadhand.SealedPayload
	if err := json.Unmarshal(rec.Body.Bytes(), &sealed); err != nil {
		t.Fatalf("decoding sealed payload: %v", err)
	}

	// Two of three guardians decrypt their shares and combine.
	shares := make([][]byte, 0, 2)
	for _, g := range guardians[:2] {
		share, err := deadhand.DecryptGuardianShare(sealed, g, *s.owner)
		if err != nil {
			t.Fatalf("DecryptGuardianShare: %v", err)
		}
		shares = append(shares, share)
	}

	content, err := deadhand.OpenWithShares(sealed, toShares(shares))
	if err != nil {
		t.Fatalf("OpenWithShares: %v", err)
	}
	if content.Message != secret {
		t.Error("guardian release produced the wrong content")
	}
}
