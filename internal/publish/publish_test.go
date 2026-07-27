package publish

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fomothy/denly.xyz/internal/profile"
	"github.com/fomothy/denly.xyz/internal/store"
)

// fakePinner records what it was asked to pin.
type fakePinner struct {
	name    string
	content []byte
	cid     string
	err     error
	calls   int
}

func (f *fakePinner) Pin(_ context.Context, name string, content []byte) (string, error) {
	f.calls++
	f.name, f.content = name, content
	if f.err != nil {
		return "", f.err
	}
	if f.cid == "" {
		f.cid = "bafyTEST"
	}
	return f.cid, nil
}

func newTestService(t *testing.T, pinner *fakePinner) (*Service, *profile.Service, context.Context) {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "denly.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	prof := profile.New(st)

	// A typed nil would make Configured() true while Pin panics; pass an
	// untyped nil when the test wants "no pinner".
	if pinner == nil {
		return New(st, prof, nil), prof, ctx
	}
	return New(st, prof, pinner), prof, ctx
}

func TestPublishPinsAndRecordsCID(t *testing.T) {
	pinner := &fakePinner{cid: "bafyABC123"}
	svc, prof, ctx := newTestService(t, pinner)

	if err := prof.Save(ctx, profile.Profile{DisplayName: "Nick", Bio: "builds denly"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rec, err := svc.Publish(ctx, "pubkeyhex")
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if rec.CID != "bafyABC123" {
		t.Errorf("CID = %q, want the pinner's answer", rec.CID)
	}
	if rec.GatewayURL == "" || !strings.Contains(rec.GatewayURL, rec.CID) {
		t.Errorf("GatewayURL = %q, want it to contain the CID", rec.GatewayURL)
	}
	if pinner.calls != 1 {
		t.Errorf("pinner called %d times, want 1", pinner.calls)
	}

	last, ok, err := svc.Last(ctx)
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	if !ok {
		t.Fatal("Last reports nothing published after a successful publish")
	}
	if last.CID != "bafyABC123" {
		t.Errorf("recorded CID = %q, want bafyABC123", last.CID)
	}
	if last.PublishedAt.IsZero() {
		t.Error("publish time was not recorded")
	}
}

// Pinning is effectively irreversible. Publishing someone's unpublished
// writing without asking would be the worst kind of surprise, so the pinned
// bundle must contain published posts only.
func TestPublishExcludesDrafts(t *testing.T) {
	pinner := &fakePinner{}
	svc, prof, ctx := newTestService(t, pinner)

	if _, err := prof.SavePost(ctx, "Public Post", "everyone sees this", true); err != nil {
		t.Fatalf("SavePost: %v", err)
	}
	if _, err := prof.SavePost(ctx, "Private Draft", "nobody should see this", false); err != nil {
		t.Fatalf("SavePost: %v", err)
	}

	if _, err := svc.Publish(ctx, "pubkeyhex"); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	body := string(pinner.content)
	if !strings.Contains(body, "Public Post") {
		t.Error("the pinned bundle is missing the published post")
	}
	if strings.Contains(body, "Private Draft") || strings.Contains(body, "nobody should see this") {
		t.Error("the pinned bundle contains an unpublished draft")
	}

	var bundle profile.Bundle
	if err := json.Unmarshal(pinner.content, &bundle); err != nil {
		t.Fatalf("pinned content is not a valid bundle: %v", err)
	}
	if len(bundle.Posts) != 1 {
		t.Errorf("pinned bundle has %d posts, want only the published one", len(bundle.Posts))
	}
	if bundle.PublicKey != "pubkeyhex" {
		t.Errorf("pinned bundle public key = %q, want it carried through", bundle.PublicKey)
	}
}

// An instance with no IPFS endpoint is normal, not broken. It must say so
// clearly rather than failing obscurely.
func TestPublishWithoutConfiguration(t *testing.T) {
	svc, _, ctx := newTestService(t, nil)

	if svc.Configured() {
		t.Error("Configured() is true with no pinner")
	}

	_, err := svc.Publish(ctx, "")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	// The message has to tell the user what to set, since this is the most
	// likely first encounter with publishing.
	if !strings.Contains(err.Error(), "DENLY_IPFS_API") {
		t.Errorf("error does not say how to configure it: %v", err)
	}
}

func TestPublishPropagatesPinnerFailure(t *testing.T) {
	pinner := &fakePinner{err: errors.New("ipfs node unreachable")}
	svc, _, ctx := newTestService(t, pinner)

	if _, err := svc.Publish(ctx, ""); err == nil {
		t.Fatal("Publish reported success when pinning failed")
	}

	// A failed pin must not leave a CID behind claiming otherwise.
	if _, ok, err := svc.Last(ctx); err != nil {
		t.Fatalf("Last: %v", err)
	} else if ok {
		t.Error("a failed publish recorded a CID")
	}
}

func TestLastBeforeAnyPublish(t *testing.T) {
	svc, _, ctx := newTestService(t, &fakePinner{})

	_, ok, err := svc.Last(ctx)
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	if ok {
		t.Error("Last reports a publish on a fresh instance")
	}
}

func TestRepublishUpdatesTheRecord(t *testing.T) {
	pinner := &fakePinner{cid: "bafyFIRST"}
	svc, prof, ctx := newTestService(t, pinner)

	if _, err := svc.Publish(ctx, ""); err != nil {
		t.Fatalf("first Publish: %v", err)
	}

	if _, err := prof.SavePost(ctx, "Newer", "more content", true); err != nil {
		t.Fatalf("SavePost: %v", err)
	}
	pinner.cid = "bafySECOND"
	if _, err := svc.Publish(ctx, ""); err != nil {
		t.Fatalf("second Publish: %v", err)
	}

	last, _, err := svc.Last(ctx)
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	if last.CID != "bafySECOND" {
		t.Errorf("recorded CID = %q, want the newer pin", last.CID)
	}
}

func TestPinnedFileIsNamedUsefully(t *testing.T) {
	pinner := &fakePinner{}
	svc, _, ctx := newTestService(t, pinner)

	if _, err := svc.Publish(ctx, ""); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !strings.HasSuffix(pinner.name, ".json") {
		t.Errorf("pinned name = %q, want something identifiable ending in .json", pinner.name)
	}
}

func TestGatewayURL(t *testing.T) {
	if got := GatewayURL(""); got != "" {
		t.Errorf("GatewayURL(\"\") = %q, want empty", got)
	}
	if got := GatewayURL("bafyX"); !strings.HasSuffix(got, "/bafyX") {
		t.Errorf("GatewayURL = %q, want it to end with the CID", got)
	}
}
