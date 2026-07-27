package drop

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fomothy/denly.xyz/internal/store"
)

func newTestService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "denly.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	return New(st), ctx
}

func TestCreateAndFetchRoundTrip(t *testing.T) {
	s, ctx := newTestService(t)
	payload := []byte("this is ciphertext as far as the server knows")

	d, err := s.Create(ctx, payload, Options{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.ID == "" {
		t.Error("drop has no ID")
	}
	if d.SizeBytes != int64(len(payload)) {
		t.Errorf("SizeBytes = %d, want %d", d.SizeBytes, len(payload))
	}

	got, meta, err := s.Fetch(ctx, d.ID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("fetched bytes differ from what was stored")
	}
	if meta.DownloadCount != 1 {
		t.Errorf("DownloadCount = %d, want 1", meta.DownloadCount)
	}
}

// Drop IDs are capability tokens — anyone with the link can attempt a fetch —
// so they must be unguessable and never collide.
func TestIDsAreUniqueAndURLSafe(t *testing.T) {
	s, ctx := newTestService(t)

	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		d, err := s.Create(ctx, []byte("x"), Options{})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if seen[d.ID] {
			t.Fatalf("duplicate drop ID after %d creates", i)
		}
		seen[d.ID] = true

		for _, c := range d.ID {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				t.Fatalf("drop ID %q contains %q, which is not URL-safe", d.ID, c)
			}
		}
	}
}

func TestBurnAfterOneDownload(t *testing.T) {
	s, ctx := newTestService(t)

	d, err := s.Create(ctx, []byte("once"), Options{MaxDownloads: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, _, err := s.Fetch(ctx, d.ID); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	// Burning must happen on the fetch that reaches the limit, not the one
	// after — otherwise "burn after 1" is readable twice.
	if _, _, err := s.Fetch(ctx, d.ID); !errors.Is(err, ErrGone) {
		t.Errorf("second Fetch = %v, want ErrGone", err)
	}
}

func TestBurnAfterN(t *testing.T) {
	s, ctx := newTestService(t)

	d, _ := s.Create(ctx, []byte("thrice"), Options{MaxDownloads: 3})
	for i := 1; i <= 3; i++ {
		if _, _, err := s.Fetch(ctx, d.ID); err != nil {
			t.Fatalf("Fetch %d: %v", i, err)
		}
	}
	if _, _, err := s.Fetch(ctx, d.ID); !errors.Is(err, ErrGone) {
		t.Errorf("fetch 4 = %v, want ErrGone", err)
	}
}

// Two simultaneous fetches of a burn-after-1 drop must not both succeed.
func TestConcurrentFetchCannotExceedTheLimit(t *testing.T) {
	s, ctx := newTestService(t)

	d, _ := s.Create(ctx, []byte("contested"), Options{MaxDownloads: 1})

	const racers = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			if _, _, err := s.Fetch(ctx, d.ID); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Errorf("%d concurrent fetches succeeded on a burn-after-1 drop, want exactly 1", successes)
	}
}

func TestExpiredDropIsGone(t *testing.T) {
	s, ctx := newTestService(t)

	d, err := s.Create(ctx, []byte("stale"), Options{TTL: time.Hour})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s.now = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }

	if _, _, err := s.Fetch(ctx, d.ID); !errors.Is(err, ErrGone) {
		t.Errorf("Fetch after expiry = %v, want ErrGone", err)
	}
}

// A wrong link and a spent link are different situations; conflating them
// makes both confusing to explain.
func TestUnknownDropIsNotFoundNotGone(t *testing.T) {
	s, ctx := newTestService(t)

	_, _, err := s.Fetch(ctx, "definitely-not-a-real-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.Create(ctx, nil, Options{}); err == nil {
		t.Error("Create accepted an empty drop")
	}
	if _, err := s.Create(ctx, []byte("x"), Options{TTL: time.Second}); err == nil {
		t.Error("Create accepted a TTL below the minimum")
	}
	if _, err := s.Create(ctx, []byte("x"), Options{TTL: MaxTTL + time.Hour}); err == nil {
		t.Error("Create accepted a TTL above the maximum")
	}
	if _, err := s.Create(ctx, []byte("x"), Options{MaxDownloads: -1}); err == nil {
		t.Error("Create accepted a negative download limit")
	}
}

func TestCreateRejectsOversizedPayload(t *testing.T) {
	s, ctx := newTestService(t)
	if _, err := s.Create(ctx, make([]byte, MaxCiphertext+1), Options{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

// Expiry has to delete the bytes. A drop that merely stops being served but
// stays on disk is the outcome denly exists to avoid.
func TestSweepDeletesExpiredAndBurnedDrops(t *testing.T) {
	s, ctx := newTestService(t)

	expired, _ := s.Create(ctx, []byte("expired"), Options{TTL: time.Hour})
	burned, _ := s.Create(ctx, []byte("burned"), Options{MaxDownloads: 1})
	alive, _ := s.Create(ctx, []byte("alive"), Options{TTL: MaxTTL})

	if _, _, err := s.Fetch(ctx, burned.ID); err != nil {
		t.Fatalf("Fetch to burn: %v", err)
	}

	s.now = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }

	n, err := s.SweepExpired(ctx)
	if err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("swept %d drops, want 2", n)
	}

	if _, err := s.Get(ctx, expired.ID); !errors.Is(err, ErrNotFound) {
		t.Error("the expired drop still exists after a sweep")
	}
	if _, err := s.Get(ctx, burned.ID); !errors.Is(err, ErrNotFound) {
		t.Error("the burned drop still exists after a sweep")
	}
	if _, err := s.Get(ctx, alive.ID); err != nil {
		t.Errorf("the sweep removed a live drop: %v", err)
	}
}

// The plan promises access logs rot within 24h. This is that promise.
func TestSweepAccessLogHonoursRetention(t *testing.T) {
	s, ctx := newTestService(t)

	d, _ := s.Create(ctx, []byte("watched"), Options{})
	if _, _, err := s.Fetch(ctx, d.ID); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	n, err := s.RecentAccessCount(ctx, d.ID)
	if err != nil {
		t.Fatalf("RecentAccessCount: %v", err)
	}
	if n != 1 {
		t.Fatalf("access count = %d, want 1", n)
	}

	s.now = func() time.Time { return time.Now().UTC().Add(AccessLogRetention + time.Hour) }

	if _, err := s.SweepAccessLog(ctx); err != nil {
		t.Fatalf("SweepAccessLog: %v", err)
	}
	n, err = s.RecentAccessCount(ctx, d.ID)
	if err != nil {
		t.Fatalf("RecentAccessCount: %v", err)
	}
	if n != 0 {
		t.Errorf("access count = %d after retention expired, want 0", n)
	}
}

func TestDeleteRemovesDrop(t *testing.T) {
	s, ctx := newTestService(t)

	d, _ := s.Create(ctx, []byte("temp"), Options{})
	if err := s.Delete(ctx, d.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete = %v, want ErrNotFound", err)
	}
}

func TestListReturnsDrops(t *testing.T) {
	s, ctx := newTestService(t)

	for i := 0; i < 3; i++ {
		if _, err := s.Create(ctx, []byte("x"), Options{}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	drops, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(drops) != 3 {
		t.Errorf("List returned %d drops, want 3", len(drops))
	}
}

/* ---------------------------------------------------------- receive box --- */

func TestReceiveRequestFlow(t *testing.T) {
	s, ctx := newTestService(t)

	r, err := s.RequestReceive(ctx, "here is that document", 1024)
	if err != nil {
		t.Fatalf("RequestReceive: %v", err)
	}
	if r.Status != StatusPending {
		t.Errorf("status = %q, want pending", r.Status)
	}

	pending, err := s.PendingRequests(ctx)
	if err != nil {
		t.Fatalf("PendingRequests: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending requests, want 1", len(pending))
	}

	approved, err := s.Decide(ctx, r.ID, true)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if approved.Status != StatusApproved {
		t.Errorf("status = %q, want approved", approved.Status)
	}

	d, err := s.FulfilRequest(ctx, r.ID, []byte("ciphertext"), Options{})
	if err != nil {
		t.Fatalf("FulfilRequest: %v", err)
	}

	final, err := s.GetRequest(ctx, r.ID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if final.Status != StatusUploaded {
		t.Errorf("status = %q, want uploaded", final.Status)
	}
	if final.DropID == nil || *final.DropID != d.ID {
		t.Error("the request was not linked to the stored drop")
	}
}

// This is the whole point of the receive box: an unapproved request has no
// path to writing bytes to disk.
func TestFulfilRequiresApproval(t *testing.T) {
	s, ctx := newTestService(t)

	r, err := s.RequestReceive(ctx, "unapproved", 0)
	if err != nil {
		t.Fatalf("RequestReceive: %v", err)
	}

	if _, err := s.FulfilRequest(ctx, r.ID, []byte("payload"), Options{}); err == nil {
		t.Fatal("a pending request accepted an upload")
	}

	if _, err := s.Decide(ctx, r.ID, false); err != nil {
		t.Fatalf("Decide(deny): %v", err)
	}
	if _, err := s.FulfilRequest(ctx, r.ID, []byte("payload"), Options{}); err == nil {
		t.Error("a denied request accepted an upload")
	}

	drops, _ := s.List(ctx)
	if len(drops) != 0 {
		t.Errorf("%d drops were stored without approval", len(drops))
	}
}

func TestDecideIsSingleShot(t *testing.T) {
	s, ctx := newTestService(t)

	r, _ := s.RequestReceive(ctx, "once", 0)
	if _, err := s.Decide(ctx, r.ID, true); err != nil {
		t.Fatalf("first Decide: %v", err)
	}
	if _, err := s.Decide(ctx, r.ID, false); !errors.Is(err, ErrRequestNotPending) {
		t.Errorf("second Decide = %v, want ErrRequestNotPending", err)
	}
}

func TestDecideUnknownRequest(t *testing.T) {
	s, ctx := newTestService(t)
	if _, err := s.Decide(ctx, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestFulfilRejectsExpiredRequest(t *testing.T) {
	s, ctx := newTestService(t)

	r, _ := s.RequestReceive(ctx, "slow", 0)
	if _, err := s.Decide(ctx, r.ID, true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	s.now = func() time.Time { return time.Now().UTC().Add(ReceiveRequestTTL + time.Hour) }

	if _, err := s.FulfilRequest(ctx, r.ID, []byte("late"), Options{}); !errors.Is(err, ErrGone) {
		t.Errorf("err = %v, want ErrGone", err)
	}
}

func TestRequestReceiveRejectsBadInput(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.RequestReceive(ctx, string(make([]byte, 501)), 0); err == nil {
		t.Error("an oversized note was accepted")
	}
	if _, err := s.RequestReceive(ctx, "", -1); err == nil {
		t.Error("a negative size hint was accepted")
	}
	if _, err := s.RequestReceive(ctx, "", MaxCiphertext+1); !errors.Is(err, ErrTooLarge) {
		t.Error("a size hint beyond the limit was accepted")
	}
}

func TestSweepRequestsRemovesExpired(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.RequestReceive(ctx, "old", 0); err != nil {
		t.Fatalf("RequestReceive: %v", err)
	}

	s.now = func() time.Time { return time.Now().UTC().Add(ReceiveRequestTTL + time.Hour) }

	n, err := s.SweepRequests(ctx)
	if err != nil {
		t.Fatalf("SweepRequests: %v", err)
	}
	if n != 1 {
		t.Errorf("swept %d requests, want 1", n)
	}
}

func TestPendingRequestsExcludesExpired(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.RequestReceive(ctx, "old", 0); err != nil {
		t.Fatalf("RequestReceive: %v", err)
	}
	s.now = func() time.Time { return time.Now().UTC().Add(ReceiveRequestTTL + time.Hour) }

	pending, err := s.PendingRequests(ctx)
	if err != nil {
		t.Fatalf("PendingRequests: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("got %d pending requests, want 0 once expired", len(pending))
	}
}
