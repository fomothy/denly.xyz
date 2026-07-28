package deadhand

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fomothy/denly.xyz/internal/nostr"
	"github.com/fomothy/denly.xyz/internal/store"
)

/* ------------------------------------------------------------ fixtures --- */

type recordedNotice struct {
	contact Contact
	subject string
	body    string
}

type fakeNotifier struct {
	mu      sync.Mutex
	notices []recordedNotice
	err     error
}

func (f *fakeNotifier) Notify(_ context.Context, c Contact, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.notices = append(f.notices, recordedNotice{c, subject, body})
	return nil
}

func (f *fakeNotifier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.notices)
}

func (f *fakeNotifier) all() []recordedNotice {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedNotice(nil), f.notices...)
}

type fakeReleaser struct {
	mu       sync.Mutex
	calls    int
	payloads [][]byte
	err      error
}

func (f *fakeReleaser) Release(_ context.Context, _ string, payload []byte) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return "", "", f.err
	}
	f.payloads = append(f.payloads, payload)
	return "bafyRELEASED", "arweaveTX", nil
}

func (f *fakeReleaser) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type harness struct {
	store    *Store
	engine   *Engine
	notifier *fakeNotifier
	releaser *fakeReleaser
	owner    *nostr.PrivateKey
	ctx      context.Context
	clock    time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "denly.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	h := &harness{
		notifier: &fakeNotifier{},
		releaser: &fakeReleaser{},
		owner:    key(t),
		ctx:      ctx,
		clock:    time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	}
	h.store = NewStore(db)
	h.store.now = func() time.Time { return h.clock }

	h.engine = NewEngine(h.store, h.notifier, h.releaser,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.engine.now = func() time.Time { return h.clock }
	return h
}

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

func (h *harness) newSwitch(t *testing.T, contacts ...Contact) Switch {
	t.Helper()

	recipient := key(t)
	sealed, err := Seal(testContent(), h.owner, SealOptions{
		Recipients: []nostr.PublicKey{recipient.PublicKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	sw, err := h.store.Create(h.ctx, CreateOptions{
		Name:     "estate",
		Payload:  sealed,
		Interval: 30 * 24 * time.Hour,
		Grace:    10 * 24 * time.Hour,
		Contacts: contacts,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return sw
}

/* ------------------------------------------------------------- store ----- */

// A switch that armed itself on creation would eventually fire on someone who
// was still setting it up.
func TestNewSwitchStartsDisarmed(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t)

	if sw.State != StateDisarmed {
		t.Errorf("state = %q, want disarmed", sw.State)
	}
	if !sw.Deadline().IsZero() {
		t.Error("a disarmed switch reports a firing deadline")
	}
}

func TestArmDisarmAndCheckIn(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t)

	armed, err := h.store.Arm(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if armed.State != StateArmed {
		t.Fatalf("state = %q, want armed", armed.State)
	}
	if armed.Deadline().IsZero() {
		t.Error("an armed switch has no deadline")
	}

	h.advance(20 * 24 * time.Hour)
	checked, err := h.store.CheckIn(h.ctx, sw.ID, "cli")
	if err != nil {
		t.Fatalf("CheckIn: %v", err)
	}
	if checked.Deadline().Before(armed.Deadline()) {
		t.Error("checking in did not push the deadline out")
	}

	disarmed, err := h.store.Disarm(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Disarm: %v", err)
	}
	if disarmed.State != StateDisarmed {
		t.Errorf("state = %q, want disarmed", disarmed.State)
	}
}

func TestScheduleValidation(t *testing.T) {
	h := newHarness(t)
	recipient := key(t)
	sealed, err := Seal(testContent(), h.owner, SealOptions{
		Recipients: []nostr.PublicKey{recipient.PublicKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct{ interval, grace time.Duration }{
		{time.Minute, DefaultGrace},     // interval too short
		{2 * MaxInterval, DefaultGrace}, // interval too long
		{DefaultInterval, time.Minute},  // grace too short
		{DefaultInterval, 2 * MaxGrace}, // grace too long
	}
	for _, c := range cases {
		if _, err := h.store.Create(h.ctx, CreateOptions{
			Name: "x", Payload: sealed, Interval: c.interval, Grace: c.grace,
		}); !errors.Is(err, ErrBadSchedule) {
			t.Errorf("interval=%s grace=%s: err = %v, want ErrBadSchedule", c.interval, c.grace, err)
		}
	}
}

func TestCreateRequiresRecipients(t *testing.T) {
	h := newHarness(t)
	if _, err := h.store.Create(h.ctx, CreateOptions{Name: "empty"}); !errors.Is(err, ErrNoRecipients) {
		t.Errorf("err = %v, want ErrNoRecipients", err)
	}
}

/* ------------------------------------------------------------ engine ----- */

// The core safety property: an armed switch inside its window does nothing at
// all. No reminders, no firing.
func TestNothingHappensBeforeTheCheckInIsDue(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t, Contact{Kind: ContactWebhook, Address: "https://example.com/hook"})
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	h.advance(29 * 24 * time.Hour) // interval is 30d
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if h.notifier.count() != 0 {
		t.Errorf("%d reminders sent before the check-in was due", h.notifier.count())
	}
	if h.releaser.callCount() != 0 {
		t.Error("the switch fired before its deadline")
	}
}

// The most important test in the package. A missed check-in must escalate, not
// release: a holiday is far more likely than a death.
func TestOverdueSwitchRemindsButDoesNotFireDuringGrace(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t,
		Contact{Kind: ContactWebhook, Address: "https://example.com/owner"},
		Contact{Kind: ContactWebhook, Address: "https://example.com/trusted", Trusted: true},
	)
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	// Just past the check-in, deep inside the 10-day grace period.
	h.advance(30*24*time.Hour + time.Hour)
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if h.notifier.count() == 0 {
		t.Error("an overdue switch sent no reminder")
	}
	if h.releaser.callCount() != 0 {
		t.Fatal("the switch fired during its grace period")
	}

	current, err := h.store.Get(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if current.State != StateArmed {
		t.Errorf("state = %q during grace, want it still armed", current.State)
	}
}

// Escalation reaches the owner first and the trusted contact only near the
// end, so someone who knows them gets a chance to intervene.
func TestTrustedContactIsNudgedLast(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t,
		Contact{Kind: ContactWebhook, Address: "https://example.com/owner"},
		Contact{Kind: ContactWebhook, Address: "https://example.com/trusted", Trusted: true},
	)
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	// Just overdue: stage 1 only, owner alone.
	h.advance(30*24*time.Hour + time.Hour)
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	for _, n := range h.notifier.all() {
		if n.contact.Trusted {
			t.Error("the trusted contact was nudged on the first reminder")
		}
	}

	// 90% through the grace period: stage 3 reaches the trusted contact.
	h.advance(8 * 24 * time.Hour)
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	var trustedNudged bool
	for _, n := range h.notifier.all() {
		if n.contact.Trusted {
			trustedNudged = true
			if !strings.Contains(n.body, "trusted contact") {
				t.Error("the trusted contact's message does not explain their role")
			}
		}
	}
	if !trustedNudged {
		t.Error("the trusted contact was never nudged before firing")
	}
	if h.releaser.callCount() != 0 {
		t.Error("the switch fired before the grace period elapsed")
	}
}

// Reminders must be sent once per cycle, not on every tick — the engine runs
// every few minutes.
func TestRemindersAreNotRepeatedOnEveryTick(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t, Contact{Kind: ContactWebhook, Address: "https://example.com/hook"})
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	h.advance(30*24*time.Hour + time.Hour)
	for i := 0; i < 5; i++ {
		if err := h.engine.Tick(h.ctx); err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
	}

	if got := h.notifier.count(); got != 1 {
		t.Errorf("%d reminders after five ticks, want 1", got)
	}
}

// Checking in must reset escalation, so the next missed cycle starts fresh
// rather than resuming near the end of the previous one.
func TestCheckInResetsEscalation(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t, Contact{Kind: ContactWebhook, Address: "https://example.com/hook"})
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	h.advance(30*24*time.Hour + time.Hour)
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	before := h.notifier.count()

	if _, err := h.store.CheckIn(h.ctx, sw.ID, "cli"); err != nil {
		t.Fatalf("CheckIn: %v", err)
	}
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick after check-in: %v", err)
	}
	if h.notifier.count() != before {
		t.Error("a reminder was sent after the owner checked in")
	}

	// Miss the next cycle entirely: escalation starts over.
	h.advance(31 * 24 * time.Hour)
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if h.notifier.count() <= before {
		t.Error("escalation did not restart for the next missed cycle")
	}
}

func TestSwitchFiresAfterGraceElapses(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t, Contact{Kind: ContactWebhook, Address: "https://example.com/hook"})
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	h.advance(41 * 24 * time.Hour) // 30d interval + 10d grace, plus a day
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if h.releaser.callCount() != 1 {
		t.Fatalf("releaser called %d times, want 1", h.releaser.callCount())
	}

	fired, err := h.store.Get(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fired.State != StateFired {
		t.Errorf("state = %q, want fired", fired.State)
	}
	if fired.ReleaseCID != "bafyRELEASED" {
		t.Errorf("release CID = %q, want it recorded", fired.ReleaseCID)
	}
	if fired.FiredAt == nil {
		t.Error("fired_at was not recorded")
	}
}

// A fired switch must not fire again on the next tick.
func TestFiredSwitchIsNotReleasedTwice(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t)
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	h.advance(41 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := h.engine.Tick(h.ctx); err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
	}
	if h.releaser.callCount() != 1 {
		t.Errorf("releaser called %d times, want exactly 1", h.releaser.callCount())
	}
}

// If publishing fails the payload is not actually anywhere the recipients can
// reach, so recording the switch as fired would quietly lose it.
func TestFailedReleaseLeavesSwitchArmedForRetry(t *testing.T) {
	h := newHarness(t)
	h.releaser.err = errors.New("ipfs node unreachable")

	sw := h.newSwitch(t)
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	h.advance(41 * 24 * time.Hour)
	_ = h.engine.Tick(h.ctx) // the error is logged, not returned

	current, err := h.store.Get(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if current.State == StateFired {
		t.Fatal("the switch was marked fired even though publishing failed")
	}

	// A later tick retries once the destination is reachable again.
	h.releaser.err = nil
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	retried, err := h.store.Get(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if retried.State != StateFired {
		t.Error("the switch never fired after the destination recovered")
	}
}

func TestDisarmedSwitchNeverFires(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t)
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if _, err := h.store.Disarm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Disarm: %v", err)
	}

	h.advance(365 * 24 * time.Hour)
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if h.releaser.callCount() != 0 {
		t.Error("a disarmed switch fired")
	}
}

/* ------------------------------------------------------------- drill ----- */

// The drill is what makes the machinery trustworthy: it must exercise the path
// without releasing anything or disturbing the switch.
func TestDrillNotifiesWithoutFiring(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t,
		Contact{Kind: ContactWebhook, Address: "https://example.com/owner"},
		Contact{Kind: ContactWebhook, Address: "https://example.com/trusted", Trusted: true},
	)
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	before, err := h.store.Get(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	result, err := h.engine.Drill(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Drill: %v", err)
	}

	if h.releaser.callCount() != 0 {
		t.Error("a drill released the payload")
	}
	if len(result.Notified) != 2 {
		t.Errorf("drill notified %d contacts, want 2", len(result.Notified))
	}
	if result.PayloadBytes == 0 {
		t.Error("the drill did not report the payload size")
	}

	// Every message must be unmistakably a test.
	for _, n := range h.notifier.all() {
		if !strings.Contains(n.subject, "DRILL") {
			t.Errorf("drill message subject is not labelled a drill: %q", n.subject)
		}
		if !strings.Contains(n.body, "has not fired") {
			t.Errorf("drill body does not make clear nothing fired: %q", n.body)
		}
	}

	after, err := h.store.Get(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.State != before.State {
		t.Errorf("the drill changed the switch state from %q to %q", before.State, after.State)
	}
	if !after.Deadline().Equal(before.Deadline()) {
		t.Error("the drill moved the firing deadline")
	}
}

func TestDrillReportsNotificationFailures(t *testing.T) {
	h := newHarness(t)
	h.notifier.err = errors.New("mail server refused")

	sw := h.newSwitch(t, Contact{Kind: ContactEmail, Address: "someone@example.com"})

	result, err := h.engine.Drill(h.ctx, sw.ID)
	if err != nil {
		t.Fatalf("Drill: %v", err)
	}
	if len(result.Failures) != 1 {
		t.Errorf("drill reported %d failures, want 1", len(result.Failures))
	}
	if len(result.Notified) != 0 {
		t.Error("drill counted a failed delivery as notified")
	}
}

/* -------------------------------------------------------- event trail ---- */

// The event log is what an owner reads to decide whether to trust the switch,
// so every meaningful action has to appear in it.
func TestEventTrailRecordsTheLifecycle(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t, Contact{Kind: ContactWebhook, Address: "https://example.com/hook"})

	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if _, err := h.store.CheckIn(h.ctx, sw.ID, "cli"); err != nil {
		t.Fatalf("CheckIn: %v", err)
	}
	if _, err := h.engine.Drill(h.ctx, sw.ID); err != nil {
		t.Fatalf("Drill: %v", err)
	}

	events, err := h.store.Events(h.ctx, sw.ID, 50)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}

	want := map[string]bool{EventCreated: false, EventArmed: false, EventCheckIn: false, EventDrill: false}
	for _, e := range events {
		if _, ok := want[e.Kind]; ok {
			want[e.Kind] = true
		}
	}
	for kind, seen := range want {
		if !seen {
			t.Errorf("the event trail is missing %q", kind)
		}
	}
}

func TestActionsOnFiredSwitchAreRefused(t *testing.T) {
	h := newHarness(t)
	sw := h.newSwitch(t)
	if _, err := h.store.Arm(h.ctx, sw.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	h.advance(41 * 24 * time.Hour)
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	if _, err := h.store.CheckIn(h.ctx, sw.ID, "cli"); !errors.Is(err, ErrAlreadyFired) {
		t.Errorf("CheckIn on a fired switch: err = %v, want ErrAlreadyFired", err)
	}
	if _, err := h.store.Arm(h.ctx, sw.ID); !errors.Is(err, ErrAlreadyFired) {
		t.Errorf("Arm on a fired switch: err = %v, want ErrAlreadyFired", err)
	}
	if err := h.engine.Fire(h.ctx, sw.ID); !errors.Is(err, ErrAlreadyFired) {
		t.Errorf("Fire on a fired switch: err = %v, want ErrAlreadyFired", err)
	}
}

func TestMultipleSwitchesAreIndependent(t *testing.T) {
	h := newHarness(t)

	family := h.newSwitch(t)
	lawyer := h.newSwitch(t)

	if _, err := h.store.Arm(h.ctx, family.ID); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	// lawyer stays disarmed

	h.advance(41 * 24 * time.Hour)
	if err := h.engine.Tick(h.ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	f, err := h.store.Get(h.ctx, family.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	l, err := h.store.Get(h.ctx, lawyer.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if f.State != StateFired {
		t.Error("the armed switch did not fire")
	}
	if l.State != StateDisarmed {
		t.Error("the disarmed switch was affected by the other firing")
	}
}
