package deadhand

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// The heartbeat engine.
//
// Escalation exists because the most likely reason a check-in is missed is a
// holiday, a hospital stay, or a dead phone — not death. So a missed check-in
// starts a conversation rather than a release: the owner is reminded, then
// reminded again, then a trusted contact is nudged, and only after all of that
// and the full grace period does anything fire.
//
// The engine is deliberately conservative: on any doubt it does not fire.
// A switch that fires late is an inconvenience; a switch that fires early
// publishes someone's private papers while they are alive.

// Reminder stages, expressed as the fraction of the grace period elapsed at
// which each fires.
var reminderStages = []struct {
	stage    int
	fraction float64
	trusted  bool
	label    string
}{
	{stage: 1, fraction: 0.0, trusted: false, label: "check-in overdue"},
	{stage: 2, fraction: 0.5, trusted: false, label: "check-in still overdue"},
	{stage: 3, fraction: 0.8, trusted: true, label: "switch will fire soon"},
}

// Notifier delivers an escalation message.
type Notifier interface {
	Notify(ctx context.Context, contact Contact, subject, body string) error
}

// Releaser publishes a fired payload somewhere durable, returning a locator.
type Releaser interface {
	Release(ctx context.Context, switchID string, payload []byte) (cid string, txID string, err error)
}

// Engine evaluates switches on a schedule.
type Engine struct {
	store    *Store
	notifier Notifier
	releaser Releaser
	log      *slog.Logger
	now      func() time.Time
}

// NewEngine builds an Engine. notifier and releaser may be nil: an instance
// with neither still tracks liveness and records events, it just cannot warn
// anyone or publish. That is a legitimate configuration, and refusing to run
// would be worse than running with reduced function.
func NewEngine(st *Store, notifier Notifier, releaser Releaser, log *slog.Logger) *Engine {
	return &Engine{
		store:    st,
		notifier: notifier,
		releaser: releaser,
		log:      log,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Tick evaluates every armed switch once, sending due reminders and firing
// switches whose grace period has fully elapsed.
func (e *Engine) Tick(ctx context.Context) error {
	switches, err := e.store.List(ctx)
	if err != nil {
		return err
	}

	now := e.now()
	for _, sw := range switches {
		if sw.State != StateArmed {
			continue
		}
		if err := e.evaluate(ctx, sw, now); err != nil {
			// One bad switch must not stop the others being evaluated: the
			// whole point is that this runs unattended.
			e.log.Error("evaluating switch", "switch", sw.ID, "name", sw.Name, "error", err)
		}
	}
	return nil
}

func (e *Engine) evaluate(ctx context.Context, sw Switch, now time.Time) error {
	deadline := sw.Deadline()
	if deadline.IsZero() {
		return nil
	}
	due := sw.DueAt()
	if now.Before(due) {
		return nil // still within the check-in window
	}

	// The cycle identifies this run of missed check-ins, so reminders are sent
	// once each and a restart does not repeat them.
	cycle := due.Format(time.RFC3339)
	graceSeconds := float64(sw.Grace)
	elapsed := now.Sub(due).Seconds()

	for _, stage := range reminderStages {
		at := due.Add(time.Duration(stage.fraction * graceSeconds * float64(time.Second)))
		if now.Before(at) {
			continue
		}
		sent, err := e.reminderSent(ctx, sw.ID, stage.stage, cycle)
		if err != nil {
			return err
		}
		if sent {
			continue
		}
		if err := e.sendReminder(ctx, sw, stage.stage, stage.trusted, stage.label, deadline); err != nil {
			return err
		}
		if err := e.markReminderSent(ctx, sw.ID, stage.stage, cycle, now); err != nil {
			return err
		}
	}

	if now.Before(deadline) {
		e.log.Debug("switch overdue but within grace",
			"switch", sw.ID, "fires_in", deadline.Sub(now).String())
		return nil
	}

	// Grace fully elapsed with no check-in and every reminder sent.
	e.log.Warn("switch deadline passed; releasing",
		"switch", sw.ID, "name", sw.Name, "overdue_by", now.Sub(deadline).String(),
		"elapsed_since_due", time.Duration(elapsed*float64(time.Second)).String())
	return e.Fire(ctx, sw.ID)
}

// Fire releases a switch's payload and marks it spent.
func (e *Engine) Fire(ctx context.Context, id string) error {
	sw, err := e.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if sw.State == StateFired {
		return ErrAlreadyFired
	}

	payload, err := e.store.Payload(ctx, id)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("deadhand: encoding payload for release: %w", err)
	}

	var cid, txID string
	if e.releaser != nil {
		cid, txID, err = e.releaser.Release(ctx, id, raw)
		if err != nil {
			// Do NOT mark the switch fired. If publishing failed, the payload
			// is not actually anywhere the recipients can reach, and recording
			// it as released would quietly lose it. Leave it armed so the next
			// tick tries again.
			if recErr := e.store.record(ctx, id, EventFireError, err.Error()); recErr != nil {
				e.log.Error("recording fire failure", "switch", id, "error", recErr)
			}
			return fmt.Errorf("deadhand: releasing switch %s: %w", id, err)
		}
	} else {
		e.log.Warn("no releaser configured; the payload stays on this server only",
			"switch", id)
	}

	if err := e.store.MarkFired(ctx, id, cid, txID); err != nil {
		return err
	}

	e.notifyRecipients(ctx, sw, cid)
	e.log.Warn("switch fired", "switch", id, "name", sw.Name, "cid", cid, "arweave", txID)
	return nil
}

// Drill exercises the whole path — reminders, notification, and the release
// encoding — without publishing anything or marking the switch spent.
//
// This exists so a user can trust the machinery. A dead man's switch nobody
// has ever seen work is a promise, not a mechanism.
func (e *Engine) Drill(ctx context.Context, id string) (DrillResult, error) {
	sw, err := e.store.Get(ctx, id)
	if err != nil {
		return DrillResult{}, err
	}

	payload, err := e.store.Payload(ctx, id)
	if err != nil {
		return DrillResult{}, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return DrillResult{}, fmt.Errorf("deadhand: encoding payload: %w", err)
	}

	contacts, err := e.store.Contacts(ctx, id)
	if err != nil {
		return DrillResult{}, err
	}

	result := DrillResult{
		SwitchID:     id,
		Name:         sw.Name,
		PayloadBytes: int64(len(raw)),
		Recipients:   sw.Recipients,
		Threshold:    sw.Threshold,
		ReleaserSet:  e.releaser != nil,
		NotifierSet:  e.notifier != nil,
	}

	// Deliver a clearly-labelled test message to every contact, so the owner
	// finds out now whether their address still works.
	for _, c := range contacts {
		body := fmt.Sprintf(
			"This is a DRILL for the denly switch %q.\n\n"+
				"Nothing has been released and the switch has not fired. This message "+
				"confirms that this address would receive a real alert.\n",
			sw.Name)
		if err := e.notify(ctx, c, "[DRILL] denly switch test", body); err != nil {
			result.Failures = append(result.Failures,
				fmt.Sprintf("%s %s: %v", c.Kind, c.Address, err))
			continue
		}
		result.Notified = append(result.Notified, c.Kind+" "+c.Address)
	}

	if err := e.store.record(ctx, id, EventDrill,
		fmt.Sprintf("notified %d, failed %d", len(result.Notified), len(result.Failures))); err != nil {
		return result, err
	}

	// The switch is untouched: same state, same deadline, still armed if it
	// was armed.
	result.StateAfter = sw.State
	return result, nil
}

// DrillResult reports what a drill exercised.
type DrillResult struct {
	SwitchID     string   `json:"switch_id"`
	Name         string   `json:"name"`
	PayloadBytes int64    `json:"payload_bytes"`
	Recipients   []string `json:"recipients"`
	Threshold    int      `json:"threshold,omitempty"`
	ReleaserSet  bool     `json:"releaser_configured"`
	NotifierSet  bool     `json:"notifier_configured"`
	Notified     []string `json:"notified,omitempty"`
	Failures     []string `json:"failures,omitempty"`
	StateAfter   State    `json:"state_after"`
}

func (e *Engine) sendReminder(ctx context.Context, sw Switch, stage int, trustedOnly bool, label string, deadline time.Time) error {
	contacts, err := e.store.Contacts(ctx, sw.ID)
	if err != nil {
		return err
	}

	remaining := deadline.Sub(e.now())
	subject := fmt.Sprintf("[denly] %s: %s", sw.Name, label)

	var body string
	if trustedOnly {
		body = fmt.Sprintf(
			"You are listed as a trusted contact for a denly dead man's switch named %q.\n\n"+
				"Its owner has not checked in, and it will release its contents in %s "+
				"unless they do.\n\n"+
				"If you can reach them, now is the moment. If you cannot, no action is "+
				"needed — the switch will act on its own.\n",
			sw.Name, remaining.Round(time.Hour))
	} else {
		body = fmt.Sprintf(
			"Your denly switch %q has not seen a check-in.\n\n"+
				"It will release its contents in %s unless you check in:\n\n"+
				"    denly deadhand checkin %s\n\n"+
				"If you are reading this and well, that command is all it takes.\n",
			sw.Name, remaining.Round(time.Hour), sw.ID)
	}

	sent := 0
	for _, c := range contacts {
		if trustedOnly != c.Trusted {
			continue
		}
		if err := e.notify(ctx, c, subject, body); err != nil {
			e.log.Error("sending reminder", "switch", sw.ID, "contact", c.Address, "error", err)
			continue
		}
		sent++
	}

	e.log.Info("escalation reminder", "switch", sw.ID, "stage", stage,
		"contacts", sent, "fires_in", remaining.Round(time.Minute).String())
	return e.store.record(ctx, sw.ID, EventReminder,
		fmt.Sprintf("stage %d, %d contacts, fires in %s", stage, sent, remaining.Round(time.Hour)))
}

// notifyRecipients tells recipients where to find the released payload. It is
// best-effort: the release already happened, and a failed email must not undo
// it or block the others.
func (e *Engine) notifyRecipients(ctx context.Context, sw Switch, cid string) {
	contacts, err := e.store.Contacts(ctx, sw.ID)
	if err != nil {
		e.log.Error("listing contacts after firing", "switch", sw.ID, "error", err)
		return
	}

	where := "on this denly instance"
	if cid != "" {
		where = "at IPFS CID " + cid
	}
	body := fmt.Sprintf(
		"The denly switch %q has fired.\n\n"+
			"Its contents are published %s. They are encrypted: only the named "+
			"recipients, or a threshold of guardians, can open them.\n",
		sw.Name, where)

	for _, c := range contacts {
		if err := e.notify(ctx, c, fmt.Sprintf("[denly] %s has fired", sw.Name), body); err != nil {
			e.log.Error("notifying after firing", "switch", sw.ID, "contact", c.Address, "error", err)
		}
	}
}

func (e *Engine) notify(ctx context.Context, c Contact, subject, body string) error {
	if e.notifier == nil {
		return fmt.Errorf("no notifier configured")
	}
	return e.notifier.Notify(ctx, c, subject, body)
}

func (e *Engine) reminderSent(ctx context.Context, switchID string, stage int, cycle string) (bool, error) {
	var n int
	err := e.store.db.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM switch_reminders WHERE switch_id = ? AND stage = ? AND cycle = ?`,
		switchID, stage, cycle).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("deadhand: checking reminder state: %w", err)
	}
	return n > 0, nil
}

func (e *Engine) markReminderSent(ctx context.Context, switchID string, stage int, cycle string, at time.Time) error {
	_, err := e.store.db.DB().ExecContext(ctx,
		`INSERT OR IGNORE INTO switch_reminders (switch_id, stage, cycle, sent_at) VALUES (?, ?, ?, ?)`,
		switchID, stage, cycle, at.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("deadhand: recording reminder: %w", err)
	}
	return nil
}

// Run evaluates switches until the context is cancelled.
func (e *Engine) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	if err := e.Tick(ctx); err != nil {
		e.log.Error("deadhand tick", "error", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.Tick(ctx); err != nil {
				e.log.Error("deadhand tick", "error", err)
			}
		}
	}
}
