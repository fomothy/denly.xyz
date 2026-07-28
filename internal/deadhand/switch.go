package deadhand

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fomothy/denly.xyz/internal/store"
)

// Schedule bounds. A check-in interval shorter than an hour turns the switch
// into a chore nobody keeps up with, which is its own failure mode; longer
// than a year and the machinery has gone untested for too long to trust.
const (
	MinInterval = time.Hour
	MaxInterval = 365 * 24 * time.Hour
	MinGrace    = time.Hour
	MaxGrace    = 90 * 24 * time.Hour

	DefaultInterval = 30 * 24 * time.Hour
	DefaultGrace    = 14 * 24 * time.Hour
)

// State is a switch's position in its lifecycle.
type State string

const (
	// StateDisarmed means the switch exists but is not counting down. New
	// switches start here so nothing can fire before the owner is ready.
	StateDisarmed State = "disarmed"
	// StateArmed means the countdown is running.
	StateArmed State = "armed"
	// StateFired means the payload has been released.
	StateFired State = "fired"
)

// Event kinds recorded against a switch.
const (
	EventCreated   = "created"
	EventArmed     = "armed"
	EventDisarmed  = "disarmed"
	EventCheckIn   = "checkin"
	EventReminder  = "reminder"
	EventDrill     = "drill"
	EventFired     = "fired"
	EventFireError = "fire_error"
)

// Contact kinds for escalation.
const (
	ContactEmail   = "email"
	ContactWebhook = "webhook"
)

var (
	// ErrNotFound is returned when a switch does not exist.
	ErrNotFound = errors.New("deadhand: no such switch")
	// ErrBadSchedule is returned for an out-of-range interval or grace period.
	ErrBadSchedule = errors.New("deadhand: invalid schedule")
	// ErrAlreadyFired is returned when acting on a spent switch. A fired
	// switch is history, not a resource to be edited.
	ErrAlreadyFired = errors.New("deadhand: this switch has already fired")
)

// Switch is a dead man's switch as the server knows it.
type Switch struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	State        State      `json:"state"`
	PayloadBytes int64      `json:"payload_bytes"`
	Recipients   []string   `json:"recipients"`
	Threshold    int        `json:"threshold,omitempty"`
	Interval     int64      `json:"checkin_interval_seconds"`
	Grace        int64      `json:"grace_period_seconds"`
	LastCheckIn  *time.Time `json:"last_checkin_at,omitempty"`
	ArmedAt      *time.Time `json:"armed_at,omitempty"`
	FiredAt      *time.Time `json:"fired_at,omitempty"`
	ReleaseCID   string     `json:"release_cid,omitempty"`
	ReleaseTx    string     `json:"release_tx,omitempty"`
	PublicNotice bool       `json:"public_notice"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Deadline is when this switch fires if nothing changes.
//
// Zero for a switch that is not armed: a disarmed switch has no deadline, and
// reporting one would be alarming and wrong.
func (s Switch) Deadline() time.Time {
	if s.State != StateArmed {
		return time.Time{}
	}
	from := s.ArmedAt
	if s.LastCheckIn != nil && (from == nil || s.LastCheckIn.After(*from)) {
		from = s.LastCheckIn
	}
	if from == nil {
		return time.Time{}
	}
	return from.Add(time.Duration(s.Interval+s.Grace) * time.Second)
}

// DueAt is when the next check-in is expected, before the grace period.
func (s Switch) DueAt() time.Time {
	deadline := s.Deadline()
	if deadline.IsZero() {
		return time.Time{}
	}
	return deadline.Add(-time.Duration(s.Grace) * time.Second)
}

// Contact is an escalation destination.
type Contact struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Address string `json:"address"`
	// Trusted contacts are nudged last, immediately before release, so someone
	// who knows the owner has a chance to intervene.
	Trusted bool `json:"trusted"`
}

// Event is one entry in a switch's history.
type Event struct {
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// CreateOptions describe a new switch.
type CreateOptions struct {
	Name         string
	Payload      SealedPayload
	Interval     time.Duration
	Grace        time.Duration
	PublicNotice bool
	Contacts     []Contact
}

// Store persists switches.
type Store struct {
	db  *store.Store
	now func() time.Time
}

// NewStore builds a Store.
func NewStore(st *store.Store) *Store {
	return &Store{db: st, now: func() time.Time { return time.Now().UTC() }}
}

// Create stores a new switch, disarmed.
//
// New switches never start armed. Arming is a separate, deliberate act,
// because a switch that begins counting down the moment it is created will
// eventually fire on someone who was still setting it up.
func (s *Store) Create(ctx context.Context, opts CreateOptions) (Switch, error) {
	if opts.Name == "" {
		return Switch{}, errors.New("deadhand: a switch needs a name")
	}
	interval, grace, err := normaliseSchedule(opts.Interval, opts.Grace)
	if err != nil {
		return Switch{}, err
	}
	if len(opts.Payload.Wraps) == 0 && opts.Payload.Threshold == 0 {
		return Switch{}, ErrNoRecipients
	}

	raw, err := json.Marshal(opts.Payload)
	if err != nil {
		return Switch{}, fmt.Errorf("deadhand: encoding payload: %w", err)
	}

	id, err := newID()
	if err != nil {
		return Switch{}, err
	}
	now := s.now()

	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return Switch{}, fmt.Errorf("deadhand: creating switch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO switches (id, name, payload, payload_bytes, checkin_interval, grace_period,
		                      state, public_notice, threshold, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, opts.Name, raw, int64(len(raw)), int64(interval.Seconds()), int64(grace.Seconds()),
		string(StateDisarmed), boolToInt(opts.PublicNotice), opts.Payload.Threshold,
		now.Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		return Switch{}, fmt.Errorf("deadhand: creating switch: %w", err)
	}

	for _, c := range opts.Contacts {
		if err := insertContact(ctx, tx, id, c, now); err != nil {
			return Switch{}, err
		}
	}
	if err := insertEvent(ctx, tx, id, EventCreated, opts.Name, now); err != nil {
		return Switch{}, err
	}

	if err := tx.Commit(); err != nil {
		return Switch{}, fmt.Errorf("deadhand: creating switch: %w", err)
	}
	return s.Get(ctx, id)
}

// Get returns a switch's metadata, without the payload.
func (s *Store) Get(ctx context.Context, id string) (Switch, error) {
	row := s.db.DB().QueryRowContext(ctx, selectSwitchColumns+` WHERE id = ?`, id)
	sw, err := scanSwitch(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Switch{}, ErrNotFound
	}
	if err != nil {
		return Switch{}, err
	}
	sw.Recipients, err = s.recipients(ctx, id)
	return sw, err
}

// List returns every switch, newest first.
func (s *Store) List(ctx context.Context) ([]Switch, error) {
	rows, err := s.db.DB().QueryContext(ctx, selectSwitchColumns+` ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("deadhand: listing switches: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]Switch, 0, 8)
	for rows.Next() {
		sw, err := scanSwitch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("deadhand: listing switches: %w", err)
	}

	for i := range out {
		if out[i].Recipients, err = s.recipients(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Payload returns the sealed payload. The server can hand this out but cannot
// read it.
func (s *Store) Payload(ctx context.Context, id string) (SealedPayload, error) {
	var raw []byte
	err := s.db.DB().QueryRowContext(ctx, `SELECT payload FROM switches WHERE id = ?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SealedPayload{}, ErrNotFound
	}
	if err != nil {
		return SealedPayload{}, fmt.Errorf("deadhand: reading payload: %w", err)
	}

	var p SealedPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return SealedPayload{}, fmt.Errorf("deadhand: decoding payload: %w", err)
	}
	return p, nil
}

// Arm starts the countdown, recording the moment as the first check-in.
func (s *Store) Arm(ctx context.Context, id string) (Switch, error) {
	sw, err := s.Get(ctx, id)
	if err != nil {
		return Switch{}, err
	}
	if sw.State == StateFired {
		return Switch{}, ErrAlreadyFired
	}

	now := s.now()
	if _, err := s.db.DB().ExecContext(ctx, `
		UPDATE switches SET state = ?, armed_at = ?, last_checkin_at = ?, updated_at = ?
		WHERE id = ?
	`, string(StateArmed), now.Format(time.RFC3339), now.Format(time.RFC3339),
		now.Format(time.RFC3339), id); err != nil {
		return Switch{}, fmt.Errorf("deadhand: arming: %w", err)
	}
	if err := s.record(ctx, id, EventArmed, ""); err != nil {
		return Switch{}, err
	}
	return s.Get(ctx, id)
}

// Disarm stops the countdown.
func (s *Store) Disarm(ctx context.Context, id string) (Switch, error) {
	sw, err := s.Get(ctx, id)
	if err != nil {
		return Switch{}, err
	}
	if sw.State == StateFired {
		return Switch{}, ErrAlreadyFired
	}

	if _, err := s.db.DB().ExecContext(ctx,
		`UPDATE switches SET state = ?, updated_at = ? WHERE id = ?`,
		string(StateDisarmed), s.now().Format(time.RFC3339), id); err != nil {
		return Switch{}, fmt.Errorf("deadhand: disarming: %w", err)
	}
	if err := s.record(ctx, id, EventDisarmed, ""); err != nil {
		return Switch{}, err
	}
	return s.Get(ctx, id)
}

// CheckIn records proof of life, resetting the countdown.
func (s *Store) CheckIn(ctx context.Context, id, via string) (Switch, error) {
	sw, err := s.Get(ctx, id)
	if err != nil {
		return Switch{}, err
	}
	if sw.State == StateFired {
		return Switch{}, ErrAlreadyFired
	}

	now := s.now()
	tx, err := s.db.DB().BeginTx(ctx, nil)
	if err != nil {
		return Switch{}, fmt.Errorf("deadhand: checking in: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`UPDATE switches SET last_checkin_at = ?, updated_at = ? WHERE id = ?`,
		now.Format(time.RFC3339), now.Format(time.RFC3339), id); err != nil {
		return Switch{}, fmt.Errorf("deadhand: checking in: %w", err)
	}
	// Clear reminders so the next missed cycle starts its escalation fresh,
	// rather than resuming where the last one left off.
	if _, err := tx.ExecContext(ctx, `DELETE FROM switch_reminders WHERE switch_id = ?`, id); err != nil {
		return Switch{}, fmt.Errorf("deadhand: clearing reminders: %w", err)
	}
	if err := insertEvent(ctx, tx, id, EventCheckIn, via, now); err != nil {
		return Switch{}, err
	}
	if err := tx.Commit(); err != nil {
		return Switch{}, fmt.Errorf("deadhand: checking in: %w", err)
	}
	return s.Get(ctx, id)
}

// Delete removes a switch and its payload.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.DB().ExecContext(ctx, `DELETE FROM switches WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deadhand: deleting switch: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkFired records a release.
func (s *Store) MarkFired(ctx context.Context, id, cid, txID string) error {
	now := s.now()
	if _, err := s.db.DB().ExecContext(ctx, `
		UPDATE switches SET state = ?, fired_at = ?, release_cid = ?, release_tx = ?, updated_at = ?
		WHERE id = ?
	`, string(StateFired), now.Format(time.RFC3339), cid, txID, now.Format(time.RFC3339), id); err != nil {
		return fmt.Errorf("deadhand: marking fired: %w", err)
	}
	detail := cid
	if txID != "" {
		detail += " arweave:" + txID
	}
	return s.record(ctx, id, EventFired, detail)
}

// Contacts returns a switch's escalation destinations.
func (s *Store) Contacts(ctx context.Context, id string) ([]Contact, error) {
	rows, err := s.db.DB().QueryContext(ctx,
		`SELECT id, kind, address, trusted FROM switch_contacts WHERE switch_id = ? ORDER BY trusted, id`, id)
	if err != nil {
		return nil, fmt.Errorf("deadhand: listing contacts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]Contact, 0, 4)
	for rows.Next() {
		var (
			c       Contact
			trusted int
		)
		if err := rows.Scan(&c.ID, &c.Kind, &c.Address, &trusted); err != nil {
			return nil, fmt.Errorf("deadhand: scanning contact: %w", err)
		}
		c.Trusted = trusted != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// Events returns a switch's history, newest first.
func (s *Store) Events(ctx context.Context, id string, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.DB().QueryContext(ctx,
		`SELECT kind, detail, at FROM switch_events WHERE switch_id = ? ORDER BY at DESC, id DESC LIMIT ?`,
		id, limit)
	if err != nil {
		return nil, fmt.Errorf("deadhand: listing events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]Event, 0, limit)
	for rows.Next() {
		var (
			e  Event
			at string
		)
		if err := rows.Scan(&e.Kind, &e.Detail, &at); err != nil {
			return nil, fmt.Errorf("deadhand: scanning event: %w", err)
		}
		e.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// record appends an event.
func (s *Store) record(ctx context.Context, id, kind, detail string) error {
	_, err := s.db.DB().ExecContext(ctx,
		`INSERT INTO switch_events (switch_id, kind, detail, at) VALUES (?, ?, ?, ?)`,
		id, kind, detail, s.now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("deadhand: recording %s: %w", kind, err)
	}
	return nil
}

// recipients reads the recipient list out of the stored payload, so the
// listing does not need a second source of truth that could disagree.
func (s *Store) recipients(ctx context.Context, id string) ([]string, error) {
	p, err := s.Payload(ctx, id)
	if err != nil {
		return nil, err
	}
	return p.Recipients(), nil
}

const selectSwitchColumns = `
	SELECT id, name, state, payload_bytes, checkin_interval, grace_period,
	       last_checkin_at, armed_at, fired_at, release_cid, release_tx,
	       public_notice, threshold, created_at, updated_at
	FROM switches`

type scanner interface{ Scan(dest ...any) error }

func scanSwitch(sc scanner) (Switch, error) {
	var (
		sw                            Switch
		state                         string
		lastCheckIn, armedAt, firedAt sql.NullString
		publicNotice                  int
		createdAt, updatedAt          string
	)
	if err := sc.Scan(&sw.ID, &sw.Name, &state, &sw.PayloadBytes, &sw.Interval, &sw.Grace,
		&lastCheckIn, &armedAt, &firedAt, &sw.ReleaseCID, &sw.ReleaseTx,
		&publicNotice, &sw.Threshold, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Switch{}, err
		}
		return Switch{}, fmt.Errorf("deadhand: scanning switch: %w", err)
	}

	sw.State = State(state)
	sw.PublicNotice = publicNotice != 0
	sw.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	sw.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	sw.LastCheckIn = parseNullTime(lastCheckIn)
	sw.ArmedAt = parseNullTime(armedAt)
	sw.FiredAt = parseNullTime(firedAt)
	return sw, nil
}

func parseNullTime(v sql.NullString) *time.Time {
	if !v.Valid {
		return nil
	}
	t, err := time.Parse(time.RFC3339, v.String)
	if err != nil {
		return nil
	}
	return &t
}

func insertContact(ctx context.Context, tx *sql.Tx, switchID string, c Contact, now time.Time) error {
	if c.Kind != ContactEmail && c.Kind != ContactWebhook {
		return fmt.Errorf("deadhand: unsupported contact kind %q", c.Kind)
	}
	if c.Address == "" {
		return errors.New("deadhand: a contact needs an address")
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO switch_contacts (switch_id, kind, address, trusted, created_at) VALUES (?, ?, ?, ?, ?)`,
		switchID, c.Kind, c.Address, boolToInt(c.Trusted), now.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("deadhand: adding contact: %w", err)
	}
	return nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, switchID, kind, detail string, now time.Time) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO switch_events (switch_id, kind, detail, at) VALUES (?, ?, ?, ?)`,
		switchID, kind, detail, now.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("deadhand: recording %s: %w", kind, err)
	}
	return nil
}

func normaliseSchedule(interval, grace time.Duration) (time.Duration, time.Duration, error) {
	if interval == 0 {
		interval = DefaultInterval
	}
	if grace == 0 {
		grace = DefaultGrace
	}
	if interval < MinInterval || interval > MaxInterval {
		return 0, 0, fmt.Errorf("%w: check-in interval must be between %s and %s",
			ErrBadSchedule, MinInterval, MaxInterval)
	}
	if grace < MinGrace || grace > MaxGrace {
		return 0, 0, fmt.Errorf("%w: grace period must be between %s and %s",
			ErrBadSchedule, MinGrace, MaxGrace)
	}
	return interval, grace, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("deadhand: generating id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
