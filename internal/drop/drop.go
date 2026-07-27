// Package drop stores encrypted file transfers.
//
// The server's entire view of a drop is: an opaque blob, its size, when it
// expires, and how many times it has been fetched. It never sees the filename,
// the content type, or the key — the client encrypts a metadata envelope into
// the blob, and the key travels in the URL fragment, which browsers do not
// send to servers.
//
// That is not a policy this package enforces on top of a richer model; it is
// the whole model. There is no column to put a filename in.
package drop

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/fomothy/denly.xyz/internal/store"
)

// Limits. MaxCiphertext bounds a single drop; self-hosters can raise it, but a
// default of nothing would let one request fill the disk.
const (
	MaxCiphertext = 100 << 20 // 100 MiB
	MinTTL        = time.Minute
	MaxTTL        = 30 * 24 * time.Hour
	DefaultTTL    = 7 * 24 * time.Hour

	// AccessLogRetention is how long access records survive. The plan promises
	// logs rot within 24h; this is that promise, and SweepAccessLog enforces it.
	AccessLogRetention = 24 * time.Hour

	// ReceiveRequestTTL bounds how long an unanswered request lingers.
	ReceiveRequestTTL = 7 * 24 * time.Hour

	idBytes = 16
)

var (
	// ErrNotFound is returned when a drop does not exist.
	ErrNotFound = errors.New("drop not found")
	// ErrGone is returned when a drop existed but has expired or burned out.
	// It is deliberately distinct from ErrNotFound so a caller can tell "wrong
	// link" from "the link was real and is now spent".
	ErrGone = errors.New("drop is no longer available")
	// ErrTooLarge is returned for ciphertext beyond the size limit.
	ErrTooLarge = errors.New("drop exceeds the size limit")
	// ErrRequestNotPending is returned when approving or denying a request
	// that has already been decided.
	ErrRequestNotPending = errors.New("request is not pending")
)

// Drop is the server's complete view of a stored transfer.
type Drop struct {
	ID            string     `json:"id"`
	SizeBytes     int64      `json:"size_bytes"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	MaxDownloads  *int       `json:"max_downloads,omitempty"`
	DownloadCount int        `json:"download_count"`
	BurnedAt      *time.Time `json:"burned_at,omitempty"`
}

// Options configure a new drop.
type Options struct {
	// TTL is how long the drop lives. Zero means DefaultTTL.
	TTL time.Duration
	// MaxDownloads burns the drop after N fetches. Zero means unlimited.
	MaxDownloads int
}

// RequestStatus is the state of a receive-box request.
type RequestStatus string

// The lifecycle of a receive-box request. A request moves pending -> approved
// -> uploaded, or pending -> denied, and never backwards.
const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
	StatusUploaded RequestStatus = "uploaded"
)

// ReceiveRequest is a stranger asking permission to send you a file.
type ReceiveRequest struct {
	ID        string        `json:"id"`
	Note      string        `json:"note"`
	SizeHint  *int64        `json:"size_hint,omitempty"`
	Status    RequestStatus `json:"status"`
	DropID    *string       `json:"drop_id,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	DecidedAt *time.Time    `json:"decided_at,omitempty"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// Service stores and serves drops.
type Service struct {
	store *store.Store
	now   func() time.Time
}

// New builds a Service.
func New(st *store.Store) *Service {
	return &Service{store: st, now: func() time.Time { return time.Now().UTC() }}
}

// Create stores ciphertext and returns its handle.
//
// The caller must have encrypted the payload already. This function has no way
// to check that, which is the point: it cannot distinguish ciphertext from
// plaintext, so it also cannot be tempted to look.
func (s *Service) Create(ctx context.Context, ciphertext []byte, opts Options) (Drop, error) {
	if len(ciphertext) == 0 {
		return Drop{}, errors.New("drop is empty")
	}
	if len(ciphertext) > MaxCiphertext {
		return Drop{}, fmt.Errorf("%w: %d bytes, limit is %d", ErrTooLarge, len(ciphertext), MaxCiphertext)
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < MinTTL || ttl > MaxTTL {
		return Drop{}, fmt.Errorf("expiry must be between %s and %s", MinTTL, MaxTTL)
	}
	if opts.MaxDownloads < 0 {
		return Drop{}, errors.New("download limit cannot be negative")
	}

	id, err := newID()
	if err != nil {
		return Drop{}, err
	}

	now := s.now()
	expires := now.Add(ttl)

	var maxDownloads any
	if opts.MaxDownloads > 0 {
		maxDownloads = opts.MaxDownloads
	}

	_, err = s.store.DB().ExecContext(ctx, `
		INSERT INTO drops (id, ciphertext, size_bytes, created_at, expires_at, max_downloads)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, ciphertext, int64(len(ciphertext)), now.Format(time.RFC3339),
		expires.Format(time.RFC3339), maxDownloads)
	if err != nil {
		return Drop{}, fmt.Errorf("storing drop: %w", err)
	}

	d := Drop{
		ID:        id,
		SizeBytes: int64(len(ciphertext)),
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	if opts.MaxDownloads > 0 {
		n := opts.MaxDownloads
		d.MaxDownloads = &n
	}
	return d, nil
}

// Fetch returns the ciphertext and records the access.
//
// This is the only path that increments the download count, and it burns the
// drop when the limit is reached. The whole operation runs in one transaction
// so two simultaneous fetches of a burn-after-1 drop cannot both succeed.
func (s *Service) Fetch(ctx context.Context, id string) ([]byte, Drop, error) {
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, Drop{}, fmt.Errorf("fetching drop: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	d, ciphertext, err := scanDropTx(ctx, tx, id, true)
	if err != nil {
		return nil, Drop{}, err
	}

	now := s.now()
	if d.BurnedAt != nil {
		return nil, Drop{}, ErrGone
	}
	if d.ExpiresAt != nil && now.After(*d.ExpiresAt) {
		return nil, Drop{}, ErrGone
	}
	if d.MaxDownloads != nil && d.DownloadCount >= *d.MaxDownloads {
		return nil, Drop{}, ErrGone
	}

	d.DownloadCount++

	// Burn on the fetch that reaches the limit, not the one after. Otherwise a
	// "burn after 1 download" drop is readable twice.
	var burnedAt any
	if d.MaxDownloads != nil && d.DownloadCount >= *d.MaxDownloads {
		burnedAt = now.Format(time.RFC3339)
		d.BurnedAt = &now
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE drops SET download_count = ?, burned_at = ? WHERE id = ?`,
		d.DownloadCount, burnedAt, id); err != nil {
		return nil, Drop{}, fmt.Errorf("recording download: %w", err)
	}

	// The access row carries a timestamp and nothing else — no address, no
	// user agent. It exists to enforce burn limits and show recent activity,
	// and it is swept within 24h.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO drop_access (drop_id, accessed_at) VALUES (?, ?)`,
		id, now.Format(time.RFC3339)); err != nil {
		return nil, Drop{}, fmt.Errorf("recording access: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, Drop{}, fmt.Errorf("fetching drop: %w", err)
	}
	return ciphertext, d, nil
}

// Get returns a drop's metadata without counting a download.
func (s *Service) Get(ctx context.Context, id string) (Drop, error) {
	d, _, err := scanDrop(ctx, s.store.DB(), id, false)
	return d, err
}

// List returns drops the owner still has, newest first.
func (s *Service) List(ctx context.Context) ([]Drop, error) {
	rows, err := s.store.DB().QueryContext(ctx, `
		SELECT id, size_bytes, created_at, expires_at, max_downloads, download_count, burned_at
		FROM drops ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("listing drops: %w", err)
	}
	defer func() { _ = rows.Close() }()

	drops := make([]Drop, 0, 16)
	for rows.Next() {
		d, err := scanDropRow(rows)
		if err != nil {
			return nil, err
		}
		drops = append(drops, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing drops: %w", err)
	}
	return drops, nil
}

// Delete removes a drop and its ciphertext immediately.
func (s *Service) Delete(ctx context.Context, id string) error {
	res, err := s.store.DB().ExecContext(ctx, `DELETE FROM drops WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting drop: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SweepExpired deletes expired and burned drops, returning how many went.
//
// Expiry has to actually delete the bytes. A drop that merely stops being
// served but stays on disk is exactly the outcome denly promises to avoid.
func (s *Service) SweepExpired(ctx context.Context) (int64, error) {
	res, err := s.store.DB().ExecContext(ctx, `
		DELETE FROM drops
		WHERE (expires_at IS NOT NULL AND expires_at < ?)
		   OR burned_at IS NOT NULL
	`, s.now().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("sweeping expired drops: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SweepAccessLog deletes access records older than the retention window.
func (s *Service) SweepAccessLog(ctx context.Context) (int64, error) {
	cutoff := s.now().Add(-AccessLogRetention)
	res, err := s.store.DB().ExecContext(ctx,
		`DELETE FROM drop_access WHERE accessed_at < ?`, cutoff.Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("sweeping access log: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// RecentAccessCount reports fetches within the retention window.
func (s *Service) RecentAccessCount(ctx context.Context, id string) (int, error) {
	var n int
	err := s.store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM drop_access WHERE drop_id = ?`, id).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting access: %w", err)
	}
	return n, nil
}

// RequestReceive records a stranger's request to send a file.
//
// Nothing is stored but the note and an optional size hint. No bytes are
// accepted until the owner approves, which is what keeps an open receive box
// from becoming an open disk.
func (s *Service) RequestReceive(ctx context.Context, note string, sizeHint int64) (ReceiveRequest, error) {
	const maxNote = 500
	if len(note) > maxNote {
		return ReceiveRequest{}, fmt.Errorf("note is %d characters, limit is %d", len(note), maxNote)
	}
	if sizeHint < 0 {
		return ReceiveRequest{}, errors.New("size hint cannot be negative")
	}
	if sizeHint > MaxCiphertext {
		return ReceiveRequest{}, fmt.Errorf("%w: %d bytes, limit is %d", ErrTooLarge, sizeHint, MaxCiphertext)
	}

	id, err := newID()
	if err != nil {
		return ReceiveRequest{}, err
	}

	now := s.now()
	expires := now.Add(ReceiveRequestTTL)

	var hint any
	if sizeHint > 0 {
		hint = sizeHint
	}

	if _, err := s.store.DB().ExecContext(ctx, `
		INSERT INTO receive_requests (id, note, size_hint, status, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, note, hint, string(StatusPending),
		now.Format(time.RFC3339), expires.Format(time.RFC3339)); err != nil {
		return ReceiveRequest{}, fmt.Errorf("recording receive request: %w", err)
	}

	r := ReceiveRequest{
		ID:        id,
		Note:      note,
		Status:    StatusPending,
		CreatedAt: now,
		ExpiresAt: expires,
	}
	if sizeHint > 0 {
		r.SizeHint = &sizeHint
	}
	return r, nil
}

// PendingRequests lists requests awaiting a decision.
func (s *Service) PendingRequests(ctx context.Context) ([]ReceiveRequest, error) {
	rows, err := s.store.DB().QueryContext(ctx, `
		SELECT id, note, size_hint, status, drop_id, created_at, decided_at, expires_at
		FROM receive_requests
		WHERE status = ? AND expires_at > ?
		ORDER BY created_at DESC
	`, string(StatusPending), s.now().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("listing receive requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]ReceiveRequest, 0, 8)
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing receive requests: %w", err)
	}
	return out, nil
}

// GetRequest fetches a single receive request.
func (s *Service) GetRequest(ctx context.Context, id string) (ReceiveRequest, error) {
	row := s.store.DB().QueryRowContext(ctx, `
		SELECT id, note, size_hint, status, drop_id, created_at, decided_at, expires_at
		FROM receive_requests WHERE id = ?
	`, id)
	r, err := scanRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ReceiveRequest{}, ErrNotFound
	}
	return r, err
}

// Decide approves or denies a pending request.
func (s *Service) Decide(ctx context.Context, id string, approve bool) (ReceiveRequest, error) {
	status := StatusDenied
	if approve {
		status = StatusApproved
	}

	res, err := s.store.DB().ExecContext(ctx, `
		UPDATE receive_requests SET status = ?, decided_at = ?
		WHERE id = ? AND status = ?
	`, string(status), s.now().Format(time.RFC3339), id, string(StatusPending))
	if err != nil {
		return ReceiveRequest{}, fmt.Errorf("deciding receive request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either it does not exist or it was already decided. Distinguish, so
		// the caller can tell a stale UI from a bad ID.
		if _, err := s.GetRequest(ctx, id); errors.Is(err, ErrNotFound) {
			return ReceiveRequest{}, ErrNotFound
		}
		return ReceiveRequest{}, ErrRequestNotPending
	}
	return s.GetRequest(ctx, id)
}

// FulfilRequest stores the sender's ciphertext against an approved request.
//
// It refuses anything not in the approved state, which is the enforcement
// point for the whole approval flow: an unapproved request has no path to
// writing bytes.
func (s *Service) FulfilRequest(ctx context.Context, id string, ciphertext []byte, opts Options) (Drop, error) {
	r, err := s.GetRequest(ctx, id)
	if err != nil {
		return Drop{}, err
	}
	if r.Status != StatusApproved {
		return Drop{}, fmt.Errorf("%w: status is %q", ErrRequestNotPending, r.Status)
	}
	if s.now().After(r.ExpiresAt) {
		return Drop{}, ErrGone
	}

	d, err := s.Create(ctx, ciphertext, opts)
	if err != nil {
		return Drop{}, err
	}

	if _, err := s.store.DB().ExecContext(ctx,
		`UPDATE receive_requests SET status = ?, drop_id = ? WHERE id = ?`,
		string(StatusUploaded), d.ID, id); err != nil {
		return Drop{}, fmt.Errorf("linking drop to request: %w", err)
	}
	return d, nil
}

// SweepRequests deletes expired receive requests.
func (s *Service) SweepRequests(ctx context.Context) (int64, error) {
	res, err := s.store.DB().ExecContext(ctx,
		`DELETE FROM receive_requests WHERE expires_at < ?`, s.now().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("sweeping receive requests: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// newID returns a URL-safe random identifier.
//
// 128 bits from the CSPRNG: drop IDs are effectively capability tokens, since
// anyone holding the link can attempt a fetch, so they must not be guessable.
func newID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating drop id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func scanDrop(ctx context.Context, q queryer, id string, withCiphertext bool) (Drop, []byte, error) {
	cols := `id, size_bytes, created_at, expires_at, max_downloads, download_count, burned_at`
	if withCiphertext {
		cols += `, ciphertext`
	}
	row := q.QueryRowContext(ctx, `SELECT `+cols+` FROM drops WHERE id = ?`, id)

	var (
		d                   Drop
		createdAt           string
		expiresAt, burnedAt sql.NullString
		maxDownloads        sql.NullInt64
		ciphertext          []byte
	)

	dest := []any{&d.ID, &d.SizeBytes, &createdAt, &expiresAt, &maxDownloads, &d.DownloadCount, &burnedAt}
	if withCiphertext {
		dest = append(dest, &ciphertext)
	}
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Drop{}, nil, ErrNotFound
		}
		return Drop{}, nil, fmt.Errorf("reading drop: %w", err)
	}

	d.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if expiresAt.Valid {
		if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
			d.ExpiresAt = &t
		}
	}
	if burnedAt.Valid {
		if t, err := time.Parse(time.RFC3339, burnedAt.String); err == nil {
			d.BurnedAt = &t
		}
	}
	if maxDownloads.Valid {
		n := int(maxDownloads.Int64)
		d.MaxDownloads = &n
	}
	return d, ciphertext, nil
}

func scanDropTx(ctx context.Context, tx *sql.Tx, id string, withCiphertext bool) (Drop, []byte, error) {
	return scanDrop(ctx, tx, id, withCiphertext)
}

func scanDropRow(rows *sql.Rows) (Drop, error) {
	var (
		d                   Drop
		createdAt           string
		expiresAt, burnedAt sql.NullString
		maxDownloads        sql.NullInt64
	)
	if err := rows.Scan(&d.ID, &d.SizeBytes, &createdAt, &expiresAt,
		&maxDownloads, &d.DownloadCount, &burnedAt); err != nil {
		return Drop{}, fmt.Errorf("scanning drop: %w", err)
	}
	d.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if expiresAt.Valid {
		if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
			d.ExpiresAt = &t
		}
	}
	if burnedAt.Valid {
		if t, err := time.Parse(time.RFC3339, burnedAt.String); err == nil {
			d.BurnedAt = &t
		}
	}
	if maxDownloads.Valid {
		n := int(maxDownloads.Int64)
		d.MaxDownloads = &n
	}
	return d, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRequest(sc scanner) (ReceiveRequest, error) {
	var (
		r                    ReceiveRequest
		status               string
		sizeHint             sql.NullInt64
		dropID, decidedAt    sql.NullString
		createdAt, expiresAt string
	)
	if err := sc.Scan(&r.ID, &r.Note, &sizeHint, &status, &dropID,
		&createdAt, &decidedAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ReceiveRequest{}, err
		}
		return ReceiveRequest{}, fmt.Errorf("scanning receive request: %w", err)
	}

	r.Status = RequestStatus(status)
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	r.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	if sizeHint.Valid {
		n := sizeHint.Int64
		r.SizeHint = &n
	}
	if dropID.Valid {
		v := dropID.String
		r.DropID = &v
	}
	if decidedAt.Valid {
		if t, err := time.Parse(time.RFC3339, decidedAt.String); err == nil {
			r.DecidedAt = &t
		}
	}
	return r, nil
}
