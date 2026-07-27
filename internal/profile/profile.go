// Package profile holds the presence page's content: who you are, where else
// to find you, and what you have written.
//
// Everything here is public by definition — it is the page strangers read — so
// unlike the rest of denly there is no ciphertext involved. The interesting
// property is Export: the whole thing comes back out as one JSON bundle at any
// time, because a tool that promises you can leave has to make leaving a
// single command.
package profile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fomothy/denly.xyz/internal/store"
)

// Limits on stored content. These are not security boundaries — the owner is
// the only writer — but they stop a runaway client from filling the database.
const (
	MaxDisplayName = 200
	MaxBio         = 10_000
	MaxLabel       = 200
	MaxURL         = 2_000
	MaxTitle       = 300
	MaxBody        = 500_000
	MaxLinks       = 100
)

// ErrNotFound is returned when a post or link does not exist.
var ErrNotFound = errors.New("not found")

var slugPattern = regexp.MustCompile(`[^a-z0-9]+`)

// Profile is the presence page's header.
type Profile struct {
	DisplayName string    `json:"display_name"`
	Bio         string    `json:"bio"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Link is an outbound link shown on the page.
type Link struct {
	ID        int64     `json:"id"`
	Label     string    `json:"label"`
	URL       string    `json:"url"`
	Position  int       `json:"position"`
	CreatedAt time.Time `json:"created_at"`
}

// Post is a note or article.
type Post struct {
	ID          int64      `json:"id"`
	Slug        string     `json:"slug"`
	Title       string     `json:"title"`
	Body        string     `json:"body"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Published reports whether the post is visible to the public.
func (p Post) Published() bool { return p.PublishedAt != nil }

// Service reads and writes presence content.
type Service struct {
	store *store.Store
	now   func() time.Time
}

// New builds a Service.
func New(st *store.Store) *Service {
	return &Service{store: st, now: func() time.Time { return time.Now().UTC() }}
}

// Get returns the profile header, or a zero-valued one before it is first set.
func (s *Service) Get(ctx context.Context) (Profile, error) {
	var (
		p         Profile
		updatedAt string
	)
	err := s.store.DB().QueryRowContext(ctx,
		`SELECT display_name, bio, updated_at FROM profile WHERE id = 1`,
	).Scan(&p.DisplayName, &p.Bio, &updatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, nil
	}
	if err != nil {
		return Profile{}, fmt.Errorf("reading profile: %w", err)
	}
	p.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return p, nil
}

// Save writes the profile header.
func (s *Service) Save(ctx context.Context, p Profile) error {
	name := strings.TrimSpace(p.DisplayName)
	bio := strings.TrimSpace(p.Bio)

	if len(name) > MaxDisplayName {
		return fmt.Errorf("display name is %d characters, limit is %d", len(name), MaxDisplayName)
	}
	if len(bio) > MaxBio {
		return fmt.Errorf("bio is %d characters, limit is %d", len(bio), MaxBio)
	}

	_, err := s.store.DB().ExecContext(ctx, `
		INSERT INTO profile (id, display_name, bio, updated_at) VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			display_name = excluded.display_name,
			bio          = excluded.bio,
			updated_at   = excluded.updated_at
	`, name, bio, s.now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("saving profile: %w", err)
	}
	return nil
}

// Links returns links in display order.
func (s *Service) Links(ctx context.Context) ([]Link, error) {
	rows, err := s.store.DB().QueryContext(ctx,
		`SELECT id, label, url, position, created_at FROM links ORDER BY position, id`)
	if err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	defer func() { _ = rows.Close() }()

	links := make([]Link, 0, 8)
	for rows.Next() {
		var (
			l         Link
			createdAt string
		)
		if err := rows.Scan(&l.ID, &l.Label, &l.URL, &l.Position, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning link: %w", err)
		}
		l.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	return links, nil
}

// AddLink appends a link to the page.
func (s *Service) AddLink(ctx context.Context, label, rawURL string, position int) (Link, error) {
	label = strings.TrimSpace(label)
	rawURL = strings.TrimSpace(rawURL)

	if label == "" {
		return Link{}, errors.New("a link needs a label")
	}
	if len(label) > MaxLabel {
		return Link{}, fmt.Errorf("label is %d characters, limit is %d", len(label), MaxLabel)
	}
	if err := validateURL(rawURL); err != nil {
		return Link{}, err
	}

	var count int
	if err := s.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM links`).Scan(&count); err != nil {
		return Link{}, fmt.Errorf("counting links: %w", err)
	}
	if count >= MaxLinks {
		return Link{}, fmt.Errorf("the page already has %d links, the limit is %d", count, MaxLinks)
	}

	now := s.now()
	res, err := s.store.DB().ExecContext(ctx,
		`INSERT INTO links (label, url, position, created_at) VALUES (?, ?, ?, ?)`,
		label, rawURL, position, now.Format(time.RFC3339))
	if err != nil {
		return Link{}, fmt.Errorf("adding link: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Link{}, fmt.Errorf("adding link: %w", err)
	}
	return Link{ID: id, Label: label, URL: rawURL, Position: position, CreatedAt: now}, nil
}

// DeleteLink removes a link.
func (s *Service) DeleteLink(ctx context.Context, id int64) error {
	res, err := s.store.DB().ExecContext(ctx, `DELETE FROM links WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting link: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Posts lists posts, newest first. When publishedOnly is set, drafts are
// omitted — that is the distinction between the public page and the owner's
// view, so callers must be explicit about which they want.
func (s *Service) Posts(ctx context.Context, publishedOnly bool) ([]Post, error) {
	query := `SELECT id, slug, title, body, published_at, created_at, updated_at FROM posts`
	if publishedOnly {
		query += ` WHERE published_at IS NOT NULL`
	}
	query += ` ORDER BY COALESCE(published_at, created_at) DESC, id DESC`

	rows, err := s.store.DB().QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("listing posts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	posts := make([]Post, 0, 16)
	for rows.Next() {
		p, err := scanPost(rows)
		if err != nil {
			return nil, err
		}
		posts = append(posts, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing posts: %w", err)
	}
	return posts, nil
}

// PostBySlug fetches one post.
func (s *Service) PostBySlug(ctx context.Context, slug string) (Post, error) {
	row := s.store.DB().QueryRowContext(ctx,
		`SELECT id, slug, title, body, published_at, created_at, updated_at FROM posts WHERE slug = ?`, slug)

	p, err := scanPost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Post{}, ErrNotFound
	}
	return p, err
}

// SavePost creates or updates a post, keyed by slug.
func (s *Service) SavePost(ctx context.Context, title, body string, publish bool) (Post, error) {
	title = strings.TrimSpace(title)
	body = strings.TrimSpace(body)

	if title == "" {
		return Post{}, errors.New("a post needs a title")
	}
	if len(title) > MaxTitle {
		return Post{}, fmt.Errorf("title is %d characters, limit is %d", len(title), MaxTitle)
	}
	if len(body) > MaxBody {
		return Post{}, fmt.Errorf("body is %d characters, limit is %d", len(body), MaxBody)
	}

	slug := Slugify(title)
	if slug == "" {
		return Post{}, errors.New("that title produces an empty slug; use some letters or numbers")
	}

	now := s.now()
	var publishedAt any
	if publish {
		publishedAt = now.Format(time.RFC3339)
	}

	_, err := s.store.DB().ExecContext(ctx, `
		INSERT INTO posts (slug, title, body, published_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(slug) DO UPDATE SET
			title        = excluded.title,
			body         = excluded.body,
			-- Re-saving a draft must not silently publish it, and re-saving a
			-- published post must not silently unpublish it. Only an explicit
			-- publish moves it forward.
			published_at = COALESCE(posts.published_at, excluded.published_at),
			updated_at   = excluded.updated_at
	`, slug, title, body, publishedAt, now.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return Post{}, fmt.Errorf("saving post: %w", err)
	}
	return s.PostBySlug(ctx, slug)
}

// DeletePost removes a post.
func (s *Service) DeletePost(ctx context.Context, slug string) error {
	res, err := s.store.DB().ExecContext(ctx, `DELETE FROM posts WHERE slug = ?`, slug)
	if err != nil {
		return fmt.Errorf("deleting post: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Bundle is the portable export of everything on the presence page.
type Bundle struct {
	Version    int       `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	PublicKey  string    `json:"public_key,omitempty"`
	Profile    Profile   `json:"profile"`
	Links      []Link    `json:"links"`
	Posts      []Post    `json:"posts"`
}

// Export produces the full bundle, drafts included.
//
// Drafts are included deliberately: this is the owner's copy of their own
// work, and an export that quietly dropped unpublished writing would be a
// nasty surprise for someone leaving.
func (s *Service) Export(ctx context.Context, publicKey string) (Bundle, error) {
	p, err := s.Get(ctx)
	if err != nil {
		return Bundle{}, err
	}
	links, err := s.Links(ctx)
	if err != nil {
		return Bundle{}, err
	}
	posts, err := s.Posts(ctx, false)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Version:    1,
		ExportedAt: s.now(),
		PublicKey:  publicKey,
		Profile:    p,
		Links:      links,
		Posts:      posts,
	}, nil
}

// ExportJSON renders the bundle as indented JSON, which is what the CLI and
// the export endpoint both hand back.
func (s *Service) ExportJSON(ctx context.Context, publicKey string) ([]byte, error) {
	bundle, err := s.Export(ctx, publicKey)
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding export bundle: %w", err)
	}
	return raw, nil
}

// Slugify turns a title into a URL-safe identifier.
func Slugify(title string) string {
	s := strings.ToLower(strings.TrimSpace(title))
	s = slugPattern.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 80 {
		s = strings.Trim(s[:80], "-")
	}
	return s
}

// validateURL rejects anything that is not plainly http(s).
//
// Link targets are rendered into a public page. Permitting javascript: or
// data: URLs here would hand every visitor's browser to whoever could write a
// link — and while only the owner can write, defence in depth is cheap.
func validateURL(raw string) error {
	if raw == "" {
		return errors.New("a link needs a URL")
	}
	if len(raw) > MaxURL {
		return fmt.Errorf("URL is %d characters, limit is %d", len(raw), MaxURL)
	}
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return errors.New("links must start with http:// or https://")
	}
	if strings.ContainsAny(raw, "\r\n\t") {
		return errors.New("URL contains control characters")
	}
	return nil
}

// rowScanner covers both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanPost(sc rowScanner) (Post, error) {
	var (
		p                    Post
		publishedAt          sql.NullString
		createdAt, updatedAt string
	)
	if err := sc.Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &publishedAt, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Post{}, err
		}
		return Post{}, fmt.Errorf("scanning post: %w", err)
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	p.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if publishedAt.Valid {
		if t, err := time.Parse(time.RFC3339, publishedAt.String); err == nil {
			p.PublishedAt = &t
		}
	}
	return p, nil
}
