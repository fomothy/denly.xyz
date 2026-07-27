package profile

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

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

func TestProfileStartsEmptyAndSaves(t *testing.T) {
	s, ctx := newTestService(t)

	got, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("Get on a fresh instance: %v", err)
	}
	if got.DisplayName != "" || got.Bio != "" {
		t.Error("a fresh profile is not empty")
	}

	if err := s.Save(ctx, Profile{DisplayName: "Nick", Bio: "builds things"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err = s.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DisplayName != "Nick" || got.Bio != "builds things" {
		t.Errorf("Get = %+v, want the saved values", got)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt was not set")
	}
}

// The profile table is pinned to a single row; saving twice must update rather
// than create a second profile that disagrees with the first.
func TestProfileSaveIsUpsert(t *testing.T) {
	s, ctx := newTestService(t)

	if err := s.Save(ctx, Profile{DisplayName: "First"}); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := s.Save(ctx, Profile{DisplayName: "Second"}); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	got, _ := s.Get(ctx)
	if got.DisplayName != "Second" {
		t.Errorf("DisplayName = %q, want the later value", got.DisplayName)
	}
}

func TestProfileRejectsOversizedFields(t *testing.T) {
	s, ctx := newTestService(t)

	if err := s.Save(ctx, Profile{DisplayName: strings.Repeat("a", MaxDisplayName+1)}); err == nil {
		t.Error("an oversized display name was accepted")
	}
	if err := s.Save(ctx, Profile{Bio: strings.Repeat("a", MaxBio+1)}); err == nil {
		t.Error("an oversized bio was accepted")
	}
}

func TestLinksRoundTripInOrder(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.AddLink(ctx, "Second", "https://b.example", 2); err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	if _, err := s.AddLink(ctx, "First", "https://a.example", 1); err != nil {
		t.Fatalf("AddLink: %v", err)
	}

	links, err := s.Links(ctx)
	if err != nil {
		t.Fatalf("Links: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("got %d links, want 2", len(links))
	}
	if links[0].Label != "First" || links[1].Label != "Second" {
		t.Errorf("links are not in position order: %q then %q", links[0].Label, links[1].Label)
	}
}

// Link targets end up in a public page. javascript: and data: URLs must never
// make it into storage, even though only the owner can write them.
func TestAddLinkRejectsDangerousURLs(t *testing.T) {
	s, ctx := newTestService(t)

	bad := []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD4=",
		"file:///etc/passwd",
		"ftp://example.com",
		"",
		"https://example.com/\r\nX-Injected: yes",
	}
	for _, u := range bad {
		if _, err := s.AddLink(ctx, "bad", u, 0); err == nil {
			t.Errorf("AddLink accepted %q", u)
		}
	}
}

func TestAddLinkRequiresLabel(t *testing.T) {
	s, ctx := newTestService(t)
	if _, err := s.AddLink(ctx, "   ", "https://example.com", 0); err == nil {
		t.Error("AddLink accepted a blank label")
	}
}

func TestDeleteLink(t *testing.T) {
	s, ctx := newTestService(t)

	l, err := s.AddLink(ctx, "Gone", "https://example.com", 0)
	if err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	if err := s.DeleteLink(ctx, l.ID); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}
	if err := s.DeleteLink(ctx, l.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteLink = %v, want ErrNotFound", err)
	}
}

func TestSavePostCreatesDraft(t *testing.T) {
	s, ctx := newTestService(t)

	p, err := s.SavePost(ctx, "Hello World", "body text", false)
	if err != nil {
		t.Fatalf("SavePost: %v", err)
	}
	if p.Slug != "hello-world" {
		t.Errorf("slug = %q, want hello-world", p.Slug)
	}
	if p.Published() {
		t.Error("a post saved with publish=false is published")
	}
}

// Editing a draft must not publish it, and editing a published post must not
// retract it. Both would be destructive surprises.
func TestSavePostDoesNotChangePublicationStateImplicitly(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.SavePost(ctx, "Note", "v1", false); err != nil {
		t.Fatalf("SavePost: %v", err)
	}
	edited, err := s.SavePost(ctx, "Note", "v2", false)
	if err != nil {
		t.Fatalf("re-save: %v", err)
	}
	if edited.Published() {
		t.Error("re-saving a draft published it")
	}

	published, err := s.SavePost(ctx, "Note", "v3", true)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !published.Published() {
		t.Fatal("publishing did not take effect")
	}

	reEdited, err := s.SavePost(ctx, "Note", "v4", false)
	if err != nil {
		t.Fatalf("edit after publish: %v", err)
	}
	if !reEdited.Published() {
		t.Error("editing a published post unpublished it")
	}
	if reEdited.Body != "v4" {
		t.Errorf("body = %q, want the edited text", reEdited.Body)
	}
}

func TestPostsPublishedOnlyFiltersDrafts(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.SavePost(ctx, "Draft", "hidden", false); err != nil {
		t.Fatalf("SavePost: %v", err)
	}
	if _, err := s.SavePost(ctx, "Live", "visible", true); err != nil {
		t.Fatalf("SavePost: %v", err)
	}

	all, err := s.Posts(ctx, false)
	if err != nil {
		t.Fatalf("Posts(all): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("owner view has %d posts, want 2", len(all))
	}

	public, err := s.Posts(ctx, true)
	if err != nil {
		t.Fatalf("Posts(published): %v", err)
	}
	if len(public) != 1 {
		t.Fatalf("public view has %d posts, want 1", len(public))
	}
	if public[0].Title != "Live" {
		t.Errorf("public view shows %q, want the published post", public[0].Title)
	}
}

func TestPostBySlugNotFound(t *testing.T) {
	s, ctx := newTestService(t)
	if _, err := s.PostBySlug(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDeletePost(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.SavePost(ctx, "Temp", "x", false); err != nil {
		t.Fatalf("SavePost: %v", err)
	}
	if err := s.DeletePost(ctx, "temp"); err != nil {
		t.Fatalf("DeletePost: %v", err)
	}
	if err := s.DeletePost(ctx, "temp"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeletePost = %v, want ErrNotFound", err)
	}
}

func TestSavePostRejectsEmptyTitleAndUnsluggableTitle(t *testing.T) {
	s, ctx := newTestService(t)

	if _, err := s.SavePost(ctx, "   ", "body", false); err == nil {
		t.Error("SavePost accepted a blank title")
	}
	if _, err := s.SavePost(ctx, "!!! ???", "body", false); err == nil {
		t.Error("SavePost accepted a title with no sluggable characters")
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Hello World", "hello-world"},
		{"  Trim  Me  ", "trim-me"},
		{"Symbols!@#$Here", "symbols-here"},
		{"---leading and trailing---", "leading-and-trailing"},
		{"ALLCAPS", "allcaps"},
		{"!!!", ""},
		{strings.Repeat("a", 200), strings.Repeat("a", 80)},
	}
	for _, tt := range tests {
		if got := Slugify(tt.in); got != tt.want {
			t.Errorf("Slugify(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// An export that silently omitted drafts would lose someone's unpublished
// writing at exactly the moment they were leaving.
func TestExportIncludesDrafts(t *testing.T) {
	s, ctx := newTestService(t)

	if err := s.Save(ctx, Profile{DisplayName: "Nick", Bio: "bio"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := s.AddLink(ctx, "Site", "https://example.com", 0); err != nil {
		t.Fatalf("AddLink: %v", err)
	}
	if _, err := s.SavePost(ctx, "Public", "seen", true); err != nil {
		t.Fatalf("SavePost: %v", err)
	}
	if _, err := s.SavePost(ctx, "Private Draft", "unseen", false); err != nil {
		t.Fatalf("SavePost: %v", err)
	}

	raw, err := s.ExportJSON(ctx, "abc123")
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}

	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}

	if b.Version != 1 {
		t.Errorf("version = %d, want 1", b.Version)
	}
	if b.PublicKey != "abc123" {
		t.Errorf("public key = %q, want it carried through", b.PublicKey)
	}
	if b.Profile.DisplayName != "Nick" {
		t.Error("export is missing the profile")
	}
	if len(b.Links) != 1 {
		t.Errorf("export has %d links, want 1", len(b.Links))
	}
	if len(b.Posts) != 2 {
		t.Fatalf("export has %d posts, want 2 including the draft", len(b.Posts))
	}

	var foundDraft bool
	for _, p := range b.Posts {
		if p.Slug == "private-draft" {
			foundDraft = true
			if p.Published() {
				t.Error("the draft is marked published in the export")
			}
		}
	}
	if !foundDraft {
		t.Error("the export dropped the unpublished draft")
	}
}

func TestExportOnEmptyInstance(t *testing.T) {
	s, ctx := newTestService(t)

	raw, err := s.ExportJSON(ctx, "")
	if err != nil {
		t.Fatalf("ExportJSON on an empty instance: %v", err)
	}

	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	// Empty collections must serialise as [] rather than null, so consumers
	// can iterate without a nil check.
	if b.Links == nil || b.Posts == nil {
		t.Error("empty collections serialised as null instead of []")
	}
}
