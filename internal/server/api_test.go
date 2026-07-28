package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fomothy/denly.xyz/internal/drop"
)

// authed builds a request carrying the loopback admin token.
func authed(method, path string, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("Authorization", "Bearer "+testAdminToken)
	return r
}

func anon(method, path string, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	r.RemoteAddr = "203.0.113.9:5555"
	return r
}

func do(t *testing.T, s *Server, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	return rec
}

// The single most important test in this file: every route that changes
// owner-controlled state must reject an unauthenticated caller. A new endpoint
// added to the admin mux without auth would show up here.
func TestEveryMutableEndpointRequiresAuth(t *testing.T) {
	s := newTestServer(t)

	cases := []struct{ method, path string }{
		{http.MethodPut, "/api/admin/profile"},
		{http.MethodPost, "/api/admin/links"},
		{http.MethodDelete, "/api/admin/links/1"},
		{http.MethodGet, "/api/admin/posts"},
		{http.MethodPost, "/api/admin/posts"},
		{http.MethodDelete, "/api/admin/posts/some-slug"},
		{http.MethodGet, "/api/admin/export"},
		{http.MethodPost, "/api/drops"},
		{http.MethodGet, "/api/admin/drops"},
		{http.MethodDelete, "/api/admin/drops/abc"},
		{http.MethodGet, "/api/admin/receive"},
		{http.MethodPost, "/api/admin/receive/abc/approve"},
		{http.MethodPost, "/api/admin/identity/verify"},
		{http.MethodPost, "/api/admin/publish"},
		{http.MethodGet, "/api/admin/publish"},
		{http.MethodGet, "/api/admin/deadhand"},
		{http.MethodPost, "/api/admin/deadhand"},
		{http.MethodGet, "/api/admin/deadhand/abc"},
		{http.MethodDelete, "/api/admin/deadhand/abc"},
		{http.MethodPost, "/api/admin/deadhand/abc/arm"},
		{http.MethodPost, "/api/admin/deadhand/abc/disarm"},
		{http.MethodPost, "/api/admin/deadhand/abc/checkin"},
		{http.MethodPost, "/api/admin/deadhand/abc/drill"},
		{http.MethodPost, "/api/admin/deadhand/abc/fire"},
	}

	for _, c := range cases {
		rec := do(t, s, anon(c.method, c.path, []byte(`{}`)))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s returned %d for an anonymous caller, want 401",
				c.method, c.path, rec.Code)
		}
	}
}

func TestProfileSaveAndPublicRead(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]string{"display_name": "Nick", "bio": "builds things"})
	if rec := do(t, s, authed(http.MethodPut, "/api/admin/profile", body)); rec.Code != http.StatusOK {
		t.Fatalf("saving profile returned %d: %s", rec.Code, rec.Body)
	}

	rec := do(t, s, anon(http.MethodGet, "/api/profile", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("public profile returned %d", rec.Code)
	}

	var out struct {
		Profile struct {
			DisplayName string `json:"display_name"`
		} `json:"profile"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding profile: %v", err)
	}
	if out.Profile.DisplayName != "Nick" {
		t.Errorf("display name = %q, want Nick", out.Profile.DisplayName)
	}
	if out.PublicKey == "" {
		t.Error("public profile does not advertise the identity key")
	}
}

// Drafts must not leak through the public endpoints just because they exist.
func TestDraftsAreNotPubliclyReadable(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]any{"title": "Secret Draft", "body": "unpublished", "publish": false})
	if rec := do(t, s, authed(http.MethodPost, "/api/admin/posts", body)); rec.Code != http.StatusOK {
		t.Fatalf("saving post returned %d: %s", rec.Code, rec.Body)
	}

	rec := do(t, s, anon(http.MethodGet, "/api/posts/secret-draft", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("a draft was readable at its public URL (status %d)", rec.Code)
	}

	rec = do(t, s, anon(http.MethodGet, "/api/profile", nil))
	if strings.Contains(rec.Body.String(), "Secret Draft") {
		t.Error("a draft appeared in the public profile listing")
	}

	// The owner can still see it.
	rec = do(t, s, authed(http.MethodGet, "/api/admin/posts", nil))
	if !strings.Contains(rec.Body.String(), "Secret Draft") {
		t.Error("the owner's own draft is missing from the admin listing")
	}
}

func TestPublishedPostIsPubliclyReadable(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]any{"title": "Out Loud", "body": "published", "publish": true})
	if rec := do(t, s, authed(http.MethodPost, "/api/admin/posts", body)); rec.Code != http.StatusOK {
		t.Fatalf("saving post returned %d: %s", rec.Code, rec.Body)
	}

	rec := do(t, s, anon(http.MethodGet, "/api/posts/out-loud", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("published post returned %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "published") {
		t.Error("the published post body is missing")
	}
}

func TestNIP05Document(t *testing.T) {
	s := newTestServer(t)

	rec := do(t, s, anon(http.MethodGet, "/.well-known/nostr.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("well-known returned %d", rec.Code)
	}
	// Other people's browser clients fetch this cross-origin; without the
	// header, verification silently fails for them.
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("the NIP-05 document is not readable cross-origin")
	}

	var doc struct {
		Names map[string]string `json:"names"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding document: %v", err)
	}
	if doc.Names["_"] != s.owner.Hex() {
		t.Error("the reserved _ name does not map to the owner key")
	}
}

func TestNIP05NameFilter(t *testing.T) {
	s := newTestServer(t)

	rec := do(t, s, anon(http.MethodGet, "/.well-known/nostr.json?name=nobody", nil))
	var doc struct {
		Names map[string]string `json:"names"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding document: %v", err)
	}
	if len(doc.Names) != 0 {
		t.Errorf("asking for an unknown name returned %v, want an empty set", doc.Names)
	}
}

// The whole ciphertext-only story, end to end through HTTP.
func TestDropUploadAndAnonymousFetch(t *testing.T) {
	s := newTestServer(t)

	ciphertext, key, err := drop.Seal(drop.Envelope{
		Filename: "secret.txt",
		Content:  []byte("the actual contents"),
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	rec := do(t, s, authed(http.MethodPost, "/api/drops?burn_after=1", ciphertext))
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating drop returned %d: %s", rec.Code, rec.Body)
	}
	var created drop.Drop
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding drop: %v", err)
	}

	// The server's own response must not carry the filename — it never had it.
	if strings.Contains(rec.Body.String(), "secret.txt") {
		t.Error("the API response leaked the filename")
	}

	// Anyone with the link can fetch; no credentials involved.
	rec = do(t, s, anon(http.MethodGet, "/d/"+created.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("fetching drop returned %d", rec.Code)
	}

	env, err := drop.Open(rec.Body.Bytes(), key)
	if err != nil {
		t.Fatalf("opening fetched drop: %v", err)
	}
	if string(env.Content) != "the actual contents" {
		t.Error("the round-tripped content does not match")
	}
	if env.Filename != "secret.txt" {
		t.Error("the filename did not survive inside the envelope")
	}

	// Burn-after-1: the second fetch is Gone, not Not Found.
	rec = do(t, s, anon(http.MethodGet, "/d/"+created.ID, nil))
	if rec.Code != http.StatusGone {
		t.Errorf("second fetch returned %d, want 410", rec.Code)
	}
}

func TestFetchUnknownDropIs404(t *testing.T) {
	s := newTestServer(t)
	if rec := do(t, s, anon(http.MethodGet, "/d/no-such-drop", nil)); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// The receive box: a stranger may ask, but nothing lands until the owner says
// yes.
func TestReceiveBoxRequiresApprovalBeforeUpload(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]any{"note": "sending you that file", "size_hint": 100})
	rec := do(t, s, anon(http.MethodPost, "/api/receive", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("receive request returned %d: %s", rec.Code, rec.Body)
	}
	var req drop.ReceiveRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &req); err != nil {
		t.Fatalf("decoding request: %v", err)
	}

	// Uploading before approval must be refused.
	rec = do(t, s, anon(http.MethodPost, "/api/receive/"+req.ID+"/upload", []byte("payload")))
	if rec.Code != http.StatusForbidden {
		t.Errorf("upload before approval returned %d, want 403", rec.Code)
	}

	// Owner approves.
	rec = do(t, s, authed(http.MethodPost, "/api/admin/receive/"+req.ID+"/approve", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("approving returned %d: %s", rec.Code, rec.Body)
	}

	// Now the upload lands.
	rec = do(t, s, anon(http.MethodPost, "/api/receive/"+req.ID+"/upload", []byte("ciphertext payload")))
	if rec.Code != http.StatusCreated {
		t.Errorf("upload after approval returned %d: %s", rec.Code, rec.Body)
	}
}

func TestReceiveBoxDenial(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]any{"note": "no thanks"})
	rec := do(t, s, anon(http.MethodPost, "/api/receive", body))
	var req drop.ReceiveRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &req); err != nil {
		t.Fatalf("decoding request: %v", err)
	}

	if rec := do(t, s, authed(http.MethodPost, "/api/admin/receive/"+req.ID+"/deny", nil)); rec.Code != http.StatusOK {
		t.Fatalf("denying returned %d", rec.Code)
	}
	rec = do(t, s, anon(http.MethodPost, "/api/receive/"+req.ID+"/upload", []byte("payload")))
	if rec.Code != http.StatusForbidden {
		t.Errorf("upload after denial returned %d, want 403", rec.Code)
	}
}

func TestExportIncludesDraftsAndIsAttachment(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]any{"title": "Kept Back", "body": "draft", "publish": false})
	if rec := do(t, s, authed(http.MethodPost, "/api/admin/posts", body)); rec.Code != http.StatusOK {
		t.Fatalf("saving post: %d", rec.Code)
	}

	rec := do(t, s, authed(http.MethodGet, "/api/admin/export", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export returned %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	if !strings.Contains(rec.Body.String(), "Kept Back") {
		t.Error("the export omitted an unpublished draft")
	}
}

// A challenge must be obtainable without credentials — otherwise remote
// authentication has no entry point.
func TestChallengeIsPublicAndUsable(t *testing.T) {
	s := newTestServer(t)

	rec := do(t, s, anon(http.MethodGet, "/api/auth/challenge", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge returned %d", rec.Code)
	}
	var ch struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decoding challenge: %v", err)
	}
	if ch.Challenge == "" {
		t.Fatal("challenge is empty")
	}

	sig, err := signAsOwner(s, ch.Challenge)
	if err != nil {
		t.Fatalf("signing challenge: %v", err)
	}

	r := anon(http.MethodGet, "/api/admin/drops", nil)
	r.Header.Set("Authorization", "Nostr "+ch.Challenge+":"+sig)
	if rec := do(t, s, r); rec.Code != http.StatusOK {
		t.Errorf("a signed challenge from a remote address returned %d, want 200", rec.Code)
	}
}

func TestLinksLifecycle(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]any{"label": "Site", "url": "https://example.com", "position": 1})
	rec := do(t, s, authed(http.MethodPost, "/api/admin/links", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("adding link returned %d: %s", rec.Code, rec.Body)
	}
	var link struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &link); err != nil {
		t.Fatalf("decoding link: %v", err)
	}

	rec = do(t, s, anon(http.MethodGet, "/api/profile", nil))
	if !strings.Contains(rec.Body.String(), "https://example.com") {
		t.Error("the link is missing from the public profile")
	}

	rec = do(t, s, authed(http.MethodDelete, "/api/admin/links/"+itoa(link.ID), nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("deleting link returned %d", rec.Code)
	}
}

func TestAddLinkRejectsJavascriptURL(t *testing.T) {
	s := newTestServer(t)

	body, _ := json.Marshal(map[string]any{"label": "bad", "url": "javascript:alert(1)"})
	if rec := do(t, s, authed(http.MethodPost, "/api/admin/links", body)); rec.Code != http.StatusBadRequest {
		t.Errorf("a javascript: URL returned %d, want 400", rec.Code)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// An instance with no IPFS endpoint is a normal instance; publishing must say
// so precisely rather than reporting a server fault.
func TestPublishWithoutIPFSConfigured(t *testing.T) {
	s := newTestServer(t)

	rec := do(t, s, authed(http.MethodPost, "/api/admin/publish", nil))
	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412 when no IPFS endpoint is set", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "DENLY_IPFS_API") {
		t.Error("the error does not tell the operator how to configure publishing")
	}
}

func TestPublishStatusOnFreshInstance(t *testing.T) {
	s := newTestServer(t)

	rec := do(t, s, authed(http.MethodGet, "/api/admin/publish", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var out struct {
		Configured bool `json:"configured"`
		Published  bool `json:"published"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding status: %v", err)
	}
	if out.Configured {
		t.Error("status claims IPFS is configured when it is not")
	}
	if out.Published {
		t.Error("status claims a publish happened on a fresh instance")
	}
}
