package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/fomothy/denly.xyz/internal/deadhand"
	"github.com/fomothy/denly.xyz/internal/nostr"
)

// Deadhand's HTTP surface.
//
// Everything that creates, arms, checks in, drills, or fires is an owner
// action and sits behind the admin authenticator. The only public routes are
// the liveness notice for a fired switch and the payload fetch — both of which
// hand out ciphertext that the server itself cannot read.

type switchResponse struct {
	deadhand.Switch
	Deadline   *time.Time `json:"deadline,omitempty"`
	NextDueAt  *time.Time `json:"next_checkin_due_at,omitempty"`
	ArweaveURL string     `json:"arweave_url,omitempty"`
	GatewayURL string     `json:"ipfs_url,omitempty"`
}

func describeSwitch(sw deadhand.Switch) switchResponse {
	out := switchResponse{Switch: sw}
	if d := sw.Deadline(); !d.IsZero() {
		out.Deadline = &d
	}
	if due := sw.DueAt(); !due.IsZero() {
		out.NextDueAt = &due
	}
	if sw.ReleaseTx != "" {
		out.ArweaveURL = deadhand.ArweaveURL(sw.ReleaseTx)
	}
	if sw.ReleaseCID != "" {
		out.GatewayURL = "https://ipfs.io/ipfs/" + sw.ReleaseCID
	}
	return out
}

func (s *Server) handleListSwitches(w http.ResponseWriter, r *http.Request) {
	switches, err := s.switches.List(r.Context())
	if err != nil {
		s.log.Error("listing switches", "error", err)
		s.writeError(w, http.StatusInternalServerError, "could not list switches")
		return
	}
	out := make([]switchResponse, 0, len(switches))
	for _, sw := range switches {
		out = append(out, describeSwitch(sw))
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetSwitch(w http.ResponseWriter, r *http.Request) {
	sw, err := s.switches.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, deadhand.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no such switch")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read the switch")
		return
	}

	events, err := s.switches.Events(r.Context(), sw.ID, 50)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read the switch history")
		return
	}
	contacts, err := s.switches.Contacts(r.Context(), sw.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read the switch contacts")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"switch":   describeSwitch(sw),
		"contacts": contacts,
		"events":   events,
	})
}

// createSwitchRequest is the owner's instruction to seal a payload.
//
// The plaintext arrives here and is encrypted before it is stored — this is
// the one place the server briefly holds it. That is unavoidable when the
// owner drives it over HTTP from the same machine; a browser-side client would
// seal it first and post the sealed payload instead, which the API also
// accepts via `sealed`.
type createSwitchRequest struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Files   []struct {
		Filename    string `json:"filename"`
		ContentType string `json:"content_type"`
		Data        []byte `json:"data"`
	} `json:"files"`

	Recipients []string `json:"recipients"`
	Guardians  []string `json:"guardians"`
	Threshold  int      `json:"threshold"`

	IntervalSeconds int64 `json:"checkin_interval_seconds"`
	GraceSeconds    int64 `json:"grace_period_seconds"`
	PublicNotice    bool  `json:"public_notice"`

	Contacts []struct {
		Kind    string `json:"kind"`
		Address string `json:"address"`
		Trusted bool   `json:"trusted"`
	} `json:"contacts"`

	// Sealed, when present, is a payload the client encrypted itself. It takes
	// precedence, and is the path that keeps plaintext off the server entirely.
	Sealed *deadhand.SealedPayload `json:"sealed,omitempty"`
}

func (s *Server) handleCreateSwitch(w http.ResponseWriter, r *http.Request) {
	if s.ownerSecret == nil {
		s.writeError(w, http.StatusConflict,
			"this instance has no identity; run `denly init` before creating a switch")
		return
	}

	var body createSwitchRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, deadhand.MaxPayloadBytes+(1<<20))).Decode(&body); err != nil {
		s.writeError(w, http.StatusBadRequest, "could not read the switch definition")
		return
	}

	sealed, err := s.sealFromRequest(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	opts := deadhand.CreateOptions{
		Name:         body.Name,
		Payload:      sealed,
		Interval:     time.Duration(body.IntervalSeconds) * time.Second,
		Grace:        time.Duration(body.GraceSeconds) * time.Second,
		PublicNotice: body.PublicNotice,
	}
	for _, c := range body.Contacts {
		opts.Contacts = append(opts.Contacts, deadhand.Contact{
			Kind: c.Kind, Address: c.Address, Trusted: c.Trusted,
		})
	}

	sw, err := s.switches.Create(r.Context(), opts)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("switch created", "switch", sw.ID, "name", sw.Name,
		"recipients", len(sw.Recipients), "threshold", sw.Threshold)
	s.writeJSON(w, http.StatusCreated, describeSwitch(sw))
}

// sealFromRequest turns a request into a sealed payload, preferring one the
// client sealed itself.
func (s *Server) sealFromRequest(body createSwitchRequest) (deadhand.SealedPayload, error) {
	if body.Sealed != nil {
		return *body.Sealed, nil
	}

	recipients, err := parsePubKeys(body.Recipients)
	if err != nil {
		return deadhand.SealedPayload{}, err
	}
	guardians, err := parsePubKeys(body.Guardians)
	if err != nil {
		return deadhand.SealedPayload{}, err
	}

	content := deadhand.Content{Message: body.Message}
	for _, f := range body.Files {
		content.Files = append(content.Files, deadhand.File{
			Filename: f.Filename, ContentType: f.ContentType, Data: f.Data,
		})
	}

	return deadhand.Seal(content, s.ownerSecret, deadhand.SealOptions{
		Recipients: recipients,
		Guardians:  guardians,
		Threshold:  body.Threshold,
	})
}

func parsePubKeys(in []string) ([]nostr.PublicKey, error) {
	out := make([]nostr.PublicKey, 0, len(in))
	for _, s := range in {
		pk, err := nostr.DecodePublicKey(s)
		if err != nil {
			return nil, err
		}
		out = append(out, pk)
	}
	return out, nil
}

func (s *Server) handleArmSwitch(w http.ResponseWriter, r *http.Request) {
	s.switchAction(w, r, func(id string) (deadhand.Switch, error) {
		return s.switches.Arm(r.Context(), id)
	})
}

func (s *Server) handleDisarmSwitch(w http.ResponseWriter, r *http.Request) {
	s.switchAction(w, r, func(id string) (deadhand.Switch, error) {
		return s.switches.Disarm(r.Context(), id)
	})
}

func (s *Server) handleCheckIn(w http.ResponseWriter, r *http.Request) {
	s.switchAction(w, r, func(id string) (deadhand.Switch, error) {
		return s.switches.CheckIn(r.Context(), id, "http")
	})
}

func (s *Server) switchAction(w http.ResponseWriter, r *http.Request, fn func(string) (deadhand.Switch, error)) {
	sw, err := fn(r.PathValue("id"))
	switch {
	case errors.Is(err, deadhand.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "no such switch")
	case errors.Is(err, deadhand.ErrAlreadyFired):
		s.writeError(w, http.StatusConflict, "this switch has already fired")
	case err != nil:
		s.writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.writeJSON(w, http.StatusOK, describeSwitch(sw))
	}
}

// handleDrill runs a test fire: contacts are notified, nothing is released.
func (s *Server) handleDrill(w http.ResponseWriter, r *http.Request) {
	result, err := s.engine.Drill(r.Context(), r.PathValue("id"))
	if errors.Is(err, deadhand.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no such switch")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

// handleFireNow releases a switch immediately.
//
// Deliberately requires an explicit confirmation parameter. This is the one
// irreversible action in denly: it publishes someone's private papers, and a
// mis-click or a stray curl should not be enough.
func (s *Server) handleFireNow(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("confirm") != "yes" {
		s.writeError(w, http.StatusPreconditionRequired,
			"firing is irreversible; repeat the request with ?confirm=yes")
		return
	}

	id := r.PathValue("id")
	if err := s.engine.Fire(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, deadhand.ErrNotFound):
			s.writeError(w, http.StatusNotFound, "no such switch")
		case errors.Is(err, deadhand.ErrAlreadyFired):
			s.writeError(w, http.StatusConflict, "this switch has already fired")
		default:
			s.writeError(w, http.StatusBadGateway, err.Error())
		}
		return
	}

	sw, err := s.switches.Get(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fired, but could not read the result")
		return
	}
	s.writeJSON(w, http.StatusOK, describeSwitch(sw))
}

func (s *Server) handleDeleteSwitch(w http.ResponseWriter, r *http.Request) {
	if err := s.switches.Delete(r.Context(), r.PathValue("id")); errors.Is(err, deadhand.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no such switch")
		return
	} else if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not delete the switch")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSwitchPayload hands out the sealed payload.
//
// Public, and safe to be: the bytes are encrypted to the recipients' keys. The
// server cannot read them, so gating access here would protect nothing while
// preventing a recipient from collecting what was left for them.
//
// Only released once the switch has fired. Before that, handing it out would
// let anyone who guessed an ID hold the ciphertext and wait for a key.
func (s *Server) handleSwitchPayload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	sw, err := s.switches.Get(r.Context(), id)
	if errors.Is(err, deadhand.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "no such switch")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read the switch")
		return
	}
	if sw.State != deadhand.StateFired {
		s.writeError(w, http.StatusForbidden, "this switch has not fired")
		return
	}

	payload, err := s.switches.Payload(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read the payload")
		return
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not encode the payload")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(raw); err != nil {
		s.log.Error("writing switch payload", "error", err)
	}
}

// handleSwitchNotice is the optional public "this switch fired" record.
//
// It carries no content — only the fact, the time, and where the ciphertext
// went. Switches without public_notice are invisible here, because some
// switches should fire without announcing themselves.
func (s *Server) handleSwitchNotice(w http.ResponseWriter, r *http.Request) {
	switches, err := s.switches.List(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read switches")
		return
	}

	type notice struct {
		Name       string     `json:"name"`
		FiredAt    *time.Time `json:"fired_at"`
		CID        string     `json:"ipfs_cid,omitempty"`
		ArweaveURL string     `json:"arweave_url,omitempty"`
	}

	out := make([]notice, 0)
	for _, sw := range switches {
		if sw.State != deadhand.StateFired || !sw.PublicNotice {
			continue
		}
		out = append(out, notice{
			Name:       sw.Name,
			FiredAt:    sw.FiredAt,
			CID:        sw.ReleaseCID,
			ArweaveURL: deadhand.ArweaveURL(sw.ReleaseTx),
		})
	}
	s.writeJSON(w, http.StatusOK, out)
}
