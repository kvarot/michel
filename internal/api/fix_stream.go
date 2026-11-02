package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
)

// heartbeat is the pause between two comment lines of an idle stream, so
// that no proxy or browser closes it.
const heartbeat = 15 * time.Second

// streamPoll is how often a stream reads the store when the fix service
// gives no interval: the proposals and messages of michel mcp (another
// process) only reach serve through the store.
const streamPoll = time.Second

// fixEvents is GET /fix/{attempt}/events: a text/event-stream of the
// attempt. It sends, as they appear in the store, "message" (a line of the
// conversation), "activity" (a tool the agent used, one line), "state"
// (state and cause) and "proposal" (the current proposal, in full). The
// first events are the conversation so far, the current proposal and the
// current state. Every text is masked as in the other answers. The stream
// ends when the client leaves or the handler closes.
func (s *server) fixEvents(w http.ResponseWriter, r *http.Request) {
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	a, ok := s.attempt(w, r, lang)
	if !ok {
		return
	}
	rc := http.NewResponseController(w)
	// A stream outlives the server's write timeout.
	if err := rc.SetWriteDeadline(time.Time{}); err != nil && err != http.ErrNotSupported {
		s.internal(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	st := &stream{w: w, flush: func() error { return rc.Flush() }, m: s.displayMasker(a.ID), seen: map[string]bool{}, lang: lang}
	if _, err := io.WriteString(w, "retry: 3000\n\n"); err != nil {
		return
	}
	poll := streamPoll
	if s.deps.Fix != nil && s.deps.Fix.PollInterval > 0 {
		poll = s.deps.Fix.PollInterval
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	beat := time.NewTicker(heartbeat)
	defer beat.Stop()
	ctx := r.Context()
	for {
		if err := st.step(ctx, s, a.ID); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-s.bg.Done():
			return
		case <-beat.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil || st.flush() != nil {
				return
			}
		case <-ticker.C:
		}
	}
}

// stream is what one event stream already sent.
type stream struct {
	w     io.Writer
	flush func() error
	m     *mask.Masker
	seen  map[string]bool
	state StateView
	sent  bool
	prop  string // id and hash of the proposal sent
	lang  i18n.Lang
}

// event writes one event; data is JSON (one line).
func (st *stream) event(name, id string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if id != "" {
		if _, err := fmt.Fprintf(st.w, "id: %s\n", id); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(st.w, "event: %s\ndata: %s\n\n", name, b)
	return err
}

// step sends what changed in the store since the last step: the new lines
// of the conversation, the proposal when it changed, then the state when it
// changed.
func (st *stream) step(ctx context.Context, s *server, id string) error {
	repo := fix.NewRepo(s.deps.Store)
	a, err := repo.GetAttempt(ctx, id)
	if err != nil {
		return err
	}
	wrote := false
	msgs, err := repo.ListMessages(ctx, id)
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		if st.seen[msg.ID] {
			continue
		}
		st.seen[msg.ID] = true
		name := "message"
		if msg.Role == fix.RoleTool {
			name = "activity"
		}
		if err := st.event(name, msg.ID, messageView(st.m, msg)); err != nil {
			return err
		}
		wrote = true
	}
	prop, ok, err := repo.CurrentProposal(ctx, id)
	if err != nil {
		return err
	}
	if ok && prop.ID+" "+prop.Hash != st.prop {
		if err := st.event("proposal", "", proposalView(st.m, prop, true)); err != nil {
			return err
		}
		st.prop, wrote = prop.ID+" "+prop.Hash, true
	}
	// The state last: when it says proposed, the proposal is already sent.
	if v := stateView(st.m, a, st.lang); !st.sent || v != st.state {
		if err := st.event("state", "", v); err != nil {
			return err
		}
		st.state, st.sent, wrote = v, true, true
	}
	if wrote {
		return st.flush()
	}
	return nil
}
