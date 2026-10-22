// Package audit keeps a tamper-evident, hash-chained log of what Michel does.
package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// Event is one audit entry. ID, TS, PrevHash and Hash are filled by Record.
type Event struct {
	ID, TS, Actor, Action, Target, Result, CorrelationID string
	Evidence                                             map[string]any
	PrevHash, Hash                                       string
}

// Logger appends events to the chain. It is safe for concurrent use.
type Logger struct {
	s       *store.Store
	now     func() time.Time
	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewLogger builds a Logger writing to s. now gives the event time.
func NewLogger(s *store.Store, now func() time.Time) *Logger {
	return &Logger{s: s, now: now, entropy: ulid.Monotonic(rand.Reader, 0)}
}

// canonical returns the JSON text of the hashed fields. Go sorts map keys,
// so the output is stable. evidence must already be JSON text.
func canonical(e Event, evidence json.RawMessage) ([]byte, error) {
	return json.Marshal(map[string]any{
		"id": e.ID, "ts": e.TS, "actor": e.Actor, "action": e.Action, "target": e.Target,
		"result": e.Result, "correlation_id": e.CorrelationID, "evidence": evidence,
	})
}

func chainHash(prev string, canon []byte) string {
	sum := sha256.Sum256([]byte(prev + "\n" + string(canon)))
	return hex.EncodeToString(sum[:])
}

// Record appends e to the chain and returns it completed.
func (l *Logger) Record(ctx context.Context, e Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	t := l.now().UTC()
	id, err := ulid.New(ulid.Timestamp(t), l.entropy)
	if err != nil {
		return Event{}, fmt.Errorf("cannot create an audit event id: %w", err)
	}
	e.ID = id.String()
	e.TS = t.Format(time.RFC3339Nano)

	ev := e.Evidence
	if ev == nil {
		ev = map[string]any{}
	}
	evJSON, err := json.Marshal(ev)
	if err != nil {
		return Event{}, fmt.Errorf("cannot encode the audit evidence: %w", err)
	}
	canon, err := canonical(e, evJSON)
	if err != nil {
		return Event{}, err
	}

	db := l.s.DB()
	prev := ""
	err = db.QueryRowContext(ctx, `SELECT hash FROM audit_event ORDER BY rowid DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Event{}, fmt.Errorf("cannot read the audit chain: %w", err)
	}
	e.PrevHash = prev
	e.Hash = chainHash(prev, canon)
	_, err = db.ExecContext(ctx, `INSERT INTO audit_event
		(id, ts, actor, action, target, result, correlation_id, evidence, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.TS, e.Actor, e.Action, e.Target, e.Result, e.CorrelationID, string(evJSON), e.PrevHash, e.Hash)
	if err != nil {
		return Event{}, fmt.Errorf("cannot write to the audit log: %w", err)
	}
	return e, nil
}

type egressSink struct{ l *Logger }

// EgressSink returns a sink that records every egress attempt as an event.
func (l *Logger) EgressSink() egress.Sink { return egressSink{l} }

// Record never panics and never blocks the caller on a database error.
func (s egressSink) Record(a egress.Attempt) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("audit: cannot record egress attempt", "err", fmt.Sprint(r))
		}
	}()
	result := "denied"
	if a.Allowed {
		result = "allowed"
	}
	_, err := s.l.Record(context.Background(), Event{
		Actor: "egress", Action: "egress.attempt", Target: a.Host, Result: result,
		Evidence: map[string]any{"purpose": a.Purpose, "reason": a.Reason},
	})
	if err != nil {
		slog.Error("audit: cannot record egress attempt", "err", err)
	}
}
