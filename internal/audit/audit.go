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
	commit  func(*sql.Tx) error // tests replace it to simulate a failed commit
}

// NewLogger builds a Logger writing to s. now gives the event time.
func NewLogger(s *store.Store, now func() time.Time) *Logger {
	return &Logger{s: s, now: now, entropy: ulid.Monotonic(rand.Reader, 0),
		commit: func(tx *sql.Tx) error { return tx.Commit() }}
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

	tx, err := l.s.DB().BeginTx(ctx, nil) // immediate: read-then-insert is atomic across processes
	if err != nil {
		return Event{}, fmt.Errorf("cannot write to the audit log: %w", err)
	}
	defer tx.Rollback()
	prev := ""
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_event ORDER BY rowid DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Event{}, fmt.Errorf("cannot read the audit chain: %w", err)
	}
	e.PrevHash = prev
	canon, err := canonical(e, evJSON)
	if err != nil {
		return Event{}, err
	}
	e.Hash = chainHash(prev, canon)
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_event
		(id, ts, actor, action, target, result, correlation_id, evidence, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.TS, e.Actor, e.Action, e.Target, e.Result, e.CorrelationID, string(evJSON), e.PrevHash, e.Hash); err != nil {
		return Event{}, fmt.Errorf("cannot write to the audit log: %w", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_event`).Scan(&count); err != nil {
		return Event{}, fmt.Errorf("cannot count the audit chain: %w", err)
	}
	if err := l.commit(tx); err != nil {
		return Event{}, fmt.Errorf("cannot write to the audit log: %w", err)
	}
	// The head is written only once the event is durable, so it never points
	// past the chain. It is written under l.mu, so heads from this process
	// land in chain order. The database is the source of truth: a head that
	// cannot be written is a warning, never a failed Record.
	if err := writeHead(l.s.Path(), count, e.Hash); err != nil {
		slog.Warn("audit: cannot update the head anchor file; audit verify may report it as absent or stale",
			"path", HeadFile(l.s.Path()), "err", err)
	}
	return e, nil
}

type egressSink struct{ l *Logger }

// EgressSink returns a sink that records every egress attempt as an event.
func (l *Logger) EgressSink() egress.Sink { return egressSink{l} }

// Record never panics. It returns the write error so the gateway can refuse
// an allowed request that would otherwise leave no audit trace.
func (s egressSink) Record(a egress.Attempt) (err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("audit: cannot record egress attempt", "err", fmt.Sprint(r))
			err = fmt.Errorf("cannot record egress attempt: %v", r)
		}
	}()
	result := "denied"
	if a.Allowed {
		result = "allowed"
	}
	_, err = s.l.Record(context.Background(), Event{
		Actor: "egress", Action: "egress.attempt", Target: a.Host, Result: result,
		Evidence: map[string]any{"purpose": a.Purpose, "reason": a.Reason},
	})
	if err != nil {
		slog.Error("audit: cannot record egress attempt", "err", err)
	}
	return err
}
