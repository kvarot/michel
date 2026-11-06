// Package audit keeps a tamper-evident, hash-chained log of what Michel does.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/store"
	"github.com/oklog/ulid/v2"
)

// Event is one audit entry. ID, TS, Seq, PrevHash and Hash are filled by Record.
type Event struct {
	ID, TS, Actor, Action, Target, Result, CorrelationID string
	Evidence                                             map[string]any
	PrevHash, Hash                                       string
	// Seq is the place of the event in the chain, from 1.
	Seq int64 `json:",omitempty"`
	// HMAC is the seal of the event: HMAC-SHA256 of Hash with the key of
	// the secret store (hex), "" when the log is not sealed.
	HMAC string `json:",omitempty"`
}

// Logger appends events to the chain. It is safe for concurrent use.
type Logger struct {
	s       *store.Store
	now     func() time.Time
	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
	commit  func(*sql.Tx) error // tests replace it to simulate a failed commit
	key     []byte              // the seal key; nil writes no seal
}

// SetKey makes the logger seal every event it writes with key (see Event.HMAC).
func (l *Logger) SetKey(key []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.key = append([]byte(nil), key...)
}

// seal is the HMAC of an event's hash with key, hex.
func seal(key []byte, hash string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(hash))
	return hex.EncodeToString(m.Sum(nil))
}

// keySize is the size of a seal key.
const keySize = 32

// LoadKey reads the seal key from the secret store; ok is false when there
// is none yet.
func LoadKey(s secret.Store) (key []byte, ok bool, err error) {
	v, err := s.Get(secret.ReservedAuditKey)
	if errors.Is(err, secret.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("cannot read the key of the audit seals: %w", err)
	}
	key, err = hex.DecodeString(strings.TrimSpace(string(v)))
	if err != nil || len(key) != keySize {
		return nil, false, errors.New("the key of the audit seals is damaged")
	}
	return key, true, nil
}

// LoadOrCreateKey reads the seal key, creating 32 random bytes the first
// time. Making the key starts the protection: in the same transaction of st,
// the sealed anchor marks the next event as the first that must be sealed.
// The transaction holds the write lock of the database, so of several
// processes starting at once on a fresh data folder one makes the key and
// the others read it; the secret is also created only when none is stored
// (secret.Creator), and read back, so every process seals with the stored key.
func LoadOrCreateKey(ctx context.Context, s secret.Store, st *store.Store) ([]byte, error) {
	key, ok, err := LoadKey(s)
	if err != nil || ok {
		return key, err
	}
	tx, err := st.DB().BeginTx(ctx, nil) // immediate: one maker at a time
	if err != nil {
		return nil, fmt.Errorf("cannot start the seals of the audit log: %w", err)
	}
	defer tx.Rollback()
	if key, ok, err := LoadKey(s); err != nil || ok {
		return key, err
	}
	key = make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("cannot create the key of the audit seals: %w", err)
	}
	if err := startSealing(ctx, tx, key); err != nil {
		return nil, err
	}
	value := []byte(hex.EncodeToString(key))
	if c, ok := s.(secret.Creator); ok {
		err = c.Create(secret.ReservedAuditKey, value)
		if errors.Is(err, secret.ErrExists) {
			// Made meanwhile by a process outside the lock: use it, and
			// leave the anchor to its maker.
			tx.Rollback()
			return readBackKey(s)
		}
	} else {
		err = s.Set(secret.ReservedAuditKey, value)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot save the key of the audit seals: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot start the seals of the audit log: %w", err)
	}
	return readBackKey(s)
}

// readBackKey reads the key that is stored, after a write.
func readBackKey(s secret.Store) ([]byte, error) {
	key, ok, err := LoadKey(s)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("the key of the audit seals was saved but cannot be read back")
	}
	return key, nil
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
	prev, last := "", int64(0)
	err = tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_event ORDER BY seq DESC LIMIT 1`).Scan(&last, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Event{}, fmt.Errorf("cannot read the audit chain: %w", err)
	}
	e.PrevHash, e.Seq = prev, last+1
	canon, err := canonical(e, evJSON)
	if err != nil {
		return Event{}, err
	}
	e.Hash = chainHash(prev, canon)
	if l.key != nil {
		e.HMAC = seal(l.key, e.Hash)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_event
		(seq, id, ts, actor, action, target, result, correlation_id, evidence, prev_hash, hash, hmac)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Seq, e.ID, e.TS, e.Actor, e.Action, e.Target, e.Result, e.CorrelationID, string(evJSON), e.PrevHash, e.Hash, e.HMAC); err != nil {
		return Event{}, fmt.Errorf("cannot write to the audit log: %w", err)
	}
	// The count of the head anchor is kept in the database and moves with the
	// event, in the same transaction: the table is never counted.
	var count int
	if err := tx.QueryRowContext(ctx, `UPDATE audit_anchor SET events = events + 1 WHERE id = 1 RETURNING events`).Scan(&count); err != nil {
		return Event{}, fmt.Errorf("cannot count the audit chain: %w", err)
	}
	anchored := true
	if l.key != nil {
		if anchored, err = advanceSealedAnchor(ctx, tx, l.key, e); err != nil {
			return Event{}, err
		}
	}
	if err := l.commit(tx); err != nil {
		return Event{}, fmt.Errorf("cannot write to the audit log: %w", err)
	}
	if !anchored {
		slog.Warn("audit: the sealed anchor is missing or does not match the chain (events removed or changed?); audit verify reports it")
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
