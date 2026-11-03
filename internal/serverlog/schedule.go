package serverlog

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/kvarot/michel/internal/target"
)

const (
	// maxParallel is how many servers are read at the same time.
	maxParallel = 4
	// notReadingFailures and notReadingAfter: Michel says it no longer reads
	// after this many failures in a row and this long without a good read
	// (spec § 5.4).
	notReadingFailures = 3
	notReadingAfter    = 30 * time.Minute
	// purgeEvery is how often the retention is applied.
	purgeEvery = 6 * time.Hour
)

// Scheduler reads the due servers until ctx ends: now, then every `every`. A
// server is due when its interval (Settings.Interval) has passed since its last
// try; a failed read is tried again at the next interval, not sooner. At most
// maxParallel servers are read at once, a server never twice at the same time,
// and a slow server delays no other one. The retention of the log data is
// applied from here too, at the start and every few hours.
//
// A server without an active source is never contacted, and neither is one
// turned off or read by hand only (ManualInterval).
func Scheduler(ctx context.Context, d Deps, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	s := newScheduler(d)
	var wg sync.WaitGroup
	defer wg.Wait()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		s.maintain(ctx)
		// Each round runs on its own: a slow server holds its own round only.
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.tick(ctx)
		}()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// scheduler is the memory of Scheduler: who runs, when each server was last
// tried, and the incidents of servers that cannot be read.
type scheduler struct {
	d    Deps
	pass func(context.Context, Deps, string) (PassResult, error)
	sem  chan struct{}

	mu        sync.Mutex
	inflight  map[string]bool
	lastTry   map[string]time.Time
	lastGood  map[string]time.Time
	incidents map[string]*incident
	lastPurge time.Time
}

// incident is a server that cannot be read: failures in a row since first,
// told once (alerted) when the two conditions of spec § 5.4 hold. carrier says
// that the alert about the SSH agent was sent for it; the others that fail for
// the same cause join without a new alert.
type incident struct {
	failures int
	first    time.Time
	reason   string
	alerted  bool
	carrier  bool
}

func newScheduler(d Deps) *scheduler {
	return &scheduler{
		d: d, pass: Pass, sem: make(chan struct{}, maxParallel),
		inflight: map[string]bool{}, lastTry: map[string]time.Time{}, lastGood: map[string]time.Time{}, incidents: map[string]*incident{},
	}
}

// maintain applies the retention: at the start and every purgeEvery. The
// purge is audited by PurgeAudited when it removes something.
func (s *scheduler) maintain(ctx context.Context) {
	now := s.d.now()
	s.mu.Lock()
	due := s.lastPurge.IsZero() || now.Sub(s.lastPurge) >= purgeEvery
	if due {
		s.lastPurge = now
	}
	s.mu.Unlock()
	if !due {
		return
	}
	if err := PurgeAudited(ctx, s.d.Repo, s.d.Audit, now); err != nil && ctx.Err() == nil {
		slog.Warn("serverlog: the retention of the log data failed", "err", err)
	}
}

type passOutcome struct {
	t   target.Target
	res PassResult
	err error
	at  time.Time
}

// tick reads the servers that are due and settles the outcome: it returns when
// they are all done.
func (s *scheduler) tick(ctx context.Context) {
	now := s.d.now()
	all, err := s.d.Targets.List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("serverlog: cannot list the servers to read", "err", err)
		}
		return
	}
	var due []target.Target
	for _, t := range all {
		if t.Active && s.claim(ctx, t, now) {
			due = append(due, t)
		}
	}
	outcomes := make([]passOutcome, len(due))
	var wg sync.WaitGroup
	for i, t := range due {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.release(t.ID)
			select {
			case s.sem <- struct{}{}:
				defer func() { <-s.sem }()
			case <-ctx.Done():
				outcomes[i] = passOutcome{t: t, err: ctx.Err()}
				return
			}
			res, err := s.pass(ctx, s.d, t.ID)
			outcomes[i] = passOutcome{t: t, res: res, err: err, at: s.d.now()}
		}()
	}
	wg.Wait()
	s.settle(ctx, outcomes)
}

// claim says whether t is to be read now, and marks it as running if so.
func (s *scheduler) claim(ctx context.Context, t target.Target, now time.Time) bool {
	st, err := s.d.Repo.Settings(ctx, t.ID)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("serverlog: cannot read the log settings", "target", t.ID, "err", err)
		}
		return false
	}
	if st.Interval == ManualInterval {
		return false
	}
	srcs, err := s.d.Repo.Sources(ctx, t.ID)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("serverlog: cannot read the log sources", "target", t.ID, "err", err)
		}
		return false
	}
	active := false
	for _, src := range srcs {
		active = active || src.Active
	}
	if !active {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[t.ID] {
		return false
	}
	if at, ok := s.lastTry[t.ID]; ok && now.Sub(at) < st.Interval {
		return false
	}
	s.inflight[t.ID] = true
	s.lastTry[t.ID] = now
	return true
}

func (s *scheduler) release(id string) {
	s.mu.Lock()
	delete(s.inflight, id)
	s.mu.Unlock()
}

// settle updates the incidents with the outcomes of one round and tells the
// new ones. A cause shared by several servers of the round (the SSH agent
// locked or absent) is one alert.
func (s *scheduler) settle(ctx context.Context, outcomes []passOutcome) {
	var declared []passOutcome
	for _, o := range outcomes {
		if ctx.Err() != nil || errors.Is(o.err, context.Canceled) {
			return
		}
		switch {
		case o.err == nil:
			s.mu.Lock()
			delete(s.incidents, o.t.ID)
			s.lastGood[o.t.ID] = o.at
			s.mu.Unlock()
		case errors.Is(o.err, ErrInactive), errors.Is(o.err, ErrPassRunning):
			// Not a failure of the reading itself.
		default:
			slog.Warn("serverlog: the log read of a server failed", "target", o.t.ID, "name", o.t.Name, "reason", o.res.Reason)
			if s.fail(ctx, o) {
				declared = append(declared, o)
			}
		}
	}
	s.tell(ctx, declared)
}

// fail counts a failure and says whether the incident has just reached the
// bar: 3 failures in a row and 30 minutes without a good read.
func (s *scheduler) fail(ctx context.Context, o passOutcome) bool {
	since := s.goodRead(ctx, o.t.ID)
	s.mu.Lock()
	defer s.mu.Unlock()
	inc := s.incidents[o.t.ID]
	if inc == nil {
		inc = &incident{first: o.at}
		s.incidents[o.t.ID] = inc
	}
	inc.failures++
	inc.reason = o.res.Reason
	if since.IsZero() || since.After(inc.first) {
		since = inc.first
	}
	if inc.alerted || inc.failures < notReadingFailures || o.at.Sub(since) < notReadingAfter {
		return false
	}
	inc.alerted = true
	return true
}

// goodRead is when the server was last read well: this process knows it, else
// the dates of the saved positions do, else nothing is known (zero).
func (s *scheduler) goodRead(ctx context.Context, id string) time.Time {
	s.mu.Lock()
	at, ok := s.lastGood[id]
	s.mu.Unlock()
	if ok {
		return at
	}
	at, err := s.d.Repo.LastRead(ctx, id)
	if err != nil {
		return time.Time{}
	}
	return at
}

// tell notes the gap of each new incident (the digest carries it) and sends the
// alert of the servers whose route is immediate: prod ones. Servers failing
// for the SSH agent are one alert; if one is already sent and still stands,
// the newcomers join it without another one.
func (s *scheduler) tell(ctx context.Context, declared []passOutcome) {
	if len(declared) == 0 {
		return
	}
	for _, o := range declared {
		s.noteGap(ctx, o)
	}
	sort.SliceStable(declared, func(i, j int) bool { return declared[i].t.Name < declared[j].t.Name })
	var agent []passOutcome
	for _, o := range declared {
		if o.t.Env != target.EnvProd {
			continue
		}
		if o.res.Reason == ReasonNoAgent {
			agent = append(agent, o)
			continue
		}
		s.send(ctx, []passOutcome{o}, o.res.Reason)
	}
	if len(agent) == 0 {
		return
	}
	if s.agentAlertStands() {
		return
	}
	s.send(ctx, agent, ReasonNoAgent)
}

// agentAlertStands says whether an alert about the SSH agent was sent and its
// servers still cannot be read.
func (s *scheduler) agentAlertStands() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inc := range s.incidents {
		if inc.carrier && inc.reason == ReasonNoAgent {
			return true
		}
	}
	return false
}

func (s *scheduler) send(ctx context.Context, group []passOutcome, reason string) {
	if s.d.Alert == nil {
		return
	}
	items := make([]AlertItem, len(group))
	s.mu.Lock()
	for i, o := range group {
		items[i] = AlertItem{Type: o.t.Name}
		if inc := s.incidents[o.t.ID]; inc != nil {
			inc.carrier = true
		}
	}
	s.mu.Unlock()
	s.d.Alert(ctx, AlertInput{Target: group[0].t, Kind: AlertNotReading, Items: items, Reason: reason})
}

// noteGap puts the silence in the notes of each source that has a position:
// from its last read to now. The read that ends the incident extends the note.
func (s *scheduler) noteGap(ctx context.Context, o passOutcome) {
	srcs, err := s.d.Repo.Sources(ctx, o.t.ID)
	if err != nil {
		return
	}
	for _, src := range srcs {
		if !src.Active {
			continue
		}
		cs, err := s.d.Repo.Cursors(ctx, src.ID)
		if err != nil {
			continue
		}
		if from := latestRead(cs); !from.IsZero() {
			_ = s.d.Repo.RecordState(ctx, Note{TargetID: o.t.ID, SourceID: src.ID, Kind: NoteGap, From: from, To: o.at})
		}
	}
}
