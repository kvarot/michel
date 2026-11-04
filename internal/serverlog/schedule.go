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
	first := true
	for {
		s.maintain(ctx)
		// Each round runs on its own: a slow server holds its own round only.
		wg.Add(1)
		announce := first && d.FirstRound != nil
		first = false
		go func() {
			defer wg.Done()
			s.tick(ctx)
			if announce {
				d.FirstRound()
			}
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

	// partial: the last pass reached the server and read some sources, so the
	// incident is told source by source. sources are the streaks of the sources
	// failing in the last pass (by id), keyed out as soon as one does not fail;
	// told the sources already told in this incident; named the sources past the
	// bar in the last pass, newly those of them not told yet.
	partial bool
	sources map[string]*streak
	told    map[string]bool
	named   []FailedSource
	newly   []string
}

// streak counts the passes in a row in which one source failed.
type streak struct {
	failures int
	first    time.Time
}

// schedulerPass is the read of one server; replaced in tests.
var schedulerPass = Pass

func newScheduler(d Deps) *scheduler {
	return &scheduler{
		d: d, pass: schedulerPass, sem: make(chan struct{}, maxParallel),
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
	eligible := make(map[string]bool, len(all))
	for _, t := range all {
		st, ok, err := s.eligible(ctx, t)
		if err != nil {
			// Not known: its incident stays, and it is not read this round.
			if ctx.Err() == nil {
				slog.Warn("serverlog: cannot read the log settings or sources", "target", t.ID, "err", err)
			}
			eligible[t.ID] = true
			continue
		}
		if ok {
			eligible[t.ID] = true
			if s.claim(t, st, now) {
				due = append(due, t)
			}
		}
	}
	s.dropIncidents(eligible)
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

// eligible says whether the scheduler reads t at all: a server turned on, not
// read by hand only, with an active source.
func (s *scheduler) eligible(ctx context.Context, t target.Target) (Settings, bool, error) {
	if !t.Active {
		return Settings{}, false, nil
	}
	st, err := s.d.Repo.Settings(ctx, t.ID)
	if err != nil {
		return Settings{}, false, err
	}
	if st.Interval == ManualInterval {
		return st, false, nil
	}
	srcs, err := s.d.Repo.Sources(ctx, t.ID)
	if err != nil {
		return Settings{}, false, err
	}
	for _, src := range srcs {
		if src.Active {
			return st, true, nil
		}
	}
	return st, false, nil
}

// dropIncidents forgets the incidents of servers no longer read: they will
// never get an outcome, and must not stand for anyone else.
func (s *scheduler) dropIncidents(eligible map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.incidents {
		if !eligible[id] {
			delete(s.incidents, id)
		}
	}
}

// claim says whether t, with its settings st, is to be read now, and marks it as
// running if so.
func (s *scheduler) claim(t target.Target, st Settings, now time.Time) bool {
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
// locked or absent) is one alert. The gap of an incident past the bar is noted
// at each failure, so it lasts as long as the incident and a note that could
// not be written is tried again. A non-prod incident is told by that note only,
// so it counts as told once the note is written.
func (s *scheduler) settle(ctx context.Context, outcomes []passOutcome) {
	if ctx.Err() != nil {
		return
	}
	s.clearAgentIncidents(outcomes)
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
			reached, untold := s.fail(ctx, o)
			if !reached {
				continue
			}
			noted := s.noteGap(ctx, o)
			switch {
			case !untold:
			case o.t.Env == target.EnvProd:
				declared = append(declared, o)
			case noted:
				s.markTold(o.t.ID)
			}
		}
	}
	s.tell(ctx, declared)
}

// clearAgentIncidents ends the incidents about the SSH agent as soon as a server
// of the round got past it (a good read, or a failure for another reason): the
// agent is shared, so it is back for all, whenever each server is next read. A
// server that still fails for the agent in this round keeps its incident.
func (s *scheduler) clearAgentIncidents(outcomes []passOutcome) {
	past := false
	still := map[string]bool{}
	for _, o := range outcomes {
		switch {
		case errors.Is(o.err, context.Canceled), errors.Is(o.err, ErrInactive), errors.Is(o.err, ErrPassRunning):
		case o.err != nil && o.res.Reason == ReasonNoAgent:
			still[o.t.ID] = true
		default:
			past = true
		}
	}
	if !past {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, inc := range s.incidents {
		if inc.reason == ReasonNoAgent && !still[id] {
			delete(s.incidents, id)
		}
	}
}

// markTold says that the incident of a server was told.
func (s *scheduler) markTold(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inc := s.incidents[id]; inc != nil {
		if inc.partial {
			for _, src := range inc.newly {
				inc.told[src] = true
			}
			return
		}
		inc.alerted = true
	}
}

// fail counts a failure and says whether the incident is past the bar (3
// failures in a row and 30 minutes without a good read), and if so whether it
// still has to be told. A prod incident counts as told from here: its alert goes
// at once, whatever becomes of the note.
func (s *scheduler) fail(ctx context.Context, o passOutcome) (reached, untold bool) {
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
	// The server answered and some of its sources were opened: each source that
	// fails has its own bar, and is told once per incident.
	if inc.partial = o.res.Read > 0 && len(o.res.Failed) > 0; inc.partial {
		return s.failSources(inc, o, o.t.Env == target.EnvProd)
	}
	inc.sources, inc.named, inc.newly = nil, nil, nil
	if since.IsZero() || since.After(inc.first) {
		since = inc.first
	}
	if inc.failures < notReadingFailures || o.at.Sub(since) < notReadingAfter {
		return false, false
	}
	untold = !inc.alerted
	if o.t.Env == target.EnvProd {
		inc.alerted = true
	}
	return true, untold
}

// failSources updates the streaks of the sources that failed in a pass that
// reached the server (the caller holds the lock). A source that does not fail
// loses its streak. A source is past the bar after 3 failures in a row and 30
// minutes since the first of them; it is told once per incident, and a source
// newly past the bar is a new thing to tell, whatever was told before. A prod
// incident counts as told from here, as in fail.
func (s *scheduler) failSources(inc *incident, o passOutcome, prod bool) (reached, untold bool) {
	if inc.told == nil {
		inc.told = map[string]bool{}
	}
	now := make(map[string]*streak, len(o.res.Failed))
	inc.named, inc.newly = nil, nil
	for _, f := range o.res.Failed {
		st := inc.sources[f.ID]
		if st == nil {
			st = &streak{first: o.at}
		}
		st.failures++
		now[f.ID] = st
		if st.failures >= notReadingFailures && o.at.Sub(st.first) >= notReadingAfter {
			inc.named = append(inc.named, f)
			if !inc.told[f.ID] {
				inc.newly = append(inc.newly, f.ID)
			}
		}
	}
	inc.sources = now
	if len(inc.named) == 0 {
		return false, false
	}
	untold = len(inc.newly) > 0
	if prod {
		for _, id := range inc.newly {
			inc.told[id] = true
		}
	}
	return true, untold
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

// tell sends the alert of the new incidents whose route is immediate: prod ones.
// Servers failing for the SSH agent are one alert; if one is already sent and
// still stands, the newcomers join it without another one.
func (s *scheduler) tell(ctx context.Context, declared []passOutcome) {
	if len(declared) == 0 {
		return
	}
	sort.SliceStable(declared, func(i, j int) bool { return declared[i].t.Name < declared[j].t.Name })
	var agent []passOutcome
	for _, o := range declared {
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
	var named []FailedSource
	s.mu.Lock()
	for i, o := range group {
		items[i] = AlertItem{Kind: AlertNotReading, Type: o.t.Name}
		if inc := s.incidents[o.t.ID]; inc != nil {
			inc.carrier = true
			if len(group) == 1 && inc.partial {
				named = append(named, inc.named...)
			}
		}
	}
	s.mu.Unlock()
	in := AlertInput{Target: group[0].t, Kind: AlertNotReading, Items: items, Reason: reason}
	if len(named) > 0 {
		in.Sources, in.Reason = namedSources(named)
	}
	s.d.Alert(ctx, in)
}

// namedSources says which sources a partial alert is about, and the cause they
// share (the general one if they differ).
func namedSources(named []FailedSource) ([]SourceRef, string) {
	refs := make([]SourceRef, 0, len(named))
	shared := named[0].Reason
	for _, f := range named {
		refs = append(refs, f.Ref)
		if f.Reason != shared {
			shared = ReasonError
		}
	}
	return refs, shared
}

// noteGap puts the silence in the notes of each source that is behind: from its
// last read, or from the first failure of the incident if it was never read, to
// now. A source read recently is not behind, even if another one fails the pass.
// The read that ends the incident extends the note. It says whether every note
// was written; what could not be is logged, without content.
func (s *scheduler) noteGap(ctx context.Context, o passOutcome) bool {
	warn := func(err error) {
		if ctx.Err() == nil {
			slog.Warn("serverlog: cannot note a gap in the reading", "target", o.t.ID, "err", err)
		}
	}
	st, err := s.d.Repo.Settings(ctx, o.t.ID)
	if err != nil {
		warn(err)
		return false
	}
	srcs, err := s.d.Repo.Sources(ctx, o.t.ID)
	if err != nil {
		warn(err)
		return false
	}
	first := o.at
	s.mu.Lock()
	if inc := s.incidents[o.t.ID]; inc != nil {
		first = inc.first
	}
	s.mu.Unlock()
	noted := true
	for _, src := range srcs {
		if !src.Active {
			continue
		}
		cs, err := s.d.Repo.Cursors(ctx, src.ID)
		if err != nil {
			warn(err)
			noted = false
			continue
		}
		from := latestRead(cs)
		switch {
		case from.IsZero():
			from = first
		case o.at.Sub(from) < gapAfter(st.Interval):
			continue
		}
		if err := s.d.Repo.RecordState(ctx, Note{TargetID: o.t.ID, SourceID: src.ID, Kind: NoteGap, From: from, To: o.at}); err != nil {
			warn(err)
			noted = false
		}
	}
	return noted
}
