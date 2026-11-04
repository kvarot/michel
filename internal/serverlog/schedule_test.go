package serverlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// schedEnv is a database with servers and a scheduler whose reads are faked: no
// network, no shell.
type schedEnv struct {
	t       *testing.T
	s       *store.Store
	repo    *Repo
	targets *target.Repo
	clock   *testClock
	alerts  *alertLog
	log     *audit.Logger
	deps    Deps
	n       int
}

func newSchedEnv(t *testing.T) *schedEnv {
	t.Helper()
	// The scheduler logs each failed read; the tests make plenty.
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	clock := &testClock{t: readNow}
	alerts := &alertLog{}
	log := audit.NewLogger(s, clock.Now)
	repo, targets := NewRepo(s), target.NewRepo(s)
	return &schedEnv{t: t, s: s, repo: repo, targets: targets, clock: clock, alerts: alerts, log: log,
		deps: Deps{Repo: repo, Targets: targets, Audit: log, Alert: alerts.add, Now: clock.Now}}
}

// server adds a server of environment e; withSource gives it an active source.
func (e *schedEnv) server(name string, env target.Env, withSource bool) (target.Target, Source) {
	e.t.Helper()
	e.n++
	tg, err := e.targets.Add(context.Background(), target.Target{Name: name, Host: fmt.Sprintf("192.0.2.%d", e.n), User: "deploy", Kind: target.KindVPS, Env: env, Classification: policy.ClassInternal})
	if err != nil {
		e.t.Fatal(err)
	}
	var src Source
	if withSource {
		if src, err = e.repo.AddSource(context.Background(), Source{TargetID: tg.ID, Path: "/var/log/demo/app.log", Format: FormatMonolog, Active: true}); err != nil {
			e.t.Fatal(err)
		}
	}
	return tg, src
}

func (e *schedEnv) interval(tg target.Target, d time.Duration) {
	e.t.Helper()
	st, err := e.repo.Settings(context.Background(), tg.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	st.Interval = d
	if err := e.repo.SaveSettings(context.Background(), st); err != nil {
		e.t.Fatal(err)
	}
}

// fakePass stands for Pass: it counts the calls and lets a test decide.
type fakePass struct {
	mu    sync.Mutex
	calls map[string]int
	fn    func(ctx context.Context, id string) (PassResult, error)
}

func (f *fakePass) run(ctx context.Context, _ Deps, id string) (PassResult, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[id]++
	f.mu.Unlock()
	if f.fn != nil {
		return f.fn(ctx, id)
	}
	return PassResult{}, nil
}

func (f *fakePass) count(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[id]
}

func failing(reason string) func(context.Context, string) (PassResult, error) {
	return func(context.Context, string) (PassResult, error) {
		return PassResult{Reason: reason}, errors.New("the read failed")
	}
}

func (e *schedEnv) scheduler(f *fakePass) *scheduler {
	s := newScheduler(e.deps)
	s.pass = f.run
	return s
}

func TestSchedulerRespectsInterval(t *testing.T) {
	e := newSchedEnv(t)
	fast, _ := e.server("srv-fast", target.EnvProd, true)
	slow, _ := e.server("srv-slow", target.EnvProd, true)
	e.interval(slow, time.Hour)
	f := &fakePass{}
	s := e.scheduler(f)
	ctx := context.Background()

	s.tick(ctx)
	if f.count(fast.ID) != 1 || f.count(slow.ID) != 1 {
		t.Fatalf("the first round reads everyone: %v", f.calls)
	}
	e.clock.Advance(4 * time.Minute)
	s.tick(ctx)
	if f.count(fast.ID) != 1 {
		t.Fatalf("read again after 4 minutes of a 5 minute interval: %v", f.calls)
	}
	e.clock.Advance(time.Minute)
	s.tick(ctx)
	if f.count(fast.ID) != 2 || f.count(slow.ID) != 1 {
		t.Fatalf("after 5 minutes: %v", f.calls)
	}
	e.clock.Advance(55 * time.Minute)
	s.tick(ctx)
	if f.count(slow.ID) != 2 {
		t.Fatalf("after an hour: %v", f.calls)
	}
}

func TestSchedulerManualIntervalNeverReads(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	e.interval(tg, ManualInterval)
	if st, err := e.repo.Settings(context.Background(), tg.ID); err != nil || st.Interval != ManualInterval {
		t.Fatalf("manual does not survive the database: %+v, %v", st.Interval, err)
	}
	f := &fakePass{}
	s := e.scheduler(f)
	for i := 0; i < 3; i++ {
		s.tick(context.Background())
		e.clock.Advance(48 * time.Hour)
	}
	if f.count(tg.ID) != 0 {
		t.Fatalf("a server read by hand was read %d times", f.count(tg.ID))
	}
	// Back to automatic: read at once.
	e.interval(tg, 5*time.Minute)
	s.tick(context.Background())
	if f.count(tg.ID) != 1 {
		t.Fatalf("calls = %v", f.calls)
	}
}

func TestIntervalOutOfBoundsIsRefused(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	st, _ := e.repo.Settings(context.Background(), tg.ID)
	for _, d := range []time.Duration{0, 30 * time.Second, 25 * time.Hour, -time.Hour} {
		st.Interval = d
		if err := e.repo.SaveSettings(context.Background(), st); !errors.Is(err, ErrInvalidSettings) {
			t.Errorf("interval %v: %v", d, err)
		}
	}
}

func TestNoSourceNoConnection(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	if err := pe.repo.UpdateSource(ctx, Source{ID: pe.src.ID, Path: pe.src.Path, Format: pe.src.Format, Active: false}); err != nil {
		t.Fatal(err)
	}
	s := newScheduler(pe.deps)
	s.tick(ctx)
	if n := pe.host.srv.Accepted(); n != 0 {
		t.Fatalf("a server without an active source was contacted %d times", n)
	}
	if err := pe.repo.DeleteSource(ctx, pe.src.ID); err != nil {
		t.Fatal(err)
	}
	pe.clock.Advance(time.Hour)
	s.tick(ctx)
	if n := pe.host.srv.Accepted(); n != 0 {
		t.Fatalf("a server without a source was contacted %d times", n)
	}
	// A direct call is just as quiet.
	if res, err := Pass(ctx, pe.deps, pe.tgt.ID); err != nil || !reflect.DeepEqual(res, PassResult{}) || pe.host.srv.Accepted() != 0 {
		t.Fatalf("Pass = %+v, %v, connections %d", res, err, pe.host.srv.Accepted())
	}
	// The control: with an active source the same scheduler does connect.
	if _, err := pe.repo.AddSource(ctx, Source{TargetID: pe.tgt.ID, Path: pe.src.Path, Format: FormatMonolog, Active: true}); err != nil {
		t.Fatal(err)
	}
	pe.clock.Advance(time.Hour)
	s.tick(ctx)
	if pe.host.srv.Accepted() == 0 {
		t.Fatal("the control did not connect")
	}
}

func TestInactiveTargetSkipped(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	tg := pe.tgt
	tg.Active = false
	if err := pe.targets.Update(ctx, tg); err != nil {
		t.Fatal(err)
	}
	s := newScheduler(pe.deps)
	s.tick(ctx)
	if n := pe.host.srv.Accepted(); n != 0 {
		t.Fatalf("a server turned off was contacted %d times", n)
	}
	tg.Active = true
	if err := pe.targets.Update(ctx, tg); err != nil {
		t.Fatal(err)
	}
	s.tick(ctx)
	if pe.host.srv.Accepted() == 0 {
		t.Fatal("the server turned back on is not read")
	}
}

func TestSameServerNeverTwiceAtOnce(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	entered, release := make(chan struct{}, 4), make(chan struct{})
	f := &fakePass{fn: func(context.Context, string) (PassResult, error) {
		entered <- struct{}{}
		<-release
		return PassResult{}, nil
	}}
	s := e.scheduler(f)
	done := make(chan struct{})
	go func() { s.tick(context.Background()); close(done) }()
	<-entered
	// The interval has passed while the read is still running.
	e.clock.Advance(time.Hour)
	s.tick(context.Background())
	if f.count(tg.ID) != 1 {
		t.Fatalf("a running server was started again: %d", f.count(tg.ID))
	}
	close(release)
	<-done
	// Once done it is read again.
	s.tick(context.Background())
	if f.count(tg.ID) != 2 {
		t.Fatalf("calls = %d", f.count(tg.ID))
	}
}

func TestSlowServerDoesNotBlockOthers(t *testing.T) {
	e := newSchedEnv(t)
	slow, _ := e.server("srv-slow", target.EnvProd, true)
	var quick []target.Target
	for i := 0; i < 4; i++ {
		tg, _ := e.server(fmt.Sprintf("srv-quick-%d", i), target.EnvProd, true)
		quick = append(quick, tg)
	}
	stuck, release := make(chan struct{}), make(chan struct{})
	f := &fakePass{fn: func(_ context.Context, id string) (PassResult, error) {
		if id == slow.ID {
			close(stuck)
			<-release
		}
		return PassResult{}, nil
	}}
	s := e.scheduler(f)
	done := make(chan struct{})
	go func() { s.tick(context.Background()); close(done) }()
	<-stuck
	// The quick servers are read while the slow one is held, and again at their
	// next interval, which the slow one's round does not wait for.
	waitFor(t, func() bool {
		for _, q := range quick {
			if f.count(q.ID) != 1 {
				return false
			}
		}
		return true
	})
	e.clock.Advance(5 * time.Minute)
	s.tick(context.Background())
	for _, q := range quick {
		if f.count(q.ID) != 2 {
			t.Fatalf("%s: %d reads while the slow server is held", q.Name, f.count(q.ID))
		}
	}
	if f.count(slow.ID) != 1 {
		t.Errorf("the slow server was started again: %d", f.count(slow.ID))
	}
	close(release)
	<-done
}

// waitFor polls a condition that only becomes true: a failure is the timeout.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("the condition did not come true")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAtMostFourServersAtOnce(t *testing.T) {
	e := newSchedEnv(t)
	for i := 0; i < 7; i++ {
		e.server(fmt.Sprintf("srv-%d", i), target.EnvProd, true)
	}
	var now, peak atomic.Int32
	var finished atomic.Int32
	gate := make(chan struct{})
	f := &fakePass{fn: func(context.Context, string) (PassResult, error) {
		n := now.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-gate
		now.Add(-1)
		finished.Add(1)
		return PassResult{}, nil
	}}
	s := e.scheduler(f)
	done := make(chan struct{})
	go func() { s.tick(context.Background()); close(done) }()
	waitFor(t, func() bool { return now.Load() == maxParallel })
	// Give a fifth read the chance to start if the bound were missing: it
	// would only make this check stronger, never fail it.
	time.Sleep(50 * time.Millisecond)
	if now.Load() != maxParallel {
		t.Fatalf("running: %d", now.Load())
	}
	close(gate)
	<-done
	if peak.Load() != maxParallel || finished.Load() != 7 {
		t.Fatalf("peak %d, finished %d", peak.Load(), finished.Load())
	}
}

func TestNotReadingAfterThreeFailuresAnd30Min(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	e.interval(tg, 10*time.Minute)
	f := &fakePass{fn: failing(ReasonTimeout)}
	s := e.scheduler(f)
	ctx := context.Background()
	step := func() int {
		s.tick(ctx)
		e.clock.Advance(10 * time.Minute)
		return len(e.alerts.all())
	}
	// Failures at 0, 10, 20 minutes: three in a row, but only 20 minutes.
	for i, want := range []int{0, 0, 0} {
		if got := step(); got != want {
			t.Fatalf("failure %d: %d alerts", i+1, got)
		}
	}
	// At 30 minutes: the fourth failure, and 30 minutes without a good read.
	if got := step(); got != 1 {
		t.Fatalf("at 30 minutes: %d alerts", got)
	}
	in := e.alerts.all()[0]
	if in.Kind != AlertNotReading || in.Reason != ReasonTimeout || in.Target.ID != tg.ID || len(in.Items) != 1 || in.Items[0].Type != "srv-demo" {
		t.Fatalf("alert = %+v", in)
	}
	// One alert per incident.
	step()
	step()
	if got := len(e.alerts.all()); got != 1 {
		t.Fatalf("the same incident alerted %d times", got)
	}
	// A good read ends it; a new one is a new incident, with the same bars.
	f.fn = nil
	step()
	f.fn = failing(ReasonTimeout)
	step() // 70
	step() // 80
	if got := len(e.alerts.all()); got != 1 {
		t.Fatalf("two failures after the success: %d alerts", got)
	}
	step() // 90: 3 failures and 30 minutes since the good read at 60
	if got := len(e.alerts.all()); got != 2 {
		t.Fatalf("the new incident was not told: %d alerts", got)
	}
}

func TestTwoFailuresAreNotAnIncident(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	e.interval(tg, 10*time.Minute)
	f := &fakePass{fn: failing(ReasonError)}
	s := e.scheduler(f)
	// The last good read was an hour ago, so only the count holds it back.
	if err := e.repo.SaveCursors(context.Background(), []Cursor{{SourceID: e.sourceOf(tg), File: "/var/log/demo/app.log", FileID: "1", Offset: 1, ReadAt: readNow.Add(-time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	if len(e.alerts.all()) != 0 {
		t.Fatalf("alerts after two failures: %v", e.alerts.kinds())
	}
	s.tick(context.Background())
	if len(e.alerts.all()) != 1 {
		t.Fatalf("alerts after three failures and an hour: %v", e.alerts.kinds())
	}
}

func (e *schedEnv) sourceOf(tg target.Target) string {
	e.t.Helper()
	srcs, err := e.repo.Sources(context.Background(), tg.ID)
	if err != nil || len(srcs) == 0 {
		e.t.Fatalf("sources: %v, %v", srcs, err)
	}
	return srcs[0].ID
}

func TestNotReadingRouteByEnv(t *testing.T) {
	e := newSchedEnv(t)
	prod, _ := e.server("srv-prod", target.EnvProd, true)
	pre, _ := e.server("srv-pre", target.EnvPreprod, true)
	dev, _ := e.server("srv-dev", target.EnvDev, true)
	for _, tg := range []target.Target{prod, pre, dev} {
		e.interval(tg, 10*time.Minute)
		// Each was read at the start: the gap begins there.
		if err := e.repo.SaveCursors(context.Background(), []Cursor{{SourceID: e.sourceOf(tg), File: "/var/log/demo/app.log", FileID: "1", Offset: 1, ReadAt: readNow}}); err != nil {
			t.Fatal(err)
		}
	}
	f := &fakePass{fn: failing(ReasonTimeout)}
	s := e.scheduler(f)
	for i := 0; i < 4; i++ {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	got := e.alerts.all()
	if len(got) != 1 || got[0].Target.ID != prod.ID || got[0].Kind != AlertNotReading {
		t.Fatalf("only prod is told at once: %+v", got)
	}
	// The others wait for the digest, which reads the gap.
	for _, tg := range []target.Target{prod, pre, dev} {
		notes, err := e.repo.Notes(context.Background(), tg.ID)
		if err != nil || len(notes) != 1 || notes[0].Kind != NoteGap || !notes[0].From.Equal(readNow) || !notes[0].To.Equal(readNow.Add(30*time.Minute)) {
			t.Errorf("%s: notes = %+v, %v", tg.Name, notes, err)
		}
	}
}

func TestNotReadingIgnoresHourlyCap(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	st, _ := e.repo.Settings(context.Background(), tg.ID)
	st.MaxAlertsPerHour, st.Interval = 1, 10*time.Minute
	if err := e.repo.SaveSettings(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	// The cap is used up by a message sent a moment ago.
	if !alertSlots.take(tg.ID, readNow, st.MaxAlertsPerHour) {
		t.Fatal("setup: the cap was already used")
	}
	f := &fakePass{fn: failing(ReasonError)}
	s := e.scheduler(f)
	for i := 0; i < 4; i++ {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	if got := e.alerts.ofKind(AlertNotReading); len(got) != 1 {
		t.Fatalf("alerts = %v", e.alerts.kinds())
	}
	if !alertSlots.take(tg.ID, readNow.Add(40*time.Minute), 2) {
		t.Error("the not reading alert used the cap of errors")
	}
}

func TestLockedAgentIsOneAlert(t *testing.T) {
	e := newSchedEnv(t)
	for _, n := range []string{"srv-c", "srv-a", "srv-b"} {
		tg, _ := e.server(n, target.EnvProd, true)
		e.interval(tg, 10*time.Minute)
	}
	pre, _ := e.server("srv-pre", target.EnvPreprod, true)
	e.interval(pre, 10*time.Minute)
	locked := true
	f := &fakePass{}
	f.fn = func(context.Context, string) (PassResult, error) {
		if locked {
			return PassResult{Reason: ReasonNoAgent}, sshx.ErrNoAgent
		}
		return PassResult{}, nil
	}
	s := e.scheduler(f)
	tick := func() {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	for i := 0; i < 8; i++ {
		tick()
	}
	got := e.alerts.all()
	if len(got) != 1 {
		t.Fatalf("three prod servers with a locked agent gave %d alerts: %v", len(got), e.alerts.kinds())
	}
	in := got[0]
	var names []string
	for _, it := range in.Items {
		names = append(names, it.Type)
	}
	if in.Kind != AlertNotReading || in.Reason != ReasonNoAgent || fmt.Sprint(names) != "[srv-a srv-b srv-c]" || in.Target.Name != "srv-a" {
		t.Fatalf("alert = %+v, names %v", in, names)
	}
	// A server that joins the incident later is not told apart.
	late, _ := e.server("srv-late", target.EnvProd, true)
	e.interval(late, 10*time.Minute)
	for i := 0; i < 6; i++ {
		tick()
	}
	if len(e.alerts.all()) != 1 {
		t.Fatalf("a late server added an alert: %v", e.alerts.kinds())
	}
	// Everyone reads again, then the agent is locked once more: a new incident.
	locked = false
	tick()
	locked = true
	for i := 0; i < 5; i++ {
		tick()
	}
	if len(e.alerts.all()) != 2 {
		t.Fatalf("the second lock gave %d alerts: %v", len(e.alerts.all()), e.alerts.kinds())
	}
}

// lockedAgent makes the fake read of a server fail for the SSH agent.
func lockedAgent(context.Context, string) (PassResult, error) {
	return PassResult{Reason: ReasonNoAgent}, sshx.ErrNoAgent
}

func TestStaleCarrierDoesNotSilenceTheNextAgentAlert(t *testing.T) {
	ctx := context.Background()
	for name, retire := range map[string]func(e *schedEnv, tg target.Target, src Source){
		"turned off": func(e *schedEnv, tg target.Target, _ Source) {
			tg.Active = false
			if err := e.targets.Update(ctx, tg); err != nil {
				t.Fatal(err)
			}
		},
		"removed": func(e *schedEnv, tg target.Target, _ Source) {
			if err := e.targets.Remove(ctx, tg.ID); err != nil {
				t.Fatal(err)
			}
		},
		"manual": func(e *schedEnv, tg target.Target, _ Source) { e.interval(tg, ManualInterval) },
		"last source off": func(e *schedEnv, _ target.Target, src Source) {
			src.Active = false
			if err := e.repo.UpdateSource(ctx, src); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newSchedEnv(t)
			carrier, src := e.server("srv-carrier", target.EnvProd, true)
			e.interval(carrier, 10*time.Minute)
			s := e.scheduler(&fakePass{fn: lockedAgent})
			tick := func() {
				s.tick(ctx)
				e.clock.Advance(10 * time.Minute)
			}
			for i := 0; i < 4; i++ {
				tick()
			}
			if len(e.alerts.all()) != 1 {
				t.Fatalf("setup: %v", e.alerts.kinds())
			}
			retire(e, carrier, src)
			next, _ := e.server("srv-next", target.EnvProd, true)
			e.interval(next, 10*time.Minute)
			for i := 0; i < 5; i++ {
				tick()
			}
			got := e.alerts.all()
			if len(got) != 2 || got[1].Target.ID != next.ID {
				t.Fatalf("no one is told for the next server: %+v", got)
			}
		})
	}
}

func TestPastTheAgentClearsAStandingAgentAlert(t *testing.T) {
	for name, past := range map[string]func(context.Context, string) (PassResult, error){
		"a good read":     func(context.Context, string) (PassResult, error) { return PassResult{}, nil },
		"another failure": failing(ReasonTimeout),
	} {
		t.Run(name, func(t *testing.T) {
			e := newSchedEnv(t)
			carrier, _ := e.server("srv-carrier", target.EnvProd, true)
			e.interval(carrier, 10*time.Minute)
			f := &fakePass{fn: lockedAgent}
			s := e.scheduler(f)
			ctx := context.Background()
			tick := func() {
				s.tick(ctx)
				e.clock.Advance(10 * time.Minute)
			}
			for i := 0; i < 4; i++ {
				tick()
			}
			if len(e.alerts.all()) != 1 {
				t.Fatalf("setup: %v", e.alerts.kinds())
			}
			// The carrier now reads once a day: it says nothing for a long time.
			e.interval(carrier, 24*time.Hour)
			other, _ := e.server("srv-other", target.EnvProd, true)
			e.interval(other, 10*time.Minute)
			f.fn = past
			tick()
			// The other server gets past the agent, and then the agent is locked anew.
			f.fn = lockedAgent
			for i := 0; i < 5; i++ {
				tick()
			}
			got := e.alerts.ofKind(AlertNotReading)
			if len(got) != 2 || got[1].Target.ID != other.ID || got[1].Reason != ReasonNoAgent {
				t.Fatalf("the new lock was not told: %+v", got)
			}
		})
	}
}

func TestServerStillFailingForTheAgentKeepsItsIncident(t *testing.T) {
	e := newSchedEnv(t)
	carrier, _ := e.server("srv-carrier", target.EnvProd, true)
	e.interval(carrier, 10*time.Minute)
	f := &fakePass{fn: lockedAgent}
	s := e.scheduler(f)
	tick := func() {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	for i := 0; i < 4; i++ {
		tick()
	}
	other, _ := e.server("srv-other", target.EnvProd, true)
	e.interval(other, 10*time.Minute)
	// In the same rounds one server reads and the other still cannot: its incident
	// goes on, it is not a new one told again.
	f.fn = func(ctx context.Context, id string) (PassResult, error) {
		if id == carrier.ID {
			return lockedAgent(ctx, id)
		}
		return PassResult{}, nil
	}
	for i := 0; i < 5; i++ {
		tick()
	}
	if got := e.alerts.all(); len(got) != 1 {
		t.Fatalf("alerts = %+v", got)
	}
}

func TestNotReadingNotesTheGapWithoutAPosition(t *testing.T) {
	e := newSchedEnv(t)
	pre, _ := e.server("srv-pre", target.EnvPreprod, true)
	dev, _ := e.server("srv-dev", target.EnvDev, true)
	for _, tg := range []target.Target{pre, dev} {
		e.interval(tg, 10*time.Minute)
	}
	s := e.scheduler(&fakePass{fn: failing(ReasonTimeout)})
	for i := 0; i < 4; i++ {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	if len(e.alerts.all()) != 0 {
		t.Fatalf("alerts = %v", e.alerts.kinds())
	}
	// Failing since the activation: the gap runs from the first failure.
	for _, tg := range []target.Target{pre, dev} {
		notes, err := e.repo.Notes(context.Background(), tg.ID)
		if err != nil || len(notes) != 1 || notes[0].Kind != NoteGap || !notes[0].From.Equal(readNow) || !notes[0].To.Equal(readNow.Add(30*time.Minute)) {
			t.Errorf("%s: notes = %+v, %v", tg.Name, notes, err)
		}
	}
}

func TestNotReadingNoteFailureIsLoggedAndTriedAgain(t *testing.T) {
	e := newSchedEnv(t)
	pre, _ := e.server("srv-pre", target.EnvPreprod, true)
	e.interval(pre, 10*time.Minute)
	s := e.scheduler(&fakePass{fn: failing(ReasonTimeout)})
	ctx := context.Background()
	tick := func() {
		s.tick(ctx)
		e.clock.Advance(10 * time.Minute)
	}
	for i := 0; i < 3; i++ {
		tick()
	}
	buf := captureLog(t)
	renameTable(t, e.s, "log_note", "log_note_off")
	tick() // the bar is reached and the note cannot be written
	renameTable(t, e.s, "log_note_off", "log_note")
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "gap") {
		t.Errorf("the lost note is not said: %q", buf.String())
	}
	if s.incidents[pre.ID].alerted {
		t.Fatal("the incident counts as told with no note written")
	}
	tick()
	notes, err := e.repo.Notes(ctx, pre.ID)
	if err != nil || len(notes) != 1 || notes[0].Kind != NoteGap {
		t.Fatalf("the note was not written the next time: %+v, %v", notes, err)
	}
	if !s.incidents[pre.ID].alerted {
		t.Error("the note is written: the incident is told")
	}
}

func TestNotReadingGapLastsAsLongAsTheIncident(t *testing.T) {
	e := newSchedEnv(t)
	pre, _ := e.server("srv-pre", target.EnvPreprod, true)
	e.interval(pre, 10*time.Minute)
	s := e.scheduler(&fakePass{fn: failing(ReasonTimeout)})
	at := readNow
	for i := 0; i < 10; i++ {
		at = e.clock.Now()
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	notes, err := e.repo.Notes(context.Background(), pre.ID)
	if err != nil || len(notes) != 1 || !notes[0].From.Equal(readNow) || !notes[0].To.Equal(at) {
		t.Fatalf("notes = %+v, want one up to %v (%v)", notes, at, err)
	}
}

func TestHealthySourceGetsNoGapNote(t *testing.T) {
	e := newSchedEnv(t)
	tg, bad := e.server("srv-demo", target.EnvProd, true)
	e.interval(tg, 10*time.Minute)
	ctx := context.Background()
	good, err := e.repo.AddSource(ctx, Source{TargetID: tg.ID, Path: "/var/log/demo/other.log", Format: FormatMonolog, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.repo.SaveCursors(ctx, []Cursor{{SourceID: bad.ID, File: bad.Path, FileID: "1", Offset: 1, ReadAt: readNow}}); err != nil {
		t.Fatal(err)
	}
	// One source is read at each pass, the other one fails the pass.
	s := e.scheduler(&fakePass{fn: func(context.Context, string) (PassResult, error) {
		if err := e.repo.SaveCursors(ctx, []Cursor{{SourceID: good.ID, File: good.Path, FileID: "2", Offset: 1, ReadAt: e.clock.Now()}}); err != nil {
			t.Error(err)
		}
		return PassResult{Reason: ReasonTimeout}, errors.New("the read failed")
	}})
	for i := 0; i < 4; i++ {
		s.tick(ctx)
		e.clock.Advance(10 * time.Minute)
	}
	notes, err := e.repo.Notes(ctx, tg.ID)
	if err != nil || len(notes) != 1 || notes[0].SourceID != bad.ID {
		t.Fatalf("notes = %+v, %v (failing source %s)", notes, err, bad.ID)
	}
}

func TestRetentionRunsWithoutAnAuditLogger(t *testing.T) {
	e := newSchedEnv(t)
	tg, src := e.server("srv-demo", target.EnvProd, true)
	ctx := context.Background()
	old := readNow.Add(-100 * 24 * time.Hour)
	if _, _, _, err := e.repo.Apply(ctx, src, []Record{rec(1, old)}, old); err != nil {
		t.Fatal(err)
	}
	d := e.deps
	d.Audit = nil
	newScheduler(d).maintain(ctx)
	if sigs, _ := e.repo.Signatures(ctx, tg.ID); len(sigs) != 0 {
		t.Fatalf("the old error is kept: %+v", sigs)
	}
}

func TestOtherCausesAreToldPerServer(t *testing.T) {
	e := newSchedEnv(t)
	for _, n := range []string{"srv-a", "srv-b"} {
		tg, _ := e.server(n, target.EnvProd, true)
		e.interval(tg, 10*time.Minute)
	}
	f := &fakePass{fn: failing(ReasonTimeout)}
	s := e.scheduler(f)
	for i := 0; i < 4; i++ {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	if got := e.alerts.ofKind(AlertNotReading); len(got) != 2 {
		t.Fatalf("two servers timing out are two alerts: %v", e.alerts.kinds())
	}
}

func TestInactiveAndBusyAreNotFailures(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	e.interval(tg, 10*time.Minute)
	f := &fakePass{fn: func(context.Context, string) (PassResult, error) {
		return PassResult{Reason: ReasonBusy}, ErrPassRunning
	}}
	s := e.scheduler(f)
	for i := 0; i < 8; i++ {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	if len(e.alerts.all()) != 0 {
		t.Fatalf("alerts = %v", e.alerts.kinds())
	}
}

func TestSchedulerStopsWithItsContext(t *testing.T) {
	e := newSchedEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Scheduler(ctx, e.deps, 5*time.Millisecond); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the scheduler did not stop")
	}
}

func TestSchedulerAppliesTheRetention(t *testing.T) {
	e := newSchedEnv(t)
	tg, src := e.server("srv-demo", target.EnvProd, true)
	ctx := context.Background()
	old := readNow.Add(-100 * 24 * time.Hour)
	if _, _, _, err := e.repo.Apply(ctx, src, []Record{rec(1, old)}, old); err != nil {
		t.Fatal(err)
	}
	s := e.scheduler(&fakePass{})
	s.maintain(ctx)
	if sigs, _ := e.repo.Signatures(ctx, tg.ID); len(sigs) != 0 {
		t.Fatalf("the old error is kept: %+v", sigs)
	}
	ev := auditRowsFor(t, e.s, "log.purge")
	if len(ev) != 1 {
		t.Fatalf("log.purge events: %v", ev)
	}
	// Not again before purgeEvery.
	if _, _, _, err := e.repo.Apply(ctx, src, []Record{rec(1, old)}, old); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Hour)
	s.maintain(ctx)
	if sigs, _ := e.repo.Signatures(ctx, tg.ID); len(sigs) != 1 {
		t.Fatalf("purged again within the hour: %+v", sigs)
	}
	e.clock.Advance(purgeEvery)
	s.maintain(ctx)
	if sigs, _ := e.repo.Signatures(ctx, tg.ID); len(sigs) != 0 {
		t.Fatalf("not purged after %v: %+v", purgeEvery, sigs)
	}
}

func auditRowsFor(t *testing.T, s *store.Store, action string) []string {
	t.Helper()
	rows, err := s.DB().Query(`SELECT evidence FROM audit_event WHERE action = ? ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ev string
		if err := rows.Scan(&ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// The first round is announced once it is over: not before the servers due
// were read.
func TestSchedulerAnnouncesTheFirstRoundOnceItIsOver(t *testing.T) {
	e := newSchedEnv(t)
	e.server("srv-demo", target.EnvProd, true)
	entered, release := make(chan struct{}, 10), make(chan struct{})
	old := schedulerPass
	schedulerPass = func(ctx context.Context, d Deps, id string) (PassResult, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return PassResult{}, nil
	}
	t.Cleanup(func() { schedulerPass = old })
	var announced atomic.Int32
	announcedCh := make(chan struct{}, 10)
	e.deps.FirstRound = func() { announced.Add(1); announcedCh <- struct{}{} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Scheduler(ctx, e.deps, 5*time.Millisecond); close(done) }()
	<-entered // the first round is reading the server
	if n := announced.Load(); n != 0 {
		t.Fatalf("announced %d times while the first round is still reading", n)
	}
	close(release)
	select {
	case <-announcedCh:
	case <-time.After(20 * time.Second):
		t.Fatal("the first round was not announced")
	}
	cancel()
	<-done
	if n := announced.Load(); n != 1 {
		t.Errorf("announced %d times", n)
	}
}

// Rights lost on the only file of a prod source: the third failure, 30 minutes
// apart, tells it once with its cause. Rights back end the incident, and the
// reading goes on from where it stood.
func TestLostRightsTellNotReadingOnProd(t *testing.T) {
	for _, tc := range []struct{ cause, reason string }{
		{CauseDenied, ReasonDenied},
		{CauseTools, ReasonTools},
		{CauseOther, ReasonError},
	} {
		t.Run(tc.cause, func(t *testing.T) {
			pe := newPassEnv(t, target.EnvProd, FormatMonolog)
			s := newScheduler(pe.deps)
			ctx := context.Background()
			step := func() {
				pe.clock.Advance(30 * time.Minute)
				s.tick(ctx)
			}
			s.tick(ctx) // the activation goes well
			pe.setShell(answer(unseenLine(pe.src.Path, tc.cause)))
			step()
			step()
			if got := pe.alerts.kinds(); len(got) != 0 {
				t.Fatalf("after two failures: %v", got)
			}
			step()
			step()
			told := pe.alerts.ofKind(AlertNotReading)
			if len(told) != 1 || told[0].Reason != tc.reason {
				t.Fatalf("not reading = %+v, all %v", told, pe.alerts.kinds())
			}
			// Rights back: the line written meanwhile is read, the incident is over.
			pe.write(mono("CRITICAL", "PDOException", "Invoice.php", 42))
			pe.setShell(nil)
			step()
			if sigs := pe.signatures(); len(sigs) != 1 || sigs[0].Total != 1 {
				t.Fatalf("after the rights came back: %+v", sigs)
			}
			if unseen, err := pe.repo.Unseen(ctx, pe.tgt.ID); err != nil || len(unseen) != 0 {
				t.Errorf("unseen rows = %+v, %v", unseen, err)
			}
			s.mu.Lock()
			_, open := s.incidents[pe.tgt.ID]
			s.mu.Unlock()
			if open {
				t.Error("the incident outlived the good read")
			}
			if n := len(pe.alerts.ofKind(AlertNotReading)); n != 1 {
				t.Errorf("not reading alerts = %d", n)
			}
		})
	}
}

// Unreadable from the activation on, the file located by its metadata: an
// incident as well.
func TestUnreadableFromTheActivationTellsNotReading(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	s := newScheduler(pe.deps)
	ctx := context.Background()
	pe.setShell(answer(locatedLine(pe.src.Path), unseenLine(pe.src.Path, CauseDenied)))
	s.tick(ctx)
	pe.setShell(answer(unseenLine(pe.src.Path, CauseDenied)))
	for i := 0; i < 2; i++ {
		pe.clock.Advance(30 * time.Minute)
		s.tick(ctx)
	}
	told := pe.alerts.ofKind(AlertNotReading)
	if len(told) != 1 || told[0].Reason != ReasonDenied {
		t.Fatalf("not reading = %+v, all %v", told, pe.alerts.kinds())
	}
}

// On preprod no alert goes: the gap note carries it to the digest (see
// TestDigestShowsReadGap for that side).
func TestLostRightsNoteAGapOnPreprod(t *testing.T) {
	pe := newPassEnv(t, target.EnvPreprod, FormatMonolog)
	s := newScheduler(pe.deps)
	ctx := context.Background()
	s.tick(ctx)
	pe.setShell(answer(unseenLine(pe.src.Path, CauseDenied)))
	for i := 0; i < 3; i++ {
		pe.clock.Advance(30 * time.Minute)
		s.tick(ctx)
	}
	if got := pe.alerts.kinds(); len(got) != 0 {
		t.Fatalf("alerts = %v", got)
	}
	gaps := pe.notes(NoteGap)
	if len(gaps) != 1 || !gaps[0].From.Equal(readNow) || !gaps[0].To.Equal(readNow.Add(90*time.Minute)) {
		t.Fatalf("gaps = %+v", gaps)
	}
	s.mu.Lock()
	inc := s.incidents[pe.tgt.ID]
	s.mu.Unlock()
	if inc == nil || inc.reason != ReasonDenied {
		t.Errorf("incident = %+v", inc)
	}
}

// An incident of one source, the others of the server being read, is told as
// that source's: it names the source and the cause, and the alert says the
// others were read. A server whose connection fails keeps the whole wording.
func TestNotReadingNamesTheSourceThatFails(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	e.interval(tg, 10*time.Minute)
	partial := PassResult{Reason: ReasonDenied, Read: 1, Failed: []FailedSource{{Label: "/var/log/demo/other.log", Reason: ReasonDenied}}}
	f := &fakePass{fn: func(context.Context, string) (PassResult, error) { return partial, errors.New("the read failed") }}
	s := e.scheduler(f)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		s.tick(ctx)
		e.clock.Advance(10 * time.Minute)
	}
	told := e.alerts.ofKind(AlertNotReading)
	if len(told) != 1 {
		t.Fatalf("alerts = %v", e.alerts.kinds())
	}
	if in := told[0]; in.Reason != ReasonDenied || len(in.Sources) != 1 || in.Sources[0] != "/var/log/demo/other.log" {
		t.Errorf("alert = %+v", in)
	}
}

// Every source failing, or the connection, is the server as a whole.
func TestNotReadingNamesNoSourceWhenNoneWasRead(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	e.interval(tg, 10*time.Minute)
	all := PassResult{Reason: ReasonDenied, Failed: []FailedSource{{Label: "/var/log/demo/app.log", Reason: ReasonDenied}}}
	f := &fakePass{fn: func(context.Context, string) (PassResult, error) { return all, errors.New("the read failed") }}
	s := e.scheduler(f)
	for i := 0; i < 4; i++ {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	told := e.alerts.ofKind(AlertNotReading)
	if len(told) != 1 || len(told[0].Sources) != 0 {
		t.Fatalf("alerts = %+v", told)
	}
}

// Sources failing for different causes: the cause is the general one, not the
// first of them.
func TestNotReadingMixedCausesAreGeneral(t *testing.T) {
	e := newSchedEnv(t)
	tg, _ := e.server("srv-demo", target.EnvProd, true)
	e.interval(tg, 10*time.Minute)
	mixed := PassResult{Reason: ReasonDenied, Read: 1, Failed: []FailedSource{{Label: "/var/log/demo/a.log", Reason: ReasonDenied}, {Label: "/var/log/demo/b.log", Reason: ReasonTools}}}
	f := &fakePass{fn: func(context.Context, string) (PassResult, error) { return mixed, errors.New("the read failed") }}
	s := e.scheduler(f)
	for i := 0; i < 4; i++ {
		s.tick(context.Background())
		e.clock.Advance(10 * time.Minute)
	}
	told := e.alerts.ofKind(AlertNotReading)
	if len(told) != 1 || told[0].Reason != ReasonError || len(told[0].Sources) != 2 {
		t.Fatalf("alerts = %+v", told)
	}
}
