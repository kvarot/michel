package fix

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

// I-R1: a fresh running attempt (another process may be running it) is
// left alone; one past its own stored bound plus the margin ends unknown,
// with an urgent alert and a recollection.
func TestStaleRunningEndsUnknownFreshSurvives(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	ctx := context.Background()
	// Claimed by another process, with a 2 min bound.
	if ok, err := f.d.repo().Claim(ctx, a.ID, f.clock.Add(2*time.Minute)); err != nil || !ok {
		t.Fatalf("Claim: %v %v", ok, err)
	}
	f.clock = f.clock.Add(time.Minute)
	if err := Sweep(ctx, f.d); err != nil {
		t.Fatal(err)
	}
	if n, err := SweepRunning(ctx, f.d); err != nil || n != 0 {
		t.Fatalf("SweepRunning: %d %v", n, err)
	}
	if got := f.attempt(a.ID); got.State != StateRunning || len(f.alerts) != 0 {
		t.Fatalf("fresh run touched: %s %+v", got.State, f.alerts)
	}
	// Past the bound but within the margin: still left.
	f.clock = f.clock.Add(5 * time.Minute)
	if n, _ := SweepRunning(ctx, f.d); n != 0 || f.attempt(a.ID).State != StateRunning {
		t.Fatal("moved within the margin")
	}
	checks := 0
	check := f.d.CheckServer
	f.d.CheckServer = func(ctx context.Context, id string) (servercheck.CheckResult, error) {
		checks++
		return check(ctx, id)
	}
	f.clock = f.clock.Add(10 * time.Minute)
	if n, err := SweepRunning(ctx, f.d); err != nil || n != 1 {
		t.Fatalf("SweepRunning stale: %d %v", n, err)
	}
	if got := f.attempt(a.ID); got.State != StateUnknown {
		t.Errorf("state %s", got.State)
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertUnknownState || !f.alerts[0].Urgent || f.alerts[0].Target.ID != s.t.ID {
		t.Errorf("alerts %+v", f.alerts)
	}
	if checks != 1 {
		t.Errorf("recollections %d", checks)
	}
	// Sweep does the same (serve start): nothing left to move.
	if err := Sweep(ctx, f.d); err != nil || len(f.alerts) != 1 {
		t.Errorf("Sweep: %v alerts %d", err, len(f.alerts))
	}
}

// I-R2: an alert that never returns neither holds the attempt nor delays
// its state: the state is set before the alert, and Apply returns within
// the recording bound.
func TestHungAlertDoesNotHoldTheAttempt(t *testing.T) {
	for name, setup := range map[string]func(*serverFixture, *demoServer){
		"unknown": func(f *serverFixture, s *demoServer) {
			var once sync.Once
			s.onFPMTest = func(sshtest.Exec) { once.Do(s.srv.DropConnections) }
		},
		"rolled back": func(f *serverFixture, s *demoServer) { s.fpmTest = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newServerFixture(t)
			s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
			f.mustCheck(s)
			a, _ := f.startApproved(s, "expose_php")
			setup(f, s)
			f.d.RecordTimeout = 300 * time.Millisecond
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			var atAlert State
			f.d.Alert = func(ctx context.Context, in servercheck.AlertInput) {
				atAlert = f.attempt(a.ID).State
				<-release
			}
			done := make(chan error, 1)
			go func() { done <- Apply(context.Background(), f.d, a.ID) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Apply is held by the alert")
			}
			if atAlert == StateRunning || atAlert == "" {
				t.Errorf("state when alerting: %q", atAlert)
			}
			// The attempt's lock is free.
			lock := f.d.sessions().attemptLock(a.ID)
			if !lock.TryLock() {
				t.Error("the attempt is still locked")
			} else {
				lock.Unlock()
			}
		})
	}
}

// Minor 3: the backup key is made once, whatever the number of callers and
// processes; the key in the store is the one the backups use.
func TestBackupKeyMadeOnce(t *testing.T) {
	f := newServerFixture(t)
	other := f.d
	other.Sessions = NewSessions()
	ctx := context.Background()
	keys := make([][]byte, 16)
	var wg sync.WaitGroup
	for i := range keys {
		d := f.d
		if i%2 == 1 {
			d = other
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, err := d.backupKey(ctx)
			if err != nil {
				t.Error(err)
			}
			keys[i] = k
		}()
	}
	wg.Wait()
	stored, err := f.d.Secrets.Get(backupKeyName)
	if err != nil {
		t.Fatal(err)
	}
	for i, k := range keys {
		if string(k) != string(stored) {
			t.Fatalf("caller %d got another key", i)
		}
	}
	// Every backup sealed by any caller opens.
	for i := 0; i < 4; i++ {
		if err := keysDeps(f, other, i).addBackup(ctx, ServerBackup{AttemptID: "A1", TargetID: "T1", RemotePath: srvBackups + "c/" + string(rune('1'+i)), Content: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	if bs, err := f.d.backups(ctx, "A1"); err != nil || len(bs) != 4 {
		t.Errorf("backups %d %v", len(bs), err)
	}
}

func keysDeps(f *serverFixture, other Deps, i int) Deps {
	if i%2 == 1 {
		return other
	}
	return f.d
}

// Minor 3 and 4: one bad row is skipped and reported, the others are
// still listed; a row moved to another server does not open.
func TestBadBackupRowSkipped(t *testing.T) {
	f := newServerFixture(t)
	ctx := context.Background()
	for _, p := range []string{"/1", "/2", "/3"} {
		if err := f.d.addBackup(ctx, ServerBackup{AttemptID: "A1", TargetID: "T1", RemotePath: srvBackups + "c" + p, Content: []byte("content" + p)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.st.DB().Exec(`UPDATE server_backup SET blob = 'AAAA' WHERE remote_path LIKE '%/1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE server_backup SET target_id = 'T2' WHERE remote_path LIKE '%/2'`); err != nil {
		t.Fatal(err)
	}
	bs, err := f.d.backups(ctx, "A1")
	if !errors.Is(err, errBackupTampered) {
		t.Errorf("not reported: %v", err)
	}
	if len(bs) != 1 || string(bs[0].Content) != "content/3" {
		t.Errorf("good rows hidden: %+v", bs)
	}
}

// Minor 5: the outcome line is read from the tail of a cut error stream.
func TestOutcomeReadFromTheTail(t *testing.T) {
	res := sshx.Result{Exit: 1, Stderr: make([]byte, sshx.MaxOutput), Truncated: true, StderrCut: true, StderrTail: []byte("...\n" + scriptRolledBack + "\n")}
	if err := classifyResult(res, false); !errors.Is(err, ErrServerRolledBack) {
		t.Errorf("cut stream: %v", err)
	}
	res = sshx.Result{Exit: 1, Stderr: []byte(scriptRolledBack + "\n")}
	if err := classifyResult(res, false); !errors.Is(err, ErrServerRolledBack) {
		t.Errorf("whole stream: %v", err)
	}
}
