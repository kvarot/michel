package fix

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// I-R3 probe 1: a collection slower than the record bound still ends the
// attempt in a final state.
func TestSlowRecollectionStillEndsTheAttempt(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	f.d.RecordTimeout = 300 * time.Millisecond
	check := f.d.CheckServer
	f.d.CheckServer = func(ctx context.Context, id string) (servercheck.CheckResult, error) {
		time.Sleep(500 * time.Millisecond)
		return check(ctx, id)
	}
	if err := Apply(context.Background(), f.d, a.ID); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateProvenFixed {
		t.Errorf("state %s cause %q", got.State, got.Cause)
	}
}

// I-R3 probe 2: a slow failing site check, then the undo: the attempt ends
// rolled back and the alert gets a live context.
func TestSlowSiteCheckThenUndoEndsTheAttempt(t *testing.T) {
	for name, rollbackFails := range map[string]bool{"undone": false, "undo fails": true} {
		t.Run(name, func(t *testing.T) {
			f := newServerFixture(t)
			s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
			f.mustCheck(s)
			a, _ := f.startApproved(s, "expose_php")
			if rollbackFails {
				s.reloads = []int{0, 1}
			}
			f.d.RecordTimeout = 300 * time.Millisecond
			f.d.SiteCheck = func(ctx context.Context, url string) error {
				time.Sleep(400 * time.Millisecond)
				return errors.New("site down")
			}
			var alertCtxErr []error
			f.d.Alert = func(ctx context.Context, in servercheck.AlertInput) {
				alertCtxErr = append(alertCtxErr, ctx.Err())
				f.alerts = append(f.alerts, in)
			}
			err := Apply(context.Background(), f.d, a.ID)
			want, state := ErrServerRolledBack, StateFailed
			if rollbackFails {
				want = ErrServerRollbackFailed
			}
			if !errors.Is(err, want) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Apply: %v", err)
			}
			if got := f.attempt(a.ID); got.State != state {
				t.Errorf("state %s", got.State)
			}
			if len(alertCtxErr) != 1 || alertCtxErr[0] != nil {
				t.Errorf("alert contexts %v", alertCtxErr)
			}
		})
	}
}

// I-R3: the site check has its own bound: a site that never answers is a
// site down, and the fix is undone.
func TestSiteCheckHasItsOwnBound(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	f.d.SiteCheckTimeout = 200 * time.Millisecond
	f.d.SiteCheck = func(ctx context.Context, url string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	start := time.Now()
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrServerRolledBack) {
		t.Fatalf("Apply: %v", err)
	}
	if time.Since(start) > 10*time.Second || file(t, s, s.ini) != demoIni {
		t.Error("not undone in time")
	}
}

// I-R3 belt and braces: a server fix left applied past its deadline plus
// the margin ends unknown; a fresh one, and a code fix, are left alone.
func TestStaleAppliedEndsUnknown(t *testing.T) {
	f := newServerFixture(t)
	s := f.addServer("srv-demo", "8.2", demoIni, target.ExecMichel, target.SudoNopasswd, nil)
	f.mustCheck(s)
	a, _ := f.startApproved(s, "expose_php")
	ctx := context.Background()
	repo := f.d.repo()
	if ok, err := repo.Claim(ctx, a.ID, f.clock.Add(5*time.Minute)); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := repo.SetState(ctx, a.ID, []State{StateRunning}, StateApplied, ""); err != nil {
		t.Fatal(err)
	}
	code, err := repo.CreateAttempt(ctx, Attempt{FindingID: "f-code", ProjectID: "P-CODE", Origin: OriginAgent})
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []State{StateProposed, StateApproved, StateApplied} {
		prev := map[State]State{StateProposed: StatePreparing, StateApproved: StateProposed, StateApplied: StateApproved}[st]
		if err := repo.SetState(ctx, code.ID, []State{prev}, st, ""); err != nil {
			t.Fatal(err)
		}
	}
	// Past the bound plus the running margin, within the applied margin:
	// the steps after the script may still be going on.
	f.clock = f.clock.Add(20 * time.Minute)
	if n, _ := SweepRunning(ctx, f.d); n != 0 || f.attempt(a.ID).State != StateApplied {
		t.Fatal("a fresh applied fix was moved")
	}
	f.clock = f.clock.Add(time.Hour)
	if n, err := SweepRunning(ctx, f.d); err != nil || n != 1 {
		t.Fatalf("SweepRunning: %d %v", n, err)
	}
	if got := f.attempt(a.ID); got.State != StateUnknown {
		t.Errorf("state %s", got.State)
	}
	if got := f.attempt(code.ID); got.State != StateApplied {
		t.Errorf("code fix moved to %s", got.State)
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != servercheck.AlertUnknownState {
		t.Errorf("alerts %+v", f.alerts)
	}
}

// flakyStore is a secret store whose reads can fail or be slow, and which
// counts its writes.
type flakyStore struct {
	secret.Store
	mu      sync.Mutex
	getErr  error
	sets    int
	setWait time.Duration
}

func (s *flakyStore) Get(name string) ([]byte, error) {
	s.mu.Lock()
	e := s.getErr
	s.mu.Unlock()
	if e != nil {
		return nil, e
	}
	return s.Store.Get(name)
}

func (s *flakyStore) Set(name string, v []byte) error {
	s.mu.Lock()
	s.sets++
	w := s.setWait
	s.mu.Unlock()
	time.Sleep(w)
	return s.Store.Set(name, v)
}

// I-R4: a winner slow to write its key is waited for, never overwritten.
func TestSlowKeyWinnerNotOverwritten(t *testing.T) {
	f := newServerFixture(t)
	fs := &flakyStore{Store: f.d.Secrets, setWait: 1500 * time.Millisecond}
	f.d.Secrets = fs
	other := f.d
	other.Sessions = NewSessions()
	plain := &flakyStore{Store: fs.Store}
	other.Secrets = plain
	ctx := context.Background()
	var k1 []byte
	var e1 error
	done := make(chan struct{})
	go func() { defer close(done); k1, e1 = f.d.backupKey(ctx) }()
	// Let the slow winner insert its fingerprint first.
	for i := 0; i < 100; i++ {
		if fp, _ := f.d.repo().BackupKeyFingerprint(ctx); fp != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	k2, e2 := other.backupKey(ctx)
	<-done
	if e1 != nil || e2 != nil || string(k1) != string(k2) {
		t.Fatalf("keys differ: %v %v", e1, e2)
	}
	if plain.sets != 0 || fs.sets != 1 {
		t.Errorf("sets: loser %d, winner %d", plain.sets, fs.sets)
	}
}

// I-R4: a read error or a key with another fingerprint never rotates the
// key: that one backup is not kept, the key is untouched.
func TestKeyReadErrorDoesNotRotate(t *testing.T) {
	f := newServerFixture(t)
	ctx := context.Background()
	k, err := f.d.backupKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fs := &flakyStore{Store: f.d.Secrets, getErr: errors.New("sharing violation")}
	f.d.Secrets = fs
	if _, err := f.d.backupKey(ctx); err == nil {
		t.Fatal("a read error gave a key")
	}
	if err := f.d.addBackup(ctx, ServerBackup{AttemptID: "A1", TargetID: "T1", RemotePath: srvBackups + "c/1", Content: []byte("x")}); err == nil {
		t.Error("a backup was kept without the key")
	}
	fs.mu.Lock()
	fs.getErr = nil
	fs.mu.Unlock()
	// Another key in the store than the recorded one: refused, not replaced.
	if err := fs.Store.Set(backupKeyName, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.backupKey(ctx); err == nil {
		t.Error("a key with another fingerprint was used")
	}
	if fs.sets != 0 {
		t.Errorf("the store was written %d times", fs.sets)
	}
	if err := fs.Store.Set(backupKeyName, k); err != nil {
		t.Fatal(err)
	}
	if got, err := f.d.backupKey(ctx); err != nil || string(got) != string(k) {
		t.Errorf("the key changed: %v", err)
	}
}

// I-R4: only a key that stays missing is replaced, and the rotation is
// audited.
func TestMissingKeyRotatesAfterTheWait(t *testing.T) {
	f := newServerFixture(t)
	ctx := context.Background()
	f.d.BackupKeyWait = 200 * time.Millisecond
	if _, err := f.d.backupKey(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Secrets.Delete(backupKeyName); err != nil {
		t.Fatal(err)
	}
	k, err := f.d.backupKey(ctx)
	if err != nil || len(k) != 32 {
		t.Fatalf("rotation: %v", err)
	}
	if auditCount(t, f.st, "server_fix.backup_key", "rotated") != 1 {
		t.Error("rotation not audited")
	}
}

// N2: the tail is added only when the error stream itself was cut.
func TestTailOnlyForCutStderr(t *testing.T) {
	res := sshx.Result{Exit: 1, Stderr: []byte("x\n"), StderrTail: []byte(scriptRolledBack), Truncated: true}
	if err := classifyResult(res, false); !errors.Is(err, ErrServerStopped) {
		t.Errorf("stdout cut only: %v", err)
	}
	res.StderrCut = true
	if err := classifyResult(res, false); !errors.Is(err, ErrServerRolledBack) {
		t.Errorf("stderr cut: %v", err)
	}
}

// A backup sealed with a key that was replaced since reads "key lost"; a
// backup sealed with the current key that no longer matches reads
// "damaged"; a good one "kept". (Task 13: the page must not call a copy
// whose key was lost a copy that does not match.)
func TestBackupStatesSayKeyLostAfterRotation(t *testing.T) {
	f := newServerFixture(t)
	ctx := context.Background()
	f.d.BackupKeyWait = 100 * time.Millisecond
	add := func(path, content string) {
		t.Helper()
		if err := f.d.addBackup(ctx, ServerBackup{AttemptID: "01ATTEMPT", TargetID: "01TARGET", RemotePath: path, Content: []byte(content)}); err != nil {
			t.Fatal(err)
		}
	}
	add("/var/lib/michel/backups/x/1", "old")
	if err := f.d.Secrets.Delete(backupKeyName); err != nil {
		t.Fatal(err)
	}
	add("/var/lib/michel/backups/x/2", "new")
	add("/var/lib/michel/backups/x/3", "bad")
	if _, err := f.st.DB().Exec(`UPDATE server_backup SET sha256 = '00' WHERE remote_path = '/var/lib/michel/backups/x/3'`); err != nil {
		t.Fatal(err)
	}
	got, err := BackupStates(ctx, f.d, "01ATTEMPT")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"/var/lib/michel/backups/x/1": BackupKeyLost, "/var/lib/michel/backups/x/2": BackupKept, "/var/lib/michel/backups/x/3": BackupDamaged}
	if len(got) != 3 {
		t.Fatalf("got %d states", len(got))
	}
	for _, s := range got {
		if want[s.RemotePath] != s.State {
			t.Errorf("%s: %s, want %s", s.RemotePath, s.State, want[s.RemotePath])
		}
	}
	// A copy stored before the fingerprint was recorded is not called lost.
	if _, err := f.st.DB().Exec(`UPDATE server_backup SET key_fingerprint = '' WHERE remote_path = '/var/lib/michel/backups/x/1'`); err != nil {
		t.Fatal(err)
	}
	got, _ = BackupStates(ctx, f.d, "01ATTEMPT")
	for _, s := range got {
		if s.RemotePath == "/var/lib/michel/backups/x/1" && s.State != BackupDamaged {
			t.Errorf("unrecorded key: %s", s.State)
		}
	}
}

// Task 13 fix round 1, I2: the page's read of the backup states never
// waits for, creates or rotates the key, and never hides the list: with the
// key gone from the store, every copy sealed with it reads key_lost at
// once; without a secret store the states are still given.
func TestBackupStatesReadTheKeyOnly(t *testing.T) {
	f := newServerFixture(t)
	ctx := context.Background()
	f.d.BackupKeyWait = 2 * time.Second
	if err := f.d.addBackup(ctx, ServerBackup{AttemptID: "01ATTEMPT", TargetID: "01TARGET", RemotePath: "/var/lib/michel/backups/x/1", Content: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Secrets.Delete(backupKeyName); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got, err := BackupStates(ctx, f.d, "01ATTEMPT")
	if err != nil || len(got) != 1 || got[0].State != BackupKeyLost {
		t.Fatalf("key deleted: %+v, %v", got, err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("BackupStates waited %s for the key", time.Since(start))
	}
	if n := auditCount(t, f.st, "server_fix.backup_key", "rotated"); n != 0 {
		t.Errorf("a page read rotated the key (%d)", n)
	}
	if _, err := f.d.Secrets.Get(backupKeyName); err == nil {
		t.Error("a page read created a key")
	}
	d := f.d
	d.Secrets = nil
	got, err = BackupStates(ctx, d, "01ATTEMPT")
	if err != nil || len(got) != 1 || got[0].State != BackupKeyLost {
		t.Errorf("no secret store: %+v, %v", got, err)
	}
}
