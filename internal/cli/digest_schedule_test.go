package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	_ "time/tzdata"

	"net/url"

	"github.com/kvarot/michel/internal/digest"
	"github.com/spf13/cobra"
)

// writeHookCfg writes a policy with one loopback webhook channel and the hour
// of the daily digest ("" leaves the default).
func writeHookCfg(t *testing.T, dir, hookURL, digestAt string) {
	t.Helper()
	cfg := "sovereignty:\n  network:\n    default_egress: deny\n    allow:\n      - {host: 127.0.0.1, purpose: notify.webhook}\n" +
		"notify:\n"
	if digestAt != "" {
		cfg += "  digest_at: \"" + digestAt + "\"\n"
	}
	cfg += "  channels:\n    - name: hook\n      type: webhook\n      url: " + hookURL + "/michel\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeFailingCfg writes a policy whose only channel cannot work: an email
// channel whose password is not in the secret store.
func writeFailingCfg(t *testing.T, dir string) {
	t.Helper()
	cfg := `sovereignty:
  network:
    default_egress: deny
    allow:
      - {host: smtp.example.org, purpose: notify.email}
notify:
  digest_at: "00:00"
  channels:
    - name: mail-perso
      type: email
      host: smtp.example.org
      port: 587
      from: michel@example.org
      to: [me@example.org]
      username: me
      password_secret: smtp-perso
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// loopReady, when set by a test, is what the loop of loopRun waits for (as serve
// makes it wait for the first round of the log scheduler).
var loopReady <-chan struct{}

// loopRun runs the digest loop of michel serve, with the clock at now, in a
// real command (store, audit and policy wired as for serve), until done says
// so or 20 seconds pass; it then stops the loop and waits for it to end.
func loopRun(t *testing.T, dir string, now time.Time, done func() bool) {
	t.Helper()
	loopRunClock(t, dir, func() time.Time { return now }, done)
}

// loopRunClock is loopRun with a clock the test can move.
func loopRunClock(t *testing.T, dir string, clock func() time.Time, done func() bool) {
	t.Helper()
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: clock}
	deps.LogsReady = loopReady
	t.Cleanup(func() { deps.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan struct{})
	cmd := NewRootCmd(deps)
	cmd.AddCommand(&cobra.Command{Use: "digestloop", RunE: func(c *cobra.Command, _ []string) error {
		runDigestLoop(ctx, c, deps, 20*time.Millisecond)
		close(ended)
		return nil
	}})
	cmd.SetArgs([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir, "digestloop"})
	execErr := make(chan error, 1)
	go func() { execErr <- cmd.ExecuteContext(ctx) }()
	deadline := time.Now().Add(20 * time.Second)
	for !done() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the digest loop did not stop with its context")
	}
	if err := <-execErr; err != nil {
		t.Fatalf("loop command: %v", err)
	}
}

// loopFor runs the loop for a while; the caller checks what it did.
func loopFor(t *testing.T, dir string, now time.Time, looks int) {
	t.Helper()
	ticks := countTicks(t)
	loopRun(t, dir, now, func() bool { return ticks.Load() >= int32(looks) })
}

// countTicks counts the looks of the digest loop through its test hook, so that
// a check that nothing was sent proves the loop did look.
func countTicks(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	old := digestTickHook
	digestTickHook = func() { n.Add(1) }
	t.Cleanup(func() { digestTickHook = old })
	return &n
}

// runsAudited is true once n digests were recorded in the audit log, that is
// once their send is over (a count of requests received is not).
func runsAudited(t *testing.T, dir string, n int) func() bool {
	return func() bool { return len(auditRows(t, dir, "digest.run")) >= n }
}

// tomorrowAt is a moment of the day after the real day (UTC), so that any
// digest the setup sent was sent "yesterday".
func tomorrowAt(h, m int) time.Time {
	d := time.Now().UTC().AddDate(0, 0, 1)
	return time.Date(d.Year(), d.Month(), d.Day(), h, m, 0, 0, time.UTC)
}

func TestDigestDueAtHour(t *testing.T) {
	paris := time.FixedZone("CEST", 2*3600)
	day := func(h, m int) time.Time { return time.Date(2026, 11, 3, h, m, 0, 0, paris) }
	sentAt := func(t time.Time) digest.Run { return digest.Run{CreatedAt: t, Until: t} }
	for _, c := range []struct {
		name    string
		last    digest.Run
		hasLast bool
		now     time.Time
		at      string
		want    bool
	}{
		{"before the hour", sentAt(day(8, 0).AddDate(0, 0, -1)), true, day(7, 59), "08:00", false},
		{"at the hour", sentAt(day(8, 0).AddDate(0, 0, -1)), true, day(8, 0), "08:00", true},
		{"after the hour", sentAt(day(8, 0).AddDate(0, 0, -1)), true, day(15, 30), "08:00", true},
		{"nothing sent yet", digest.Run{}, false, day(9, 0), "08:00", true},
		{"nothing sent yet, too early", digest.Run{}, false, day(7, 0), "08:00", false},
		{"once a day", sentAt(day(8, 1)), true, day(18, 0), "08:00", false},
		{"sent early this morning by the scheduled task", sentAt(day(6, 30)), true, day(9, 0), "08:00", false},
		{"sent late yesterday", sentAt(day(23, 50).AddDate(0, 0, -1)), true, day(8, 0), "08:00", true},
		{"the day is the local one", sentAt(time.Date(2026, 11, 2, 23, 30, 0, 0, time.UTC)), true, day(8, 30), "08:00", false},
		{"hour set by the user, too early", sentAt(day(8, 0).AddDate(0, 0, -1)), true, day(9, 29), "09:30", false},
		{"hour set by the user", sentAt(day(8, 0).AddDate(0, 0, -1)), true, day(9, 30), "09:30", true},
		{"midnight", sentAt(day(8, 0).AddDate(0, 0, -1)), true, day(0, 0), "00:00", true},
		{"off", sentAt(day(8, 0).AddDate(0, 0, -5)), true, day(12, 0), "off", false},
		{"off, nothing sent yet", digest.Run{}, false, day(12, 0), "off", false},
		{"default hour", sentAt(day(8, 0).AddDate(0, 0, -1)), true, day(8, 0), "", true},
	} {
		if got := digestDue(c.last, c.hasLast, c.now, c.at); got != c.want {
			t.Errorf("%s: digestDue = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDigestCatchesUpAfterStart(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	h := newHookRecorder(t)
	// A digest left yesterday (no channel then: it is only the mark).
	if _, _, _, err := run(t, dir, "digest", "--send"); err != nil {
		t.Fatal(err)
	}
	writeHookCfg(t, dir, h.URL, "")
	// serve starts at 14:00: the 08:00 digest was missed, it goes out now.
	loopRun(t, dir, tomorrowAt(14, 0), runsAudited(t, dir, 2))
	if h.count() != 1 {
		t.Fatalf("the webhook got %d digests", h.count())
	}
	runs := digestRuns(t, dir)
	if len(runs) != 2 || strings.Contains(runs[1].summary, "pending") {
		t.Fatalf("runs = %+v", runs)
	}
	var channels []map[string]string
	if err := json.Unmarshal([]byte(runs[1].channels), &channels); err != nil || len(channels) != 1 || channels[0]["result"] != "ok" {
		t.Errorf("channels = %s", runs[1].channels)
	}
	if rows := auditRows(t, dir, "digest.run"); len(rows) != 2 {
		t.Errorf("digest.run = %+v", rows)
	}
	// Later the same day, nothing more.
	before := h.count()
	loopFor(t, dir, tomorrowAt(16, 0), 3)
	if h.count() != before || len(digestRuns(t, dir)) != 2 {
		t.Errorf("a second digest left the same day: %d sends, %d runs", h.count(), len(digestRuns(t, dir)))
	}
}

func TestServeDigestWaitsForTheHour(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	h := newHookRecorder(t)
	writeHookCfg(t, dir, h.URL, "08:00")
	loopFor(t, dir, tomorrowAt(7, 30), 3)
	if h.count() != 0 || len(digestRuns(t, dir)) != 0 {
		t.Errorf("sent before 08:00: %d sends, %d runs", h.count(), len(digestRuns(t, dir)))
	}
	writeHookCfg(t, dir, h.URL, "off")
	loopFor(t, dir, tomorrowAt(15, 0), 3)
	if h.count() != 0 || len(digestRuns(t, dir)) != 0 {
		t.Errorf("sent with digest_at off: %d sends, %d runs", h.count(), len(digestRuns(t, dir)))
	}
	writeHookCfg(t, dir, h.URL, "09:30")
	loopFor(t, dir, tomorrowAt(9, 0), 3)
	if h.count() != 0 {
		t.Errorf("sent before the hour set by the user")
	}
	loopRun(t, dir, tomorrowAt(9, 30), runsAudited(t, dir, 1))
	if h.count() != 1 {
		t.Errorf("not sent at the hour set by the user: %d", h.count())
	}
}

// The window does not move when nobody got the digest: nothing is lost, and
// the same elements are in the next one.
func TestServeDigestKeepsWindowWithoutDelivery(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	h := newHookRecorder(t)

	// No channel at all: the loop does not even try.
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("notify:\n  channels: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loopFor(t, dir, time.Now(), 3)
	if len(digestRuns(t, dir)) != 0 || len(auditRows(t, dir, "digest.run")) != 0 {
		t.Fatalf("a run was recorded without any channel: %+v", digestRuns(t, dir))
	}

	// Every channel fails: attempted, audited, not recorded.
	writeFailingCfg(t, dir)
	loopRun(t, dir, time.Now(), func() bool { return len(auditRows(t, dir, "notify.send")) > 0 })
	if rows := auditRows(t, dir, "notify.send"); len(rows) != 1 || rows[0].result != "error" {
		t.Fatalf("notify.send = %+v", rows)
	}
	if runs := digestRuns(t, dir); len(runs) != 0 {
		t.Fatalf("a failed digest was recorded as sent: %+v", runs)
	}
	if rows := auditRows(t, dir, "digest.run"); len(rows) != 0 {
		t.Fatalf("digest.run = %+v", rows)
	}

	// The channel works again: the same three findings are in the digest.
	writeHookCfg(t, dir, h.URL, "00:00")
	loopRun(t, dir, time.Now(), runsAudited(t, dir, 1))
	if h.count() != 1 {
		t.Fatalf("webhook got %d", h.count())
	}
	var doc map[string]any
	if err := json.Unmarshal(h.bodies[0], &doc); err != nil || doc["new_total"] != float64(3) {
		t.Errorf("the findings were lost: %v %s", err, h.bodies[0])
	}
	if runs := digestRuns(t, dir); len(runs) != 1 {
		t.Errorf("runs = %+v", runs)
	}
}

// scan --digest does the same: with no channel the digest is printed, not
// recorded, and the next one still has everything.
func TestScanDigestKeepsWindowWithoutDelivery(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, out, errOut, err := run(t, dir, "--lang", "en", "scan", "--all", "--no-analyze", "--digest", "--osv-db", db)
	if err != nil || !strings.Contains(out, "== demo ==") {
		t.Fatalf("scan --digest: %v\n%s", err, out)
	}
	if !strings.Contains(errOut, "No channel is turned on") {
		t.Errorf("stderr does not say nobody got the digest:\n%s", errOut)
	}
	if runs := digestRuns(t, dir); len(runs) != 0 {
		t.Fatalf("a digest nobody got was recorded: %+v", runs)
	}
	writeFailingCfg(t, dir)
	_, out, errOut, err = run(t, dir, "--lang", "en", "scan", "--all", "--no-analyze", "--digest", "--osv-db", db)
	if err == nil || ExitCode(err) != 1 || !strings.Contains(out, "== demo ==") || !strings.Contains(errOut, "Nobody received the digest") {
		t.Fatalf("scan --digest with a failing channel: %v\n%s\n%s", err, out, errOut)
	}
	if runs := digestRuns(t, dir); len(runs) != 0 {
		t.Fatalf("a digest nobody got was recorded: %+v", runs)
	}
	h := newHookRecorder(t)
	writeHookCfg(t, dir, h.URL, "")
	if _, _, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--no-analyze", "--digest", "--osv-db", db); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if h.count() != 1 || json.Unmarshal(h.bodies[0], &doc) != nil || doc["new_total"] != float64(3) {
		t.Errorf("sends %d, body %s", h.count(), h.bodies)
	}
	if runs := digestRuns(t, dir); len(runs) != 1 {
		t.Errorf("runs = %+v", runs)
	}
}

// The serve loop and the scheduled task start at the same time, on the same
// record. Two commands, each with its own connection to the database, both
// reach the point just before the digest is claimed (the hook below holds
// each until the other is there), then claim together: one claim wins, the
// other sees it and sends nothing.
func TestServeAndScheduledTaskSendOnce(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--all", "--no-analyze", "--osv-db", db); err != nil {
		t.Fatal(err)
	}
	h := newHookRecorder(t)
	writeHookCfg(t, dir, h.URL, "00:00")

	var arrived atomic.Int32
	var bothHere sync.WaitGroup
	bothHere.Add(2)
	old := digestBeforeClaim
	digestBeforeClaim = func() {
		if arrived.Add(1) > 2 {
			return
		}
		bothHere.Done()
		waited := make(chan struct{})
		go func() { bothHere.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(20 * time.Second):
		}
	}
	t.Cleanup(func() { digestBeforeClaim = old })

	scheduled := make(chan error, 1)
	var scheduledEnded atomic.Bool
	go func() {
		_, _, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--no-analyze", "--digest", "--osv-db", db)
		scheduledEnded.Store(true)
		scheduled <- err
	}()
	// The loop is stopped only when the scheduled task is over and the claims
	// have had time to be sent: a second send must not be cut short.
	var settled time.Time
	loopRun(t, dir, time.Now(), func() bool {
		if arrived.Load() < 2 || !scheduledEnded.Load() {
			return false
		}
		if settled.IsZero() {
			settled = time.Now()
		}
		return time.Since(settled) > time.Second
	})
	if err := <-scheduled; err != nil {
		t.Fatalf("scheduled task: %v", err)
	}
	if n := arrived.Load(); n != 2 {
		t.Fatalf("%d of the 2 senders reached the claim: the race did not happen", n)
	}
	// A moment for a duplicate to show, if there were one.
	time.Sleep(200 * time.Millisecond)
	if h.count() != 1 {
		t.Errorf("the digest went out %d times", h.count())
	}
	runs := digestRuns(t, dir)
	if len(runs) != 1 || strings.Contains(runs[0].summary, "pending") {
		t.Errorf("runs = %+v", runs)
	}
	if rows := auditRows(t, dir, "digest.run"); len(rows) != 1 {
		t.Errorf("digest.run = %+v", rows)
	}
	if rows := auditRows(t, dir, "notify.send"); len(rows) != 1 {
		t.Errorf("notify.send = %+v", rows)
	}
}

func TestManualDigestStillSends(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	h := newHookRecorder(t)
	writeHookCfg(t, dir, h.URL, "")
	// Twice the same day: the manual command always sends, and the second
	// one starts where the first ended.
	for i := 0; i < 2; i++ {
		if _, _, _, err := run(t, dir, "digest", "--send"); err != nil {
			t.Fatal(err)
		}
	}
	if h.count() != 2 {
		t.Errorf("the webhook got %d digests", h.count())
	}
	runs := digestRuns(t, dir)
	if len(runs) != 2 || runs[1].since != runs[0].until {
		t.Errorf("runs = %+v", runs)
	}
	// Even when nobody gets it, as before: the run is the mark.
	writeFailingCfg(t, dir)
	if _, _, _, err := run(t, dir, "digest", "--send"); err == nil || ExitCode(err) != 1 {
		t.Errorf("failing channel: %v", err)
	}
	if runs := digestRuns(t, dir); len(runs) != 3 {
		t.Errorf("a manual digest was not recorded: %d runs", len(runs))
	}
}

// The line of the docs, run by the scheduled task, keeps working next to serve.
func TestExistingScheduledLineStillWorks(t *testing.T) {
	dir, db := t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	h := newHookRecorder(t)
	writeHookCfg(t, dir, h.URL, "")
	_, out, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--update", "--no-analyze", "--digest", "--osv-db", db)
	if err != nil {
		t.Fatalf("scan --all --update --digest: %v\n%s", err, out)
	}
	acts := auditActions(t, dir)
	read, start, sent := indexOf(acts, "source.read"), indexOf(acts, "scan.start"), indexOf(acts, "digest.run")
	if read < 0 || start < read || sent < start {
		t.Fatalf("order of the steps: %v", acts)
	}
	if !strings.Contains(out, "== demo ==") || h.count() != 1 {
		t.Errorf("sends %d\n%s", h.count(), out)
	}
	// The same line again, later the same day (serve already sent, or the
	// task runs twice): no second digest, and it is not an error.
	_, out, _, err = run(t, dir, "--lang", "en", "scan", "--all", "--update", "--no-analyze", "--digest", "--osv-db", db)
	if err != nil {
		t.Fatalf("second run: %v\n%s", err, out)
	}
	if h.count() != 1 || len(digestRuns(t, dir)) != 1 {
		t.Errorf("sends %d, runs %d", h.count(), len(digestRuns(t, dir)))
	}
	if !strings.Contains(out, "already sent a digest today") {
		t.Errorf("the skipped digest is not explained:\n%s", out)
	}
}

func TestServeStartsAndStopsDigestLoop(t *testing.T) {
	var started, stopped atomic.Int32
	ctxEnded := make(chan struct{})
	old := digestLoop
	digestLoop = func(ctx context.Context, cmd *cobra.Command, deps *Deps, every time.Duration) {
		started.Add(1)
		if every <= 0 || every > time.Minute {
			t.Errorf("the digest loop looks every %v", every)
		}
		<-ctx.Done()
		close(ctxEnded)
		stopped.Add(1)
	}
	t.Cleanup(func() { digestLoop = old })
	_, err := runServe(t, t.TempDir(), func(base *url.URL, _ string) {
		deadline := time.Now().Add(10 * time.Second)
		for started.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if started.Load() != 1 || stopped.Load() != 0 {
			t.Errorf("while serving: started %d, stopped %d", started.Load(), stopped.Load())
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctxEnded:
	default:
		t.Error("the loop context did not end")
	}
	if started.Load() != 1 || stopped.Load() != 1 {
		t.Errorf("after serve: started %d, stopped %d", started.Load(), stopped.Load())
	}
}

func writeCfgText(t *testing.T, dir, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Finding I1: a first digest that reaches nobody does not let the window slide
// with the clock; the elements of the first 24 hours are still in the digest
// sent more than 24 hours later.
func TestFirstWindowDoesNotSlideWithoutDelivery(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	writeFailingCfg(t, dir)
	loopRun(t, dir, time.Now(), func() bool { return len(auditRows(t, dir, "notify.send")) > 0 })
	if runs := digestRuns(t, dir); len(runs) != 0 {
		t.Fatalf("runs = %+v", runs)
	}
	h := newHookRecorder(t)
	writeHookCfg(t, dir, h.URL, "00:00")
	// Thirty hours on: a window of "the last 24 hours" would have lost them.
	loopRun(t, dir, time.Now().Add(30*time.Hour), runsAudited(t, dir, 1))
	var doc map[string]any
	if h.count() != 1 || json.Unmarshal(h.bodies[0], &doc) != nil || doc["new_total"] != float64(3) {
		t.Errorf("sends %d, body %s", h.count(), h.bodies)
	}
}

// Ruling R28: with an unscoped channel enabled, only an ok on it counts, because
// only it carries the server sections; with scoped channels alone, any ok counts.
func TestDeliveryNeedsAnUnscopedChannelWhenThereIsOne(t *testing.T) {
	dir, db := demoWithDB(t)
	h := newHookRecorder(t)
	both := "sovereignty:\n  network:\n    default_egress: deny\n    allow:\n      - {host: 127.0.0.1, purpose: notify.webhook}\n      - {host: smtp.example.org, purpose: notify.email}\n" +
		"notify:\n  digest_at: \"00:00\"\n  channels:\n    - name: hook\n      type: webhook\n      url: " + h.URL + "/michel\n      projects: [demo]\n" +
		"    - name: mail-perso\n      type: email\n      host: smtp.example.org\n      port: 587\n      from: michel@example.org\n      to: [me@example.org]\n      username: me\n      password_secret: smtp-perso\n"
	writeCfgText(t, dir, both)
	_, _, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--no-analyze", "--digest", "--osv-db", db)
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
	if h.count() != 1 || len(digestRuns(t, dir)) != 0 {
		t.Errorf("the scoped channel alone was taken for a delivery: %d sends, runs %+v", h.count(), digestRuns(t, dir))
	}
	only := strings.Split(both, "    - name: mail-perso")[0]
	writeCfgText(t, dir, only)
	if _, _, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--no-analyze", "--digest", "--osv-db", db); err != nil {
		t.Fatal(err)
	}
	if len(digestRuns(t, dir)) != 1 {
		t.Errorf("a digest delivered on the only (scoped) channel was not recorded: %+v", digestRuns(t, dir))
	}
}

// A manual digest nobody received does not count as the digest of the day.
func TestManualDigestNobodyGotDoesNotBlockTheScheduledOne(t *testing.T) {
	dir, db := demoWithDB(t)
	writeFailingCfg(t, dir)
	if _, _, _, err := run(t, dir, "digest", "--send"); err == nil {
		t.Fatal("a failing channel gave no error")
	}
	h := newHookRecorder(t)
	writeHookCfg(t, dir, h.URL, "")
	_, out, _, err := run(t, dir, "--lang", "en", "scan", "--all", "--no-analyze", "--digest", "--osv-db", db)
	if err != nil || strings.Contains(out, "already sent") || h.count() != 1 {
		t.Errorf("err %v, sends %d\n%s", err, h.count(), out)
	}
}

// Ruling R26: the first look at the digest waits for the first round of the log
// scheduler, at most digestLogWait.
func TestDigestWaitsForTheFirstLogRound(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	writeFailingCfg(t, dir)
	waiting, ticked := make(chan struct{}, 1), make(chan struct{}, 100)
	var ticks atomic.Int32
	oldW, oldT := digestWaitingHook, digestTickHook
	digestWaitingHook = func() { waiting <- struct{}{} }
	digestTickHook = func() { ticks.Add(1); ticked <- struct{}{} }
	t.Cleanup(func() { digestWaitingHook, digestTickHook, loopReady = oldW, oldT, nil })

	ready := make(chan struct{})
	loopReady = ready
	var checked sync.WaitGroup
	checked.Add(1)
	go func() {
		defer checked.Done()
		select {
		case <-waiting:
		case <-time.After(10 * time.Second):
			t.Error("the loop did not wait for the logs")
			close(ready)
			return
		}
		// The loop is blocked on the logs: no look has been made.
		if n := ticks.Load(); n != 0 {
			t.Errorf("%d looks before the first log round", n)
		}
		close(ready)
	}()
	first := true
	loopRun(t, dir, time.Now(), func() bool {
		select {
		case <-ticked:
			first = false
			return true
		default:
			return false
		}
	})
	checked.Wait()
	if first {
		t.Error("no look after the first log round")
	}

	// The wait is bounded: the logs never answer, the digest is looked at anyway.
	oldWait := digestLogWait
	digestLogWait = 20 * time.Millisecond
	t.Cleanup(func() { digestLogWait = oldWait })
	loopReady = make(chan struct{})
	for len(ticked) > 0 {
		<-ticked
	}
	got := false
	loopRun(t, dir, time.Now(), func() bool {
		select {
		case <-ticked:
			got = true
			return true
		default:
			return false
		}
	})
	if !got {
		t.Error("the wait for the logs is not bounded")
	}
}

// demoWithDB is a data folder with the project demo scanned, and the folder of
// the test databases (for the commands that scan again).
func demoWithDB(t *testing.T) (dir, db string) {
	t.Helper()
	dir, db = t.TempDir(), buildTestOSVDB(t)
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "scan", "--project", "demo", "--no-analyze", "--osv-db", db); err != nil {
		t.Fatal(err)
	}
	return dir, db
}

// Ruling R29 (finding N2): a digest held because the channels that carry the
// server sections failed is retried, but the channel that already got it gets
// no second copy the same local day; the next local day every channel gets it
// again. The clock is pinned: four tries span 48 minutes, so whether they stay
// in one day depends on the hour, and a test on the real clock failed each
// evening from 23:12 (three local days, three copies, as the ruling says).
func TestHeldDigestIsNotSentAgainToTheChannelsThatGotIt(t *testing.T) {
	// The copies seen after each try, written by hand: the tries come 16 minutes
	// apart, then the fifth comes 26 hours after the fourth.
	for _, c := range []struct {
		name string
		zone string
		at   [5]int // year, month, day, hour, minute
		want []int
	}{
		{"midday", "Europe/Paris", [5]int{2026, 11, 3, 12, 0}, []int{1, 1, 1, 1, 2}},
		{"last try at 23:59", "Europe/Paris", [5]int{2026, 11, 3, 23, 11}, []int{1, 1, 1, 1, 2}},
		{"last try at midnight", "Europe/Paris", [5]int{2026, 11, 3, 23, 12}, []int{1, 1, 1, 2, 3}},
		{"evening crosses midnight", "Europe/Paris", [5]int{2026, 11, 3, 23, 20}, []int{1, 1, 1, 2, 3}},
		{"crosses the UTC day only, Paris", "Europe/Paris", [5]int{2026, 11, 3, 0, 30}, []int{1, 1, 1, 1, 2}},
		{"crosses the UTC day only, Tokyo", "Asia/Tokyo", [5]int{2026, 11, 3, 8, 50}, []int{1, 1, 1, 1, 2}},
		{"crosses the UTC day only, Los Angeles", "America/Los_Angeles", [5]int{2026, 11, 3, 15, 50}, []int{1, 1, 1, 1, 2}},
		{"evening, Los Angeles", "America/Los_Angeles", [5]int{2026, 11, 3, 23, 30}, []int{1, 1, 2, 2, 3}},
		{"evening, Apia", "Pacific/Apia", [5]int{2026, 11, 3, 23, 50}, []int{1, 2, 2, 2, 3}},
		{"the hour after midnight does not exist", "America/Havana", [5]int{2026, 3, 7, 23, 30}, []int{1, 1, 2, 2, 3}},
		{"the clock goes back an hour", "Europe/Paris", [5]int{2026, 10, 25, 1, 50}, []int{1, 1, 1, 1, 2}},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := time.Date(c.at[0], time.Month(c.at[1]), c.at[2], c.at[3], c.at[4], 0, 0, loadZone(t, c.zone))
			got, _ := heldDigestCopies(t, base)
			if !slices.Equal(got, c.want) {
				t.Errorf("from %s, copies after each try = %v, want %v", base, got, c.want)
			}
		})
	}
	// Many hours, most of them around midnight where the day changes: a copy on
	// the first try of each local day, none on the others.
	for _, zone := range []string{"Europe/Paris", "Asia/Kathmandu", "America/New_York", "UTC"} {
		loc := loadZone(t, zone)
		midnight := time.Date(2026, 11, 4, 0, 0, 0, 0, loc)
		for _, minutes := range []int{-780, -49, -48, -32, -16, -1} {
			base := midnight.Add(time.Duration(minutes) * time.Minute)
			t.Run(zone+" "+base.Format("15:04"), func(t *testing.T) {
				got, tries := heldDigestCopies(t, base)
				want, day := 0, ""
				for i, at := range tries {
					if d := at.Format("2006-01-02"); d != day {
						want, day = want+1, d
					}
					if got[i] != want {
						t.Errorf("after the try of %s: %d copies, want %d (all: %v)", at, got[i], want, got)
					}
				}
			})
		}
	}
}

// loadZone returns a named time zone, from the data built into the test.
func loadZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// heldDigestCopies runs the loop of serve from base with a scoped webhook that
// answers and an unlimited mail that fails, so the digest stays held: four
// tries the first day (the clock moves 16 minutes after each), then one 26 hours
// later. It returns how many copies the webhook had after each try, and when
// each try was.
func heldDigestCopies(t *testing.T, base time.Time) (copies []int, tries []time.Time) {
	t.Helper()
	dir, _ := scannedDemo(t, false)
	h := newHookRecorder(t)
	writeCfgText(t, dir, "sovereignty:\n  network:\n    default_egress: deny\n    allow:\n      - {host: 127.0.0.1, purpose: notify.webhook}\n      - {host: smtp.example.org, purpose: notify.email}\n"+
		"notify:\n  digest_at: \"00:00\"\n  channels:\n    - name: hook\n      type: webhook\n      url: "+h.URL+"/michel\n      projects: [demo]\n"+
		"    - name: mail-perso\n      type: email\n      host: smtp.example.org\n      port: 587\n      from: michel@example.org\n      to: [me@example.org]\n      username: me\n      password_secret: smtp-perso\n")
	var offset atomic.Int64
	clock := func() time.Time { return base.Add(time.Duration(offset.Load())) }
	mailTries := func() int {
		n := 0
		for _, r := range auditRows(t, dir, "notify.send") {
			if r.target == "mail-perso" {
				n++
			}
		}
		return n
	}
	loopRunClock(t, dir, clock, func() bool {
		n := mailTries()
		if n > len(tries) {
			// The mail is audited once every channel was tried, and the next try
			// waits for the clock to move: this is the state after try n.
			tries = append(tries, clock())
			copies = append(copies, h.count())
			switch {
			case n < 4:
				offset.Add(int64(16 * time.Minute))
			case n == 4:
				offset.Add(int64(26 * time.Hour))
			}
		}
		return n >= 5
	})
	if n := mailTries(); n != 5 || len(tries) != 5 {
		t.Fatalf("mail tries = %d, seen %d", n, len(tries))
	}
	if runs := digestRuns(t, dir); len(runs) != 0 {
		t.Errorf("a held digest was recorded: %+v", runs)
	}
	return copies, tries
}

// Serve with no channel: the first window starts when serve first looked, it
// does not slide with the clock.
func TestServeWithoutChannelKeepsTheFirstWindow(t *testing.T) {
	dir, _ := scannedDemo(t, false)
	writeCfgText(t, dir, "notify:\n  digest_at: \"00:00\"\n  channels: []\n")
	ticks := countTicks(t)
	loopRun(t, dir, time.Now(), func() bool { return ticks.Load() >= 2 })
	h := newHookRecorder(t)
	writeHookCfg(t, dir, h.URL, "00:00")
	loopRun(t, dir, time.Now().Add(30*time.Hour), runsAudited(t, dir, 1))
	var doc map[string]any
	if h.count() != 1 || json.Unmarshal(h.bodies[0], &doc) != nil || doc["new_total"] != float64(3) {
		t.Errorf("sends %d, body %s", h.count(), h.bodies)
	}
}

// Real run: the digest sent as soon as the first log round ended left that round
// out (its period stops digest.LogReadLag before now), so the errors written
// while the computer was off waited for the next day. The look waits for the lag.
func TestDigestAfterTheFirstLogRoundWaitsForItToBeInThePeriod(t *testing.T) {
	if digestLagWait <= digest.LogReadLag {
		t.Errorf("the wait (%v) does not pass the lag of the period (%v)", digestLagWait, digest.LogReadLag)
	}
	dir, _ := scannedDemo(t, false)
	writeFailingCfg(t, dir)
	oldLag := digestLagWait
	digestLagWait = 400 * time.Millisecond
	ticked := make(chan time.Time, 100)
	oldT := digestTickHook
	digestTickHook = func() { ticked <- time.Now() }
	t.Cleanup(func() { digestTickHook, loopReady, digestLagWait = oldT, nil, oldLag })
	ready := make(chan struct{})
	close(ready)
	loopReady = ready
	start := time.Now()
	var first time.Time
	loopRun(t, dir, time.Now(), func() bool {
		select {
		case first = <-ticked:
			return true
		default:
			return false
		}
	})
	if first.IsZero() {
		t.Fatal("no look after the first log round")
	}
	if d := first.Sub(start); d < digestLagWait {
		t.Errorf("the look came %v after the round, before the lag of %v", d, digestLagWait)
	}
}
