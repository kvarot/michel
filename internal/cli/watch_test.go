package cli

import (
	"bytes"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/watch"
)

// runAt is run with the clock at now.
func runAt(t *testing.T, dir string, now time.Time, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: func() time.Time { return now }}
	t.Cleanup(func() { deps.Close() })
	cmd := NewRootCmd(deps)
	cmd.SetArgs(append([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir}, args...))
	err := cmd.Execute()
	deps.Close()
	return out.String(), err
}

func TestWatchStatusSaysNextPass(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"demo", "manual"} {
		if _, _, _, err := run(t, dir, "project", "add", t.TempDir(), "--name", n); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := run(t, dir, "project", "set", "manual", "--auto-scan=false"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 5, 8, 0, 0, 0, time.Local)
	out, err := runAt(t, dir, now, "--lang", "en", "watch", "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"every day at 07:00. Next pass: tomorrow at 07:00.", "only while michel serve is running"} {
		if !strings.Contains(out, want) {
			t.Errorf("out lacks %q:\n%s", want, out)
		}
	}
	lines := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines[f[0]] = l
		}
	}
	if l := lines["demo"]; !strings.Contains(l, "never") || !strings.Contains(l, "today at 07:00") {
		t.Errorf("demo line = %q", l)
	}
	if l := lines["manual"]; !strings.Contains(l, "watch off for this project") {
		t.Errorf("manual line = %q", l)
	}
	out, err = runAt(t, dir, time.Date(2026, 11, 5, 6, 0, 0, 0, time.Local), "--lang", "fr", "watch", "status")
	if err != nil || !strings.Contains(out, "chaque jour à 07:00. Prochain passage : aujourd'hui à 07:00.") ||
		!strings.Contains(out, "veille coupée pour ce projet") {
		t.Errorf("fr: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("watch:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runAt(t, dir, now, "--lang", "en", "watch", "status", "--json")
	if err != nil || !strings.Contains(out, `"enabled":false`) || !strings.Contains(out, `"next_scan_at":""`) {
		t.Errorf("json, watch off: %v\n%s", err, out)
	}
}

// michel serve watches by itself: the sources are read first (none has a
// consent here, so nothing goes out and the read says so), then the due
// project is checked offline, once.
func TestServeWatchScansDueProjects(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("watch:\n  scan_at: \"00:00\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(dir, "osv"), os.DirFS(buildTestOSVDB(t))); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "project", "add", copyProject(t, "project-a"), "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	oldLoop, oldTick := watchLoop, watchTick
	watchLoop, watchTick = watch.Loop, 20*time.Millisecond
	t.Cleanup(func() { watchLoop, watchTick = oldLoop, oldTick })
	scans := func() (n int, status string) {
		s, err := store.Open(filepath.Join(dir, "michel.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		err = s.DB().QueryRow(`SELECT COUNT(*), MAX(status) FROM scan`).Scan(&n, new(sql.NullString))
		if err != nil {
			t.Fatal(err)
		}
		_ = s.DB().QueryRow(`SELECT status FROM scan ORDER BY started_at DESC LIMIT 1`).Scan(&status)
		return n, status
	}
	out, err := runServe(t, dir, func(*url.URL, string) {
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			if n, status := scans(); n > 0 && status != "running" {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond) // a few more looks: nothing more is done
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, status := scans(); n != 1 || status != "ok" {
		t.Errorf("scans = %d, last %q", n, status)
	}
	if !strings.Contains(out, "Daily watch: Michel reads the enabled sources") || !strings.Contains(out, "waits for your consent") {
		t.Errorf("serve output:\n%s", out)
	}
}
