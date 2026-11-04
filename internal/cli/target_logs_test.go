package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// logEnv is a server of Michel with a log file behind a real sh.
type logEnv struct {
	*targetEnv
	file string
}

func logShPath(p string) string {
	p = filepath.ToSlash(p)
	if runtime.GOOS == "windows" && len(p) > 2 && p[1] == ':' {
		return "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

func newLogEnv(t *testing.T) *logEnv {
	t.Helper()
	for _, tool := range []string{"sh", "awk", "tail", "head", "tr", "ls", "wc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	e := &logEnv{targetEnv: newTargetEnv(t)}
	e.shell = func(_ *sshtest.Server, script string, stdout, stderr io.Writer) int {
		cmd := exec.Command("sh", "-s")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = os.Environ()
		cmd.Stdout, cmd.Stderr = stdout, stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return 126
		}
		return 0
	}
	e.file = filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(e.file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"target", "add", "srv-demo"}, {"target", "trust", "srv-demo", "--fingerprint", e.ssh.HostKeyFingerprint()}} {
		if _, _, _, err := run(t, e.dir, args...); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// withRepo runs f on the log repository of the data folder (no command runs
// meanwhile).
func (e *logEnv) withRepo(t *testing.T, f func(ctx context.Context, repo *serverlog.Repo, tg target.Target)) {
	t.Helper()
	s, err := store.Open(filepath.Join(e.dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tg, err := target.NewRepo(s).Get(context.Background(), "srv-demo")
	if err != nil {
		t.Fatal(err)
	}
	f(context.Background(), serverlog.NewRepo(s), tg)
}

func (e *logEnv) addSource(t *testing.T) serverlog.Source {
	t.Helper()
	var src serverlog.Source
	e.withRepo(t, func(ctx context.Context, repo *serverlog.Repo, tg target.Target) {
		var err error
		if src, err = repo.AddSource(ctx, serverlog.Source{TargetID: tg.ID, Path: logShPath(e.file), Format: serverlog.FormatPHP, Active: true}); err != nil {
			t.Fatal(err)
		}
	})
	return src
}

func (e *logEnv) append(t *testing.T, text string) {
	t.Helper()
	f, err := os.OpenFile(e.file, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func TestTargetLogsListShowsSourcesErrorsAndWarnings(t *testing.T) {
	e := newLogEnv(t)
	_, out, _, err := run(t, e.dir, "target", "logs", "list", "srv-demo")
	if err != nil || !strings.Contains(out, "No log source") {
		t.Fatalf("list without source: %q %v", out, err)
	}
	src := e.addSource(t)
	at := time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC)
	e.withRepo(t, func(ctx context.Context, repo *serverlog.Repo, tg target.Target) {
		recs := []serverlog.Record{
			{Level: serverlog.LevelCritical, Type: "PDOException", Location: "Invoice.php:42", Hour: at, Count: 37, Text: "Connection refused for <str>"},
			{Level: serverlog.LevelWarning, Location: "Mail.php:7", Hour: at, Count: 2},
		}
		if _, _, _, err := repo.Apply(ctx, src, recs, at); err != nil {
			t.Fatal(err)
		}
		if err := repo.SaveCursors(ctx, []serverlog.Cursor{{SourceID: src.ID, File: src.Path, FileID: "1:2", Offset: 5, ReadAt: at}}); err != nil {
			t.Fatal(err)
		}
	})
	_, out, _, err = run(t, e.dir, "target", "logs", "list", "srv-demo")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{src.ID, "php", logShPath(e.file), "2026-11-03T06:00:00Z", "PDOException", "Invoice.php:42", "37", "Mail.php:7", "new",
		"nobody will be told"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	// The text was never kept: the list shows none, whatever the file holds.
	if strings.Contains(out, "Connection refused") {
		t.Errorf("a text the settings do not keep:\n%s", out)
	}
	_, out, _, err = run(t, e.dir, "target", "logs", "list", "srv-demo", "--json")
	var v struct {
		NoChannel  bool
		Deviations []string
		Sources    []struct{ ID, Path, Format string }
		Errors     []struct {
			Level, Type, Location, Status string
			Total                         int64
			Text                          string
		}
	}
	if err != nil || json.Unmarshal([]byte(out), &v) != nil || !v.NoChannel || len(v.Sources) != 1 || len(v.Errors) != 2 || v.Deviations == nil || len(v.Deviations) != 0 {
		t.Fatalf("list --json: %q %v", out, err)
	}
	for _, g := range v.Errors {
		if g.Text != "" {
			t.Errorf("json text: %+v", g)
		}
	}
	// With the text kept, the list shows the cleaned text; the badge for the
	// setting away from the recommended choice shows too.
	e.withRepo(t, func(ctx context.Context, repo *serverlog.Repo, tg target.Target) {
		st, _ := repo.Settings(ctx, tg.ID)
		st.StoreText = true
		if err := repo.SaveSettings(ctx, st); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := repo.Apply(ctx, src, []serverlog.Record{{Level: serverlog.LevelCritical, Type: "PDOException", Location: "Invoice.php:42", Hour: at, Count: 1, Text: "Connection refused for <str>"}}, at); err != nil {
			t.Fatal(err)
		}
	})
	_, out, _, err = run(t, e.dir, "target", "logs", "list", "srv-demo")
	if err != nil || !strings.Contains(out, "Connection refused for <str>") || !strings.Contains(out, "store_text") {
		t.Errorf("list with text: %q %v", out, err)
	}
	if _, _, _, err := run(t, e.dir, "target", "logs", "list", "nope"); err == nil || !strings.Contains(err.Error(), "No server") {
		t.Errorf("unknown server: %v", err)
	}
}

func TestTargetLogsReadReadsOnce(t *testing.T) {
	e := newLogEnv(t)
	_, out, _, err := run(t, e.dir, "target", "logs", "read", "srv-demo")
	if err != nil || !strings.Contains(out, "no active log source") {
		t.Fatalf("read without source: %q %v", out, err)
	}
	e.addSource(t)
	// The first read of a source only locates the end of the file.
	if _, out, _, err = run(t, e.dir, "target", "logs", "read", "srv-demo"); err != nil || !strings.Contains(out, "0 groups of errors") {
		t.Fatalf("first read: %q %v", out, err)
	}
	e.append(t, "PHP Fatal error:  Uncaught PDOException: RAWMARKER jean.dupont@example.test in /var/www/demo/src/Invoice.php:42\n"+
		"PHP Fatal error:  Uncaught PDOException: RAWMARKER again in /var/www/demo/src/Invoice.php:42\n")
	_, out, errOut, err := run(t, e.dir, "target", "logs", "read", "srv-demo")
	if err != nil || !strings.Contains(out, "1 group of errors") {
		t.Fatalf("second read: %q %v", out, err)
	}
	for _, b := range []string{out, errOut} {
		if strings.Contains(b, "RAWMARKER") || strings.Contains(b, "jean.dupont") {
			t.Errorf("a log line reached the output: %s", b)
		}
	}
	_, out, _, err = run(t, e.dir, "target", "logs", "list", "srv-demo")
	if err != nil || !strings.Contains(out, "PDOException") || !strings.Contains(out, "Invoice.php:42") || strings.Contains(out, "RAWMARKER") {
		t.Errorf("list after the read: %q %v", out, err)
	}
	if rows := auditRows(t, e.dir, "log.read"); len(rows) != 2 || rows[0].result != "ok" {
		t.Errorf("audit log.read = %+v", rows)
	}
	for _, r := range auditRows(t, e.dir, "log.read") {
		b, _ := json.Marshal(r.evidence)
		if strings.Contains(string(b), "RAWMARKER") || strings.Contains(string(b), "PDOException") {
			t.Errorf("audit holds content: %s", b)
		}
	}
}

func TestTargetLogsReadFailureSaysWhyWithoutThePathOfTheAgent(t *testing.T) {
	e := newLogEnv(t)
	e.addSource(t)
	sock := filepath.Join(e.dir, "agent.sock")
	sshAgentWas := sshAgent
	t.Cleanup(func() { sshAgent = sshAgentWas })
	sshAgent = func(string) func() (agent.ExtendedAgent, io.Closer, error) {
		return func() (agent.ExtendedAgent, io.Closer, error) {
			return nil, nil, errors.New("dial unix " + sock + ": no such file")
		}
	}
	_, _, _, err := run(t, e.dir, "target", "logs", "read", "srv-demo")
	if err == nil || !strings.Contains(err.Error(), "SSH agent") || !strings.Contains(err.Error(), "ssh-add") || strings.Contains(err.Error(), sock) {
		t.Errorf("read without agent: %v", err)
	}
}

func TestTargetLogsSayWhyAFileWasNotRead(t *testing.T) {
	e := newLogEnv(t)
	missing := filepath.Join(filepath.Dir(e.file), "later.log")
	e.withRepo(t, func(ctx context.Context, repo *serverlog.Repo, tg target.Target) {
		if _, err := repo.AddSource(ctx, serverlog.Source{TargetID: tg.ID, Path: logShPath(missing), Format: serverlog.FormatPHP, Active: true}); err != nil {
			t.Fatal(err)
		}
	})
	_, out, _, err := run(t, e.dir, "target", "logs", "read", "srv-demo")
	if err != nil || !strings.Contains(out, "1 file could not be read") {
		t.Fatalf("read: %q %v", out, err)
	}
	_, out, _, err = run(t, e.dir, "target", "logs", "list", "srv-demo")
	if err != nil || !strings.Contains(out, "Not read: "+logShPath(missing)) || !strings.Contains(out, "does not exist") {
		t.Fatalf("list: %q %v", out, err)
	}
	_, out, _, err = run(t, e.dir, "target", "logs", "list", "srv-demo", "--json")
	var v struct {
		Sources []struct {
			LastRead string
			Unseen   []struct{ File, Cause, Reason string }
		}
	}
	if err != nil || json.Unmarshal([]byte(out), &v) != nil || len(v.Sources) != 1 || len(v.Sources[0].Unseen) != 1 || v.Sources[0].Unseen[0].Cause != "absent" ||
		!strings.HasPrefix(v.Sources[0].LastRead, "0001-") {
		t.Fatalf("list --json: %q %v", out, err)
	}
}

func TestTargetRemoveErasesWhatWasReadInTheLogs(t *testing.T) {
	e := newLogEnv(t)
	src := e.addSource(t)
	e.withRepo(t, func(ctx context.Context, repo *serverlog.Repo, tg target.Target) {
		if _, _, _, err := repo.Apply(ctx, src, []serverlog.Record{{Level: serverlog.LevelError, Type: "PDOException", Location: "Invoice.php:42", Hour: time.Now(), Count: 3}}, time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	_, out, _, err := run(t, e.dir, "target", "remove", "srv-demo")
	if err != nil || !strings.Contains(out, "erased") {
		t.Fatalf("remove: %q %v", out, err)
	}
	s, err := store.Open(filepath.Join(e.dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tb := range []string{"log_source", "log_signature", "log_bucket", "log_cursor", "log_note", "log_settings", "log_unseen"} {
		var n int
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM ` + tb).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s holds %d rows after the removal (%v)", tb, n, err)
		}
	}
	if rows := auditRows(t, e.dir, "log.purge"); len(rows) != 1 || rows[0].evidence["scope"] != "server_removed" {
		t.Errorf("audit log.purge = %+v", rows)
	}
}

func TestTargetLogsListScrubsLikeTheAPI(t *testing.T) {
	e := newLogEnv(t)
	src := e.addSource(t)
	bad := filepath.ToSlash(os.TempDir()) + "/leak/Invoice.php:42"
	e.withRepo(t, func(ctx context.Context, repo *serverlog.Repo, tg target.Target) {
		if _, _, _, err := repo.Apply(ctx, src, []serverlog.Record{{Level: serverlog.LevelError, Type: "Boom", Location: bad, Hour: time.Now(), Count: 1}}, time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	for _, args := range [][]string{{"target", "logs", "list", "srv-demo"}, {"target", "logs", "list", "srv-demo", "--json"}} {
		_, out, _, err := run(t, e.dir, args...)
		if err != nil || strings.Contains(out, "leak") || (!strings.Contains(out, "<path>") && !strings.Contains(out, "u003cpath")) {
			t.Errorf("%v: %q %v", args, out, err)
		}
	}
}

// If the logs of a server cannot be erased, the server is not removed and the
// command says so; the removal can be tried again.
func TestTargetRemoveKeepsTheServerWhenItsLogsCannotBeErased(t *testing.T) {
	e := newLogEnv(t)
	e.addSource(t)
	s, err := store.Open(filepath.Join(e.dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`DROP TABLE log_unseen`); err != nil { // makes the erasure fail
		t.Fatal(err)
	}
	s.Close()
	_, out, _, err := run(t, e.dir, "target", "remove", "srv-demo")
	if err == nil || !strings.Contains(err.Error(), "the server is not removed") || strings.Contains(out, "Removed server") || strings.Contains(err.Error(), "log_unseen") {
		t.Fatalf("remove: out %q err %v", out, err)
	}
	if _, err := targetByName(t, e.dir, "srv-demo"); err != nil {
		t.Errorf("the server is gone: %v", err)
	}
	if rows := auditRows(t, e.dir, "target.remove"); len(rows) != 0 {
		t.Errorf("a removal that did not happen is audited: %+v", rows)
	}
}

func TestTargetRemoveAuditSaysTheLogsWent(t *testing.T) {
	e := newLogEnv(t)
	e.addSource(t)
	if _, _, _, err := run(t, e.dir, "target", "remove", "srv-demo"); err != nil {
		t.Fatal(err)
	}
	rows := auditRows(t, e.dir, "target.remove")
	if len(rows) != 1 || rows[0].evidence["logs_error"] != false {
		t.Errorf("audit = %+v", rows)
	}
}

// The notes of a source show in the list, and the command to see more names
// the server.
func TestTargetLogsListShowsNotesAndReadNamesTheServer(t *testing.T) {
	e := newLogEnv(t)
	src := e.addSource(t)
	at := time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC)
	e.withRepo(t, func(ctx context.Context, repo *serverlog.Repo, tg target.Target) {
		if err := repo.SaveCursors(ctx, []serverlog.Cursor{{SourceID: src.ID, File: src.Path, FileID: "1:2", Offset: 5, ReadAt: at}}); err != nil {
			t.Fatal(err)
		}
		for _, n := range []serverlog.Note{
			{Kind: serverlog.NoteSkipped, From: at, To: at, Amount: 40 << 20},
			{Kind: serverlog.NoteRotated, From: at, To: at},
			{Kind: serverlog.NoteGap, From: at.Add(-5 * time.Hour), To: at.Add(-4 * time.Hour)},
		} {
			n.TargetID, n.SourceID = tg.ID, src.ID
			if err := repo.AddNote(ctx, n); err != nil {
				t.Fatal(err)
			}
		}
	})
	_, out, _, err := run(t, e.dir, "target", "logs", "list", "srv-demo")
	for _, want := range []string{"Source " + src.ID + ": Part of this log was not read (40 MiB)", "replaced or emptied", "could not read this log from"} {
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("list lacks %q: %q %v", want, out, err)
		}
	}
	// Reading a missing file: the hint names the server.
	e.withRepo(t, func(ctx context.Context, repo *serverlog.Repo, tg target.Target) {
		if err := repo.UpdateSource(ctx, serverlog.Source{ID: src.ID, TargetID: tg.ID, Path: logShPath(e.file) + ".gone", Format: serverlog.FormatPHP, Active: true}); err != nil {
			t.Fatal(err)
		}
	})
	_, out, _, err = run(t, e.dir, "target", "logs", "read", "srv-demo")
	if err != nil || !strings.Contains(out, "michel target logs list srv-demo") {
		t.Errorf("read: %q %v", out, err)
	}
}
