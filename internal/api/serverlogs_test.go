package api

import (
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

// logFixture is a server on loopback whose `sh -s` is the real sh of this
// computer (the log filter really runs), pinned, with one log file.
type logFixture struct {
	*targetFixture
	id   string
	file string

	mu      sync.Mutex
	scripts []string
}

// shPath writes a local path the way the filter, a POSIX sh, names it.
func shPath(p string) string {
	p = filepath.ToSlash(p)
	if runtime.GOOS == "windows" && len(p) > 2 && p[1] == ':' {
		return "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

func needLogTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"sh", "awk", "tail", "head", "tr", "ls", "wc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

func newLogFixture(t *testing.T, content string, opts ...func(tf *targetFixture)) *logFixture {
	t.Helper()
	needLogTools(t)
	lf := &logFixture{targetFixture: newTargetFixture(t, opts...)}
	lf.shell = func(_ *sshtest.Server, script string, stdout, stderr io.Writer) int {
		lf.mu.Lock()
		lf.scripts = append(lf.scripts, script)
		lf.mu.Unlock()
		sh, err := exec.LookPath("sh")
		if err != nil {
			return 127
		}
		cmd := exec.Command(sh, "-s")
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
	lf.file = filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(lf.file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	v := lf.add("")
	lf.pin(v.ID)
	lf.id = v.ID
	return lf
}

func (lf *logFixture) url(suffix string) string {
	return "/api/v1/targets/" + lf.id + "/logs" + suffix
}

func (lf *logFixture) path() string { return shPath(lf.file) }

func (lf *logFixture) scriptsSent() int {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	return len(lf.scripts)
}

func (lf *logFixture) repo() *serverlog.Repo { return serverlog.NewRepo(lf.st) }

// addSource declares the log file as a PHP source through the API.
func (lf *logFixture) addSource(extra string) LogSourceView {
	lf.t.Helper()
	body := `{"path":"` + lf.path() + `","format":"php"`
	if extra != "" {
		body += "," + extra
	}
	code, out := lf.send("POST", lf.url("/sources"), body+"}")
	if code != http.StatusCreated {
		lf.t.Fatalf("add source = %d %s", code, out)
	}
	var v LogSourceView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		lf.t.Fatal(err)
	}
	return v
}

// sourceRow reads the source stored for the server.
func (lf *logFixture) sourceRow() serverlog.Source {
	lf.t.Helper()
	all, err := lf.repo().Sources(context.Background(), lf.id)
	if err != nil || len(all) != 1 {
		lf.t.Fatalf("sources = %v %v", all, err)
	}
	return all[0]
}

// apply stores records as a read of the first source would.
func (lf *logFixture) apply(recs ...serverlog.Record) {
	lf.t.Helper()
	if _, _, _, err := lf.repo().Apply(context.Background(), lf.sourceRow(), recs, now); err != nil {
		lf.t.Fatal(err)
	}
}

func (lf *logFixture) errorsList() []LogErrorView {
	lf.t.Helper()
	var list []LogErrorView
	lf.get(lf.url("/errors"), &list)
	return list
}

func (lf *logFixture) settings() LogSettingsView {
	lf.t.Helper()
	var v LogSettingsView
	lf.get(lf.url("/settings"), &v)
	return v
}

func (lf *logFixture) count(q string) int {
	lf.t.Helper()
	var n int
	if err := lf.st.DB().QueryRow(q).Scan(&n); err != nil {
		lf.t.Fatal(err)
	}
	return n
}

func (lf *logFixture) auditCount(action string) int {
	return lf.count(`SELECT COUNT(*) FROM audit_event WHERE action = '` + action + `'`)
}

var pdoRecord = serverlog.Record{Level: serverlog.LevelCritical, Type: "PDOException", Location: "Invoice.php:42", Hour: now.Truncate(time.Hour), Count: 37}

func TestLogsAPIRoundTrip(t *testing.T) {
	lf := newLogFixture(t, "")
	var empty []LogSourceView
	if body := lf.get(lf.url("/sources"), &empty); strings.TrimSpace(body) != "[]" {
		t.Errorf("no source yet = %s", body)
	}

	src := lf.addSource("")
	if src.ID == "" || src.Path != lf.path() || src.Format != "php" || !src.Active || src.LastReadAt != "" || src.Notes == nil {
		t.Errorf("added source = %+v", src)
	}
	var list []LogSourceView
	lf.get(lf.url("/sources"), &list)
	if len(list) != 1 || list[0].ID != src.ID {
		t.Fatalf("sources = %+v", list)
	}
	if code, body := lf.send("PATCH", lf.url("/sources/"+src.ID), `{"active":false}`); code != http.StatusOK || !strings.Contains(body, `"active":false`) {
		t.Errorf("deactivate = %d %s", code, body)
	}
	if code, body := lf.send("PATCH", lf.url("/sources/"+src.ID), `{"active":true,"format":"text","pattern":"ERROR|FATAL"}`); code != http.StatusOK ||
		!strings.Contains(body, `"format":"text"`) || !strings.Contains(body, `"active":true`) {
		t.Errorf("patch = %d %s", code, body)
	}
	if code, _ := lf.send("PATCH", lf.url("/sources/nope"), `{"active":true}`); code != http.StatusNotFound {
		t.Errorf("patch unknown source = %d", code)
	}

	// Two errors are in the database (the scheduler stores them).
	warn := pdoRecord
	warn.Level, warn.Type, warn.Location, warn.Count = serverlog.LevelWarning, "", "Mail.php:7", 2
	lf.apply(pdoRecord, warn)
	errs := lf.errorsList()
	if len(errs) != 2 {
		t.Fatalf("errors = %+v", errs)
	}
	var pdo LogErrorView
	for _, e := range errs {
		if e.Type == "PDOException" {
			pdo = e
		}
	}
	if pdo.ID == "" || pdo.Level != "critical" || pdo.Location != "Invoice.php:42" || pdo.Status != "new" || pdo.Total != 37 || pdo.SourceID != src.ID ||
		pdo.FirstAt == "" || pdo.LastAt == "" || pdo.Text != "" {
		t.Errorf("error = %+v", pdo)
	}
	for _, want := range []string{"seen", "ignored", "seen"} {
		code, body := lf.send("PATCH", lf.url("/errors/"+pdo.ID), `{"status":"`+want+`"}`)
		var v LogErrorView
		if code != http.StatusOK || json.Unmarshal([]byte(body), &v) != nil || v.Status != want {
			t.Errorf("status %s = %d %s", want, code, body)
		}
	}
	if code, _ := lf.send("PATCH", lf.url("/errors/"+pdo.ID), `{"status":"new"}`); code != http.StatusBadRequest {
		t.Errorf("a status the page cannot set = %d", code)
	}
	if code, _ := lf.send("PATCH", lf.url("/errors/"+strings.Repeat("a", 64)), `{"status":"seen"}`); code != http.StatusNotFound {
		t.Errorf("unknown error = %d", code)
	}

	st := lf.settings()
	if st.Interval != "5m" || st.StoreText || st.AlertText || st.RetentionDays != 90 || st.ResolveAfterDays != 7 || st.MaxAlertsPerHour != 10 || st.SMS ||
		st.ReadCapBytes != 5<<20 || st.ReadTimeoutSeconds != 30 || st.Routes["critical"] != "immediate" || st.Routes["error"] != "digest" ||
		st.Routes["warning"] != "ignored" || st.Deviations == nil || len(st.Deviations) != 0 || st.Recommended.RetentionDays != 90 {
		t.Errorf("default settings = %+v", st)
	}
	code, body := lf.send("PATCH", lf.url("/settings"), `{"interval":"manual","sms":true,"routes":{"error":"immediate"},"max_alerts_per_hour":3}`)
	var after LogSettingsView
	if code != http.StatusOK || json.Unmarshal([]byte(body), &after) != nil || after.Interval != "manual" || !after.SMS || after.Routes["error"] != "immediate" ||
		after.MaxAlertsPerHour != 3 || after.IntervalNote == "" {
		t.Fatalf("patch settings = %d %s", code, body)
	}
	if strings.Contains(body, "-1") {
		t.Errorf("the manual interval must read plainly: %s", body)
	}
	if stored, _ := lf.repo().Settings(context.Background(), lf.id); stored.Interval != serverlog.ManualInterval || !stored.SMS {
		t.Errorf("stored = %+v", stored)
	}
	if code, _ := lf.send("PATCH", lf.url("/settings"), `{"interval":"30s"}`); code != http.StatusBadRequest {
		t.Errorf("an interval under a minute = %d", code)
	}
	if code, _ := lf.send("PATCH", lf.url("/settings"), `{"routes":{"error":"loud"}}`); code != http.StatusBadRequest {
		t.Errorf("an unknown route = %d", code)
	}

	// Erasing wipes the errors, the ignored one too; the source stays.
	if code, body := lf.send("POST", lf.url("/purge"), `{}`); code != http.StatusOK {
		t.Fatalf("purge = %d %s", code, body)
	}
	if n := len(lf.errorsList()); n != 0 {
		t.Errorf("errors after the purge = %d", n)
	}
	lf.get(lf.url("/sources"), &list)
	if len(list) != 1 {
		t.Errorf("sources after the purge = %d", len(list))
	}
	if code, body := lf.send("DELETE", lf.url("/sources/"+src.ID), ""); code != http.StatusOK || !strings.Contains(body, `"removed":true`) {
		t.Errorf("delete = %d %s", code, body)
	}
	lf.get(lf.url("/sources"), &list)
	if len(list) != 0 {
		t.Errorf("sources after the delete = %d", len(list))
	}
	for action, want := range map[string]int{"log.source_add": 1, "log.source_remove": 1, "log.purge": 1, "log.settings": 1, "log.error_status": 3} {
		if n := lf.auditCount(action); n < want {
			t.Errorf("audit %s = %d, want at least %d", action, n, want)
		}
	}
	var ev string
	_ = lf.st.DB().QueryRow(`SELECT group_concat(evidence) FROM audit_event WHERE action LIKE 'log.%'`).Scan(&ev)
	for _, leak := range []string{"PDOException", "Invoice.php", "Mail.php"} {
		if strings.Contains(ev, leak) {
			t.Errorf("the audit of the log routes holds %q: %s", leak, ev)
		}
	}
}

func TestLogSourceRefusals(t *testing.T) {
	lf := newLogFixture(t, "")
	for _, tc := range []struct{ name, body string }{
		{"relative", `{"path":"logs/app.log","format":"php"}`},
		{"parent", `{"path":"/var/log/../etc/shadow","format":"php"}`},
		{"folder", `{"path":"/var/log/","format":"php"}`},
		{"format", `{"path":"/var/log/app.log","format":"xml"}`},
		{"json without field", `{"path":"/var/log/app.log","format":"json"}`},
	} {
		code, body := lf.send("POST", lf.url("/sources"), tc.body)
		if code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", tc.name, code, body)
		}
		if strings.Contains(body, "shadow") || strings.Contains(body, "/var/log") {
			t.Errorf("%s: the refusal repeats the path: %s", tc.name, body)
		}
	}
	lf.addSource("")
	if code, _ := lf.send("POST", lf.url("/sources"), `{"path":"`+lf.path()+`","format":"monolog"}`); code != http.StatusConflict {
		t.Errorf("the same file twice = %d", code)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_source`); n != 1 {
		t.Errorf("sources = %d", n)
	}
	if code, _ := lf.send("GET", "/api/v1/targets/nope/logs/sources", ""); code != http.StatusNotFound {
		t.Errorf("unknown server = %d", code)
	}
}

func TestSettingsDeviationNeedsConfirm(t *testing.T) {
	lf := newLogFixture(t, "")
	for _, tc := range []struct {
		name, body, code string
		check            func(s serverlog.Settings) bool
	}{
		{"store text", `{"store_text":true}`, "store_text", func(s serverlog.Settings) bool { return s.StoreText }},
		{"retention", `{"retention_days":30}`, "retention", func(s serverlog.Settings) bool { return s.RetentionDays == 30 }},
	} {
		audited := lf.auditCount("log.settings")
		status, body := lf.send("PATCH", lf.url("/settings"), tc.body)
		var c LogConfirmBody
		if status != http.StatusConflict || json.Unmarshal([]byte(body), &c) != nil || c.Code != "logs.confirm_needed" || c.Error == "" ||
			len(c.Deviations) != 1 || c.Deviations[0].Code != tc.code || c.Deviations[0].Text == "" || c.Health != "" {
			t.Fatalf("%s without confirmation = %d %s", tc.name, status, body)
		}
		if stored, _ := lf.repo().Settings(context.Background(), lf.id); tc.check(stored) {
			t.Errorf("%s: refused, yet saved", tc.name)
		}
		if n := lf.auditCount("log.settings"); n != audited {
			t.Errorf("%s: refused, yet audited as a change (%d events, %d before)", tc.name, n, audited)
		}
		if status, body := lf.send("PATCH", lf.url("/settings"), strings.TrimSuffix(tc.body, "}")+`,"confirmed":true}`); status != http.StatusOK {
			t.Fatalf("%s confirmed = %d %s", tc.name, status, body)
		}
		if stored, _ := lf.repo().Settings(context.Background(), lf.id); !tc.check(stored) {
			t.Errorf("%s: confirmed, not saved", tc.name)
		}
	}
	// The text of alerts: the text must be kept first, and it is a step again.
	if status, body := lf.send("PATCH", lf.url("/settings"), `{"alert_text":true}`); status != http.StatusConflict || !strings.Contains(body, "alert_text") {
		t.Errorf("alert text = %d %s", status, body)
	}
	st := lf.settings()
	if !st.StoreText || st.RetentionDays != 30 || len(st.Deviations) != 2 {
		t.Fatalf("settings = %+v", st)
	}
	if status, body := lf.send("PATCH", lf.url("/settings"), `{"alert_text":true,"confirmed":true}`); status != http.StatusOK {
		t.Fatalf("alert text confirmed = %d %s", status, body)
	}
	// Going back to the recommended choice needs no confirmation, and is audited.
	before := lf.auditCount("log.settings")
	if status, body := lf.send("PATCH", lf.url("/settings"), `{"store_text":false,"retention_days":90}`); status != http.StatusOK {
		t.Fatalf("back to recommended = %d %s", status, body)
	}
	back := lf.settings()
	if back.StoreText || back.AlertText || back.RetentionDays != 90 || len(back.Deviations) != 0 {
		t.Errorf("after going back = %+v", back)
	}
	if lf.auditCount("log.settings") != before+1 {
		t.Errorf("the return to the recommended choice is not audited")
	}

	// A health data server: the same confirmation, with the stronger warning,
	// and the user still has the last word.
	code, body := lf.send("POST", "/api/v1/targets", `{"name":"hds-demo","host":"192.0.2.20","user":"deploy","kind":"hds"}`)
	var h TargetView
	if code != http.StatusCreated || json.Unmarshal([]byte(body), &h) != nil || h.Classification != "health" {
		t.Fatalf("add hds = %d %s", code, body)
	}
	hurl := "/api/v1/targets/" + h.ID + "/logs/settings"
	status, body := lf.send("PATCH", hurl, `{"store_text":true}`)
	var c LogConfirmBody
	if status != http.StatusConflict || json.Unmarshal([]byte(body), &c) != nil || c.Code != "logs.confirm_needed" || c.Health == "" {
		t.Fatalf("hds without confirmation = %d %s", status, body)
	}
	if !strings.Contains(strings.ToLower(c.Health), "health") {
		t.Errorf("the hds warning does not name health data: %q", c.Health)
	}
	if status, body := lf.send("PATCH", hurl, `{"store_text":true,"confirmed":true}`); status != http.StatusOK {
		t.Fatalf("hds confirmed = %d %s", status, body)
	}
	var got LogSettingsView
	lf.get(hurl, &got)
	if !got.StoreText || got.Health == "" {
		t.Errorf("hds settings = %+v", got)
	}
	var ev string
	_ = lf.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'log.settings' AND target = ? ORDER BY rowid DESC LIMIT 1`, h.ID).Scan(&ev)
	if !strings.Contains(ev, `"health":true`) {
		t.Errorf("the audit does not say health: %s", ev)
	}
	// The list and the detail of servers carry the badge.
	var all []TargetView
	lf.get("/api/v1/targets", &all)
	for _, v := range all {
		want := v.ID == h.ID
		if got := len(v.LogDeviations) > 0; got != want {
			t.Errorf("%s: log_deviations = %v", v.Name, v.LogDeviations)
		}
		if want && (len(v.LogDeviations) != 1 || v.LogDeviations[0] != "store_text") {
			t.Errorf("%s: log_deviations = %v", v.Name, v.LogDeviations)
		}
	}
}

func TestSettingsTurningTextOffTurnsAlertTextOff(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.send("PATCH", lf.url("/settings"), `{"store_text":true,"alert_text":true,"confirmed":true}`)
	if status, body := lf.send("PATCH", lf.url("/settings"), `{"store_text":false}`); status != http.StatusOK {
		t.Fatalf("text off = %d %s", status, body)
	}
	if st := lf.settings(); st.StoreText || st.AlertText {
		t.Errorf("settings = %+v", st)
	}
}

// phpLines are PHP errors with personal data in the message: none may come back.
const phpLines = "PHP Fatal error:  Uncaught PDOException: RAWMARKER jean.dupont@example.test 198.51.100.7 in /var/www/demo/src/Invoice.php:42\n" +
	"PHP Fatal error:  Uncaught PDOException: RAWMARKER other in /var/www/demo/src/Invoice.php:42\n" +
	"PHP Warning:  RAWMARKER 1850175123456 in /var/www/demo/src/Mail.php on line 7\n"

func TestTryReturnsExactlyWhatWouldComeBack(t *testing.T) {
	lf := newLogFixture(t, phpLines)
	tables := []string{"log_source", "log_signature", "log_cursor", "log_note", "log_bucket", "log_read", "log_settings"}
	status, body := lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`)
	var v LogTryView
	if status != http.StatusOK || json.Unmarshal([]byte(body), &v) != nil {
		t.Fatalf("try = %d %s", status, body)
	}
	got := map[string]LogRecordView{}
	for _, r := range v.Records {
		got[r.Level+"|"+r.Type+"|"+r.Location] = r
	}
	pdo, warn := got["critical|PDOException|Invoice.php:42"], got["warning||Mail.php:7"]
	if len(v.Records) != 2 || pdo.Count != 2 || warn.Count != 1 || pdo.Text != "" || warn.Text != "" || v.Files != 1 || v.Rejected != 0 || v.Message != "" {
		t.Fatalf("records = %+v", v)
	}
	for _, leak := range []string{"RAWMARKER", "jean.dupont", "198.51.100.7", "1850175123456"} {
		if strings.Contains(body, leak) {
			t.Errorf("the try answer holds %q: %s", leak, body)
		}
	}
	if lf.scriptsSent() != 1 {
		t.Errorf("scripts sent = %d", lf.scriptsSent())
	}
	for _, tb := range tables {
		if n := lf.count(`SELECT COUNT(*) FROM ` + tb); n != 0 {
			t.Errorf("%s holds %d rows after a try", tb, n)
		}
	}
	// Trying again brings back the same: nothing moved.
	status, again := lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`)
	if status != http.StatusOK || again != body {
		t.Errorf("a second try differs:\n%s\n%s", body, again)
	}

	// Nothing comes back: Michel says so and proposes another format.
	status, body = lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"postgres"}`)
	var empty LogTryView
	if status != http.StatusOK || json.Unmarshal([]byte(body), &empty) != nil || len(empty.Records) != 0 || empty.Message == "" || empty.Records == nil {
		t.Errorf("empty try = %d %s", status, body)
	}
	// The PostgreSQL code of an error needs %e last in log_line_prefix: said here.
	if !strings.Contains(empty.Note, "%e") || !strings.Contains(empty.Note, "log_line_prefix") {
		t.Errorf("no word on %%e: %q", empty.Note)
	}
	if status, _ := lf.send("POST", lf.url("/sources/try"), `{"path":"relative.log","format":"php"}`); status != http.StatusBadRequest {
		t.Errorf("try with a relative path = %d", status)
	}
}

func TestTryListsUnseenFilesByPathAndReason(t *testing.T) {
	lf := newLogFixture(t, "")
	// The server answers as a filter does for a file it cannot open.
	lf.shell = func(_ *sshtest.Server, _ string, stdout, _ io.Writer) int {
		io.WriteString(stdout, "U\t"+lf.path()+"\n")
		return 0
	}
	status, body := lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`)
	var v LogTryView
	if status != http.StatusOK || json.Unmarshal([]byte(body), &v) != nil || len(v.Unseen) != 1 {
		t.Fatalf("try = %d %s", status, body)
	}
	if v.Unseen[0].What != lf.path() || !strings.Contains(v.Unseen[0].Reason, "adm") || strings.Contains(v.Unseen[0].Reason, "sudo ") {
		t.Errorf("unseen = %+v", v.Unseen)
	}
	// The same server failing: nothing of what it printed is repeated.
	lf.shell = func(_ *sshtest.Server, _ string, stdout, stderr io.Writer) int {
		io.WriteString(stderr, "awk: SECRET-MARKER jean.dupont@example.test\n")
		return 3
	}
	status, body = lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`)
	if status != http.StatusBadGateway || strings.Contains(body, "SECRET-MARKER") || strings.Contains(body, "jean.dupont") || !strings.Contains(body, "api.logs.try_failed") {
		t.Errorf("failed try = %d %s", status, body)
	}
}

func TestTryShowsTheCleanedTextOnlyWhenTheSettingsAllowIt(t *testing.T) {
	lf := newLogFixture(t, "PHP Fatal error:  Uncaught PDOException: Duplicate entry 'jean.dupont@example.test' for key 'email' in /var/www/demo/src/Invoice.php:42\n")
	try := func() LogTryView {
		status, body := lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`)
		var v LogTryView
		if status != http.StatusOK || json.Unmarshal([]byte(body), &v) != nil {
			t.Fatalf("try = %d %s", status, body)
		}
		if strings.Contains(body, "jean.dupont") {
			t.Errorf("the try answer holds an email: %s", body)
		}
		return v
	}
	if v := try(); len(v.Records) != 1 || v.Records[0].Text != "" {
		t.Errorf("default try = %+v", v)
	}
	if status, body := lf.send("PATCH", lf.url("/settings"), `{"store_text":true,"confirmed":true}`); status != http.StatusOK {
		t.Fatal(body)
	}
	v := try()
	if len(v.Records) != 1 || v.Records[0].Text == "" || strings.Contains(v.Records[0].Text, "Duplicate entry 'jean") {
		t.Errorf("try with text = %+v", v)
	}
}

func TestSourceDeleteTouchesNothingRemote(t *testing.T) {
	content := "PHP Warning:  x in /var/www/demo/a.php on line 3\n"
	lf := newLogFixture(t, content)
	src := lf.addSource("")
	lf.apply(pdoRecord)
	if err := lf.repo().SaveCursors(context.Background(), []serverlog.Cursor{{SourceID: src.ID, File: lf.path(), FileID: "1:2", Offset: 10, ReadAt: now}}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(lf.file)
	scripts, accepted, log := lf.scriptsSent(), lf.ssh.Accepted(), len(lf.ssh.Log())

	if code, body := lf.send("DELETE", lf.url("/sources/"+src.ID), ""); code != http.StatusOK {
		t.Fatalf("delete = %d %s", code, body)
	}
	if lf.scriptsSent() != scripts || lf.ssh.Accepted() != accepted || len(lf.ssh.Log()) != log {
		t.Errorf("the delete reached the server: scripts %d→%d, connections %d→%d", scripts, lf.scriptsSent(), accepted, lf.ssh.Accepted())
	}
	after, err := os.ReadFile(lf.file)
	info2, _ := os.Stat(lf.file)
	if err != nil || string(after) != content || !info2.ModTime().Equal(info.ModTime()) {
		t.Errorf("the log file changed: %q %v", after, err)
	}
	for _, tb := range []string{"log_source", "log_signature", "log_cursor", "log_bucket", "log_read"} {
		if n := lf.count(`SELECT COUNT(*) FROM ` + tb); n != 0 {
			t.Errorf("%s holds %d rows after the delete", tb, n)
		}
	}
	if code, _ := lf.send("DELETE", lf.url("/sources/"+src.ID), ""); code != http.StatusNotFound {
		t.Errorf("deleting twice = %d", code)
	}
}

func TestErrorsHaveDetailCommand(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	lf.apply(pdoRecord)
	errs := lf.errorsList()
	if len(errs) != 1 {
		t.Fatalf("errors = %+v", errs)
	}
	d := errs[0].Detail
	host, port, _ := strings.Cut(lf.ssh.Addr(), ":")
	for _, want := range []string{"ssh -p " + port + " deploy@" + host, "grep", lf.path(), "23-Oct-2026", "PDOException"} {
		if !strings.Contains(d, want) {
			t.Errorf("the command %q lacks %q", d, want)
		}
	}
	for _, bad := range []string{"sudo", ">", "rm ", "eval", "Invoice.php:42 in"} {
		if strings.Contains(d, bad) {
			t.Errorf("the command %q holds %q", d, bad)
		}
	}
}

func TestDetailCommandQuotesWhatItPrints(t *testing.T) {
	needLogTools(t)
	tg := target.Target{Host: "192.0.2.10", Port: 22, User: "deploy"}
	src := serverlog.Source{Path: "/var/log/my app/it's-*.log", Format: serverlog.FormatMonolog}
	// A type that is no identifier is no search word: it is left out.
	sig := serverlog.Signature{Type: "A'; rm -rf ~; '", Level: serverlog.LevelError, LastAt: now}
	cmd := detailCommand(tg, src, sig)
	if strings.Contains(cmd, "rm -rf") {
		t.Errorf("an injected command reached the command: %s", cmd)
	}
	// What the remote shell receives is one word; read it the way the local
	// shell does and check the wildcard stays a wildcard and the rest is quoted.
	word := strings.TrimPrefix(cmd, "ssh 192.0.2.10 ")
	word = strings.TrimPrefix(word, "ssh deploy@192.0.2.10 ")
	out, err := exec.Command("sh", "-c", "printf %s "+word).Output()
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	if want := `grep -a -h -F -e 2026-10-23 '/var/log/my app/it'\''s-'*.log | tail -n 50`; string(out) != want {
		t.Errorf("remote command = %s\nwant %s", out, want)
	}
	tg.Alias = "srv-demo"
	if c := detailCommand(tg, src, serverlog.Signature{LastAt: now}); !strings.HasPrefix(c, "ssh srv-demo ") {
		t.Errorf("alias command = %s", c)
	}
	phpSrc := serverlog.Source{Path: "/var/log/php.log", Format: serverlog.FormatPHP}
	if c := detailCommand(tg, phpSrc, serverlog.Signature{LastAt: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}); !strings.Contains(c, "02-Nov-2026") {
		t.Errorf("PHP date = %s", c)
	}
	// A host that is no host name gives no command at all.
	tg.Alias, tg.Host = "", "x; reboot"
	if c := detailCommand(tg, src, sig); c != "" {
		t.Errorf("odd host: %s", c)
	}
}

func TestErrorsNeverCarryAbsolutePosteOrRawLine(t *testing.T) {
	lf := newLogFixture(t, phpLines)
	lf.addSource("")
	// A record whose place or type holds a path of this computer, and a user's
	// home on the server: what the filter would have refused, in case a record
	// reaches the database some other way.
	poste := filepath.Join(t.TempDir(), "demo", "Invoice.php")
	bad := pdoRecord
	bad.Location = poste + ":42"
	bad.Type = `C:\Docs\demo\app\Boom`
	home := serverlog.Record{Level: serverlog.LevelError, Type: "HomeException", Location: "/home/deploy/www/demo/Home.php:9", Hour: now, Count: 1}
	lf.apply(bad, home)
	status, body := lf.send("GET", lf.url("/errors"), "")
	if status != http.StatusOK {
		t.Fatalf("errors = %d %s", status, body)
	}
	for _, leak := range []string{`C:\`, `C:/`, `Docs\demo`, "/home/deploy", filepath.ToSlash(filepath.Dir(poste)), "RAWMARKER", "jean.dupont", "198.51.100.7"} {
		if strings.Contains(body, leak) {
			t.Errorf("the errors answer holds %q: %s", leak, body)
		}
	}
	// A read, then the page: the personal data of the lines never shows.
	_, try := lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`)
	_, srcs := lf.send("GET", lf.url("/sources"), "")
	for _, b := range []string{try, srcs} {
		for _, leak := range []string{"RAWMARKER", "jean.dupont", "198.51.100.7", "1850175123456", `C:\`} {
			if strings.Contains(b, leak) {
				t.Errorf("an answer holds %q: %s", leak, b)
			}
		}
	}
}

func TestTextDecryptedOnlyWhenAllowed(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	ctx := context.Background()
	if status, body := lf.send("PATCH", lf.url("/settings"), `{"store_text":true,"confirmed":true}`); status != http.StatusOK {
		t.Fatal(body)
	}
	withText := pdoRecord
	withText.Text = "Connection refused for <str> on <addr>"
	lf.apply(withText)
	if n := lf.count(`SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 1 {
		t.Fatalf("text stored = %d", n)
	}
	var raw string
	_ = lf.st.DB().QueryRow(`SELECT text_enc FROM log_signature`).Scan(&raw)
	if strings.Contains(raw, "Connection refused") {
		t.Fatalf("the text is not encrypted at rest")
	}
	errs := lf.errorsList()
	if len(errs) != 1 || errs[0].Text != "Connection refused for <str> on <addr>" {
		t.Fatalf("errors with the text allowed = %+v", errs)
	}
	// The setting goes off by a path that does not erase (a stored text left
	// behind): the page still shows nothing.
	st, _ := lf.repo().Settings(ctx, lf.id)
	st.StoreText = false
	if err := lf.repo().SaveSettings(ctx, st); err != nil {
		t.Fatal(err)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 1 {
		t.Fatalf("text left = %d", n)
	}
	if errs := lf.errorsList(); len(errs) != 1 || errs[0].Text != "" {
		t.Errorf("errors with the text off = %+v", errs)
	}
	// Going back through the API erases it at once.
	lf.send("PATCH", lf.url("/settings"), `{"store_text":true,"confirmed":true}`)
	lf.apply(withText)
	if status, body := lf.send("PATCH", lf.url("/settings"), `{"store_text":false}`); status != http.StatusOK {
		t.Fatal(body)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 0 {
		t.Errorf("text left after going back = %d", n)
	}
	// The purge of the text alone.
	lf.send("PATCH", lf.url("/settings"), `{"store_text":true,"confirmed":true}`)
	lf.apply(withText)
	lf.send("PATCH", lf.url("/settings"), `{"store_text":false}`)
	lf.apply(withText)
	lf.send("PATCH", lf.url("/settings"), `{"store_text":true,"confirmed":true}`)
	lf.apply(withText)
	if status, body := lf.send("POST", lf.url("/purge"), `{"scope":"text"}`); status != http.StatusOK {
		t.Fatalf("purge text = %d %s", status, body)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_signature WHERE text_enc IS NOT NULL`); n != 0 {
		t.Errorf("text left after the text purge = %d", n)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_signature`); n != 1 {
		t.Errorf("the text purge must keep the errors: %d", n)
	}
	if status, _ := lf.send("POST", lf.url("/purge"), `{"scope":"everything"}`); status != http.StatusBadRequest {
		t.Errorf("unknown scope = %d", status)
	}
}

func TestPurgeIsAuditedWithoutContent(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	lf.apply(pdoRecord)
	if status, body := lf.send("POST", lf.url("/purge"), ""); status != http.StatusOK {
		t.Fatalf("purge = %d %s", status, body)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_signature`); n != 0 {
		t.Errorf("signatures = %d", n)
	}
	if lf.auditCount("log.purge") != 1 {
		t.Errorf("the purge is not audited")
	}
	var ev string
	_ = lf.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'log.purge'`).Scan(&ev)
	if strings.Contains(ev, "PDOException") || !strings.Contains(ev, `"scope":"all"`) {
		t.Errorf("audit = %s", ev)
	}
}

func TestNoChannelFlag(t *testing.T) {
	// No channel at all: activating a source stays possible, with a warning.
	lf := newLogFixture(t, "")
	if v := lf.view(lf.id); v.LogNoChannel || v.LogNew != 0 {
		t.Errorf("a server without a source = %+v", v)
	}
	src := lf.addSource("")
	if !src.NoChannel || src.Warning == "" || !strings.Contains(src.Warning, "nobody") {
		t.Errorf("activation with no channel = %+v", src)
	}
	if v := lf.view(lf.id); !v.LogNoChannel {
		t.Errorf("badge missing: %+v", v)
	}
	var all []TargetView
	lf.get("/api/v1/targets", &all)
	if len(all) != 1 || !all[0].LogNoChannel {
		t.Errorf("the list lacks the badge: %+v", all)
	}
	// A source turned off: nothing is read, nothing to warn about.
	code, body := lf.send("PATCH", lf.url("/sources/"+src.ID), `{"active":false}`)
	var off LogSourceView
	if code != http.StatusOK || json.Unmarshal([]byte(body), &off) != nil || off.NoChannel || off.Warning != "" {
		t.Errorf("deactivated = %d %s", code, body)
	}
	if v := lf.view(lf.id); v.LogNoChannel {
		t.Errorf("badge on a server that reads nothing: %+v", v)
	}
	// Turning it on again warns again.
	code, body = lf.send("PATCH", lf.url("/sources/"+src.ID), `{"active":true}`)
	var on LogSourceView
	if code != http.StatusOK || json.Unmarshal([]byte(body), &on) != nil || !on.NoChannel || on.Warning == "" {
		t.Errorf("reactivated = %d %s", code, body)
	}
	// An alert is "new" until seen.
	lf.apply(pdoRecord)
	if v := lf.view(lf.id); v.LogNew != 1 {
		t.Errorf("log_new = %d", v.LogNew)
	}

	// With a channel the warning goes.
	with := newLogFixture(t, "", withToast)
	if s := with.addSource(""); s.NoChannel || s.Warning != "" {
		t.Errorf("with a channel = %+v", s)
	}
	if v := with.view(with.id); v.LogNoChannel {
		t.Errorf("badge with a channel: %+v", v)
	}
}

// withToast puts a desktop notification channel in the policy file and in force.
func withToast(tf *targetFixture) {
	const yml = `notify:
  channels:
    - name: desk
      type: toast
`
	if err := os.WriteFile(tf.policyPath, []byte(yml), 0o600); err != nil {
		tf.t.Fatal(err)
	}
	p, _, err := policy.Load(tf.policyPath, tf.dir)
	if err != nil {
		tf.t.Fatal(err)
	}
	tf.deps.Policy = p
}

func TestLogChannelHearsServers(t *testing.T) {
	on, off := true, false
	toast := policy.ChannelConfig{Name: "desk", Type: "toast"}
	cases := []struct {
		name string
		ch   []policy.ChannelConfig
		sms  bool
		want bool
	}{
		{"none", nil, false, false},
		{"toast", []policy.ChannelConfig{toast}, false, true},
		{"disabled", []policy.ChannelConfig{{Name: "desk", Type: "toast", Enabled: &off}}, false, false},
		{"enabled", []policy.ChannelConfig{{Name: "desk", Type: "toast", Enabled: &on}}, false, true},
		{"limited to a project", []policy.ChannelConfig{{Name: "desk", Type: "toast", Projects: []string{"demo"}}}, false, false},
		{"sms off for the server", []policy.ChannelConfig{{Name: "phone", Type: "sms", Urgent: true}}, false, false},
		{"sms not urgent", []policy.ChannelConfig{{Name: "phone", Type: "sms"}}, true, false},
		{"sms ticked", []policy.ChannelConfig{{Name: "phone", Type: "sms", Urgent: true}}, true, true},
	}
	for _, c := range cases {
		p := policy.Defaults()
		p.Notify.Channels = c.ch
		if got := LogChannelHears(p, serverlog.Settings{SMS: c.sms}); got != c.want {
			t.Errorf("%s: hears = %v", c.name, got)
		}
	}
}

func TestDiscoverProposesAndCreatesNothing(t *testing.T) {
	lf := newLogFixture(t, "")
	status, body := lf.send("POST", lf.url("/sources/discover"), "")
	var cands []LogCandidateView
	if status != http.StatusOK || json.Unmarshal([]byte(body), &cands) != nil || len(cands) == 0 {
		t.Fatalf("discover = %d %s", status, body)
	}
	var pg *LogCandidateView
	for i, c := range cands {
		if c.Text == "" || c.Why == "" || c.Known {
			t.Errorf("candidate = %+v", c)
		}
		if c.Format == "postgres" {
			pg = &cands[i]
		}
	}
	if pg == nil || !strings.Contains(pg.Note, "%e") || !strings.Contains(pg.Note, "log_line_prefix") {
		t.Fatalf("no PostgreSQL proposal that explains %%e: %+v", cands)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_source`); n != 0 {
		t.Errorf("discover created %d sources", n)
	}
	// Once ticked, a proposal is known.
	lf.send("POST", lf.url("/sources"), `{"path":"`+pg.Path+`","format":"postgres"}`)
	_, body = lf.send("POST", lf.url("/sources/discover"), "")
	_ = json.Unmarshal([]byte(body), &cands)
	known := 0
	for _, c := range cands {
		if c.Known {
			known++
		}
	}
	if known != 1 {
		t.Errorf("known candidates = %d: %s", known, body)
	}
}

func TestSourcesShowWhatCouldNotBeRead(t *testing.T) {
	lf := newLogFixture(t, "")
	src := lf.addSource("")
	ctx := context.Background()
	if err := lf.repo().SaveCursors(ctx, []serverlog.Cursor{{SourceID: src.ID, File: lf.path(), FileID: "1:2", Offset: 1, ReadAt: now.Add(-3 * time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []serverlog.Note{
		{Kind: serverlog.NoteSkipped, From: now.Add(-time.Hour), To: now.Add(-time.Hour), Amount: 40 << 20},
		{Kind: serverlog.NoteRotated, From: now.Add(-2 * time.Hour), To: now.Add(-2 * time.Hour)},
		{Kind: serverlog.NoteUnseen, From: now.Add(-time.Hour), To: now, Amount: 2},
		{Kind: serverlog.NoteGap, From: now.Add(-5 * time.Hour), To: now.Add(-4 * time.Hour)},
	} {
		n.TargetID, n.SourceID = lf.id, src.ID
		if err := lf.repo().AddNote(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	var list []LogSourceView
	lf.get(lf.url("/sources"), &list)
	if len(list) != 1 || list[0].LastReadAt != stamp(now.Add(-3*time.Minute)) || len(list[0].Notes) != 4 {
		t.Fatalf("sources = %+v", list)
	}
	byKind := map[string]LogNoteView{}
	for _, n := range list[0].Notes {
		if n.Text == "" {
			t.Errorf("note without a sentence: %+v", n)
		}
		byKind[n.Kind] = n
	}
	if !strings.Contains(byKind["skipped"].Text, "40 MiB") {
		t.Errorf("the size left unread is not said: %q", byKind["skipped"].Text)
	}
}

func TestLogRoutesNeedToken(t *testing.T) {
	lf := newLogFixture(t, "")
	src := lf.addSource("")
	lf.apply(pdoRecord)
	routes := []struct{ method, path, body string }{
		{"GET", "/sources", ""}, {"POST", "/sources", `{"path":"/var/log/x.log","format":"php"}`},
		{"PATCH", "/sources/" + src.ID, `{"active":false}`}, {"DELETE", "/sources/" + src.ID, ""},
		{"POST", "/sources/discover", ""}, {"POST", "/sources/try", `{"path":"/var/log/x.log","format":"php"}`},
		{"GET", "/errors", ""}, {"PATCH", "/errors/" + strings.Repeat("a", 64), `{"status":"seen"}`},
		{"GET", "/settings", ""}, {"PATCH", "/settings", `{"sms":true}`}, {"POST", "/purge", ""},
	}
	for _, r := range routes {
		for _, tok := range []string{"", "wrong"} {
			resp, body := lf.do(r.method, lf.url(r.path), tok, r.body)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s token %q = %d", r.method, r.path, tok, resp.StatusCode)
			}
			for _, leak := range []string{"srv-demo", lf.id, "PDOException", lf.path()} {
				if strings.Contains(body, leak) {
					t.Errorf("%s %s: 401 leaks %q: %s", r.method, r.path, leak, body)
				}
			}
		}
	}
	if lf.scriptsSent() != 0 || lf.count(`SELECT COUNT(*) FROM log_source`) != 1 || lf.count(`SELECT COUNT(*) FROM log_signature`) != 1 {
		t.Errorf("unauthorized calls changed something")
	}
	if st := lf.settings(); st.SMS || st.Interval != "5m" {
		t.Errorf("settings changed by an unauthorized call: %+v", st)
	}
}

// No log data reaches an AI agent (spec § 3): the packages that talk to an
// agent or expose tools to one do not import the log packages.
func TestNoLogDataReachesAnAgent(t *testing.T) {
	root := filepath.Join("..")
	var checked int
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		rel := filepath.ToSlash(p)
		agentSide := strings.Contains(rel, "/mcp/") || strings.Contains(rel, "/fix/") || strings.Contains(rel, "/agent") || strings.Contains(rel, "/cli/mcp.go") ||
			strings.Contains(rel, "/cli/fix.go")
		if !agentSide {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, imp := range f.Imports {
			if path := strings.Trim(imp.Path.Value, `"`); strings.HasSuffix(path, "/internal/serverlog") {
				t.Errorf("%s imports the server log package", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no agent side file found: the check is broken")
	}
}
