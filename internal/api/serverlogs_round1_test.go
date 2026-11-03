package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/target"
)

// pass runs one read of the server, the way the scheduler does.
func (lf *logFixture) pass() (serverlog.PassResult, error) {
	d := serverlog.Deps{Repo: lf.repo(), Targets: target.NewRepo(lf.st), Audit: lf.log, SSH: lf.deps.Servers.Check.SSH, Now: lf.deps.Now}
	return serverlog.Pass(context.Background(), d, lf.id)
}

func (lf *logFixture) sources() []LogSourceView {
	lf.t.Helper()
	var list []LogSourceView
	lf.get(lf.url("/sources"), &list)
	return list
}

func (lf *logFixture) addPath(path, format string) LogSourceView {
	lf.t.Helper()
	code, out := lf.send("POST", lf.url("/sources"), `{"path":"`+path+`","format":"`+format+`"}`)
	if code != http.StatusCreated {
		lf.t.Fatalf("add source %s = %d %s", path, code, out)
	}
	var v LogSourceView
	_ = json.Unmarshal([]byte(out), &v)
	return v
}

func logTables(lf *logFixture) map[string]int {
	out := map[string]int{}
	for _, tb := range []string{"log_source", "log_signature", "log_cursor", "log_note", "log_bucket", "log_read", "log_settings", "log_unseen"} {
		out[tb] = lf.count(`SELECT COUNT(*) FROM ` + tb)
	}
	return out
}

// A source whose files cannot be opened says which and why, and its last read
// date does not move for a pass that opened nothing (I1).
func TestUnseenFilesAreListedWithTheirCause(t *testing.T) {
	lf := newLogFixture(t, "")
	later := filepath.Join(filepath.Dir(lf.file), "later.log")
	src := lf.addPath(shPath(later), "php")
	res, err := lf.pass()
	if err != nil || res.Unseen != 1 {
		t.Fatalf("pass = %+v %v", res, err)
	}
	list := lf.sources()
	if len(list) != 1 || list[0].ID != src.ID || len(list[0].Unseen) != 1 {
		t.Fatalf("sources = %+v", list)
	}
	u := list[0].Unseen[0]
	if u.What != shPath(later) || !strings.Contains(u.Reason, "does not exist") {
		t.Errorf("unseen = %+v", u)
	}
	if list[0].LastReadAt != "" {
		t.Errorf("a pass that opened nothing is no read: last_read_at = %q", list[0].LastReadAt)
	}
	for _, n := range list[0].Notes {
		if n.Kind == serverlog.NoteUnseen {
			t.Errorf("the count note duplicates the list: %+v", n)
		}
	}
	// Once the file exists, the list empties and the read date shows.
	if err := os.WriteFile(later, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lf.pass(); err != nil {
		t.Fatal(err)
	}
	list = lf.sources()
	if len(list[0].Unseen) != 0 || list[0].LastReadAt == "" {
		t.Errorf("after the file appeared: %+v", list[0])
	}
}

// A state note (too many files) stops showing once the last read no longer
// finds it; a fixed permission does not stay on the page.
func TestStateNotesStopShowingWhenTheyAreOver(t *testing.T) {
	lf := newLogFixture(t, "")
	src := lf.addSource("")
	ctx := context.Background()
	if err := lf.repo().SaveCursors(ctx, []serverlog.Cursor{{SourceID: src.ID, File: lf.path(), FileID: "1:2", Offset: 1, ReadAt: now}}); err != nil {
		t.Fatal(err)
	}
	add := func(to time.Time) {
		n := serverlog.Note{TargetID: lf.id, SourceID: src.ID, Kind: serverlog.NoteTooManyFiles, From: to, To: to}
		if err := lf.repo().AddNote(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	add(now.Add(-time.Hour))
	if n := lf.sources()[0].Notes; len(n) != 0 {
		t.Errorf("an old state note shows: %+v", n)
	}
	add(now)
	if n := lf.sources()[0].Notes; len(n) != 1 || n[0].Kind != serverlog.NoteTooManyFiles {
		t.Errorf("the current state note is missing: %+v", n)
	}
}

// Removing a server erases what Michel read in its logs (I2), audited; a read
// that runs holds everything back with a clear answer.
func TestRemovingAServerErasesItsLogData(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	lf.apply(pdoRecord)
	ign := pdoRecord
	ign.Type = "IgnoredException"
	lf.apply(ign)
	if err := lf.repo().SetStatus(context.Background(), serverlog.SignatureID(lf.sourceRow().ID, ign.Level, ign.Type, ign.Location, ign.Channel), serverlog.StatusIgnored); err != nil {
		t.Fatal(err)
	}
	// A read is running: nothing is erased and the answers say why.
	unlock, ok := serverlog.TryLock(lf.id)
	if !ok {
		t.Fatal("lock")
	}
	for _, r := range []struct{ method, path, body string }{
		{"DELETE", "/api/v1/targets/" + lf.id, ""},
		{"POST", lf.url("/purge"), "{}"},
		{"DELETE", lf.url("/sources/" + lf.sourceRow().ID), ""},
	} {
		if code, body := lf.send(r.method, r.path, r.body); code != http.StatusConflict {
			t.Errorf("%s %s while a read runs = %d %s", r.method, r.path, code, body)
		}
	}
	code, body := lf.send("PATCH", lf.url("/sources/"+lf.sourceRow().ID), `{"path":"/var/log/other.log"}`)
	if code != http.StatusConflict || !strings.Contains(body, "api.logs.busy") {
		t.Errorf("a path change while a read runs = %d %s", code, body)
	}
	if n := logTables(lf)["log_signature"]; n != 2 {
		t.Errorf("signatures after the refusals = %d", n)
	}
	unlock()

	if code, body := lf.send("DELETE", "/api/v1/targets/"+lf.id, ""); code != http.StatusOK || strings.Contains(body, "logs_not_erased") {
		t.Fatalf("remove = %d %s", code, body)
	}
	for tb, n := range logTables(lf) {
		if n != 0 {
			t.Errorf("%s holds %d rows after the server was removed", tb, n)
		}
	}
	var ev string
	_ = lf.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'log.purge' ORDER BY rowid DESC LIMIT 1`).Scan(&ev)
	if !strings.Contains(ev, `"scope":"server_removed"`) || strings.Contains(ev, "PDOException") {
		t.Errorf("audit = %s", ev)
	}
}

// What a try shows is what a read stores: same cleaner (the masker, the cap),
// and the records are those a real read made of the same file (I4).
func TestTryMatchesARealRead(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	if status, body := lf.send("PATCH", lf.url("/settings"), `{"store_text":true,"confirmed":true}`); status != http.StatusOK {
		t.Fatal(body)
	}
	if _, err := lf.pass(); err != nil { // the activation: the end of the empty file
		t.Fatal(err)
	}
	// The filter lets "password: hunter" through (no digit, no "="); the masker hides it.
	content := "PHP Fatal error:  Uncaught PDOException: Login failed password: hunter in /var/www/demo/src/Invoice.php:42\n" +
		"PHP Fatal error:  Uncaught PDOException: other in /var/www/demo/src/Invoice.php:42\n" +
		"PHP Warning:  Low disk in /var/www/demo/src/Mail.php on line 7\n"
	if err := os.WriteFile(lf.file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := lf.pass(); err != nil || res.Records != 2 {
		t.Fatalf("real read = %+v %v", res, err)
	}
	real := map[string]serverlog.Signature{}
	texts := map[string]string{}
	sigs, _ := lf.repo().Signatures(context.Background(), lf.id)
	for _, g := range sigs {
		key := string(g.Level) + "|" + g.Type + "|" + g.Location
		real[key] = g
		txt, ok, err := lf.repo().Text(context.Background(), g.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			texts[key] = txt
		}
	}
	status, body := lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`)
	var v LogTryView
	if status != http.StatusOK || json.Unmarshal([]byte(body), &v) != nil {
		t.Fatalf("try = %d %s", status, body)
	}
	if len(v.Records) != len(real) {
		t.Fatalf("try has %d records, the read stored %d: %+v", len(v.Records), len(real), v.Records)
	}
	nonce := regexp.MustCompile(`secret-[0-9a-f]{8}`)
	for _, r := range v.Records {
		key := r.Level + "|" + r.Type + "|" + r.Location
		g, ok := real[key]
		if !ok || g.Total != r.Count {
			t.Errorf("record %s: try %d, read %+v", key, r.Count, g)
		}
		if got, want := nonce.ReplaceAllString(r.Text, "secret-N"), nonce.ReplaceAllString(texts[key], "secret-N"); got != want {
			t.Errorf("record %s: try text %q, stored text %q", key, got, want)
		}
		if strings.Contains(r.Text, "hunter") {
			t.Errorf("the masker did not run on the try text: %q", r.Text)
		}
	}
	if !strings.Contains(body, "secret-") {
		t.Errorf("no masked value in the try answer: %s", body)
	}
}

// A try leaves one audit row, success or failure, that traces the read: the
// path (it is not a declared source), the format, the volume and the
// fingerprint, never a content (I5, R31).
func TestTryIsTracedInTheAudit(t *testing.T) {
	lf := newLogFixture(t, phpLines)
	if status, body := lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`); status != http.StatusOK {
		t.Fatal(body)
	}
	rows := func() []struct{ result, ev string } {
		q, err := lf.st.DB().Query(`SELECT result, evidence FROM audit_event WHERE action = 'log.read' ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		defer q.Close()
		var out []struct{ result, ev string }
		for q.Next() {
			var r struct{ result, ev string }
			if err := q.Scan(&r.result, &r.ev); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	got := rows()
	if len(got) != 1 || got[0].result != "ok" {
		t.Fatalf("audit after a try = %+v", got)
	}
	var ev map[string]any
	_ = json.Unmarshal([]byte(got[0].ev), &ev)
	fp, _ := ev["fingerprint"].(string)
	if ev["try"] != true || ev["path"] != lf.path() || ev["format"] != "php" || len(fp) != 64 || ev["volume"] == nil || ev["volume"].(float64) <= 0 ||
		ev["records"] != float64(2) || ev["occurrences"] != float64(3) || ev["to"] == nil {
		t.Errorf("evidence = %s", got[0].ev)
	}
	for _, leak := range []string{"RAWMARKER", "jean.dupont", "198.51.100.7", "Invoice.php", "PDOException"} {
		if strings.Contains(got[0].ev, leak) {
			t.Errorf("the audit holds %q: %s", leak, got[0].ev)
		}
	}
	// A failing try leaves its row, too, with the cause and nothing the server printed.
	lf.shell = nil
	if status, _ := lf.send("POST", lf.url("/sources/try"), `{"path":"`+lf.path()+`","format":"php"}`); status != http.StatusBadGateway {
		t.Fatalf("failing try = %d", status)
	}
	got = rows()
	if len(got) != 2 || got[1].result != "failed" || !strings.Contains(got[1].ev, `"try":true`) || !strings.Contains(got[1].ev, `"reason"`) ||
		!strings.Contains(got[1].ev, lf.path()) || strings.Contains(got[1].ev, "not supported") {
		t.Errorf("audit after a failing try = %+v", got)
	}
}

// A name that ssh would take for an option gives no command (I6).
func TestDetailCommandRefusesANameThatLooksLikeAnOption(t *testing.T) {
	src := serverlog.Source{Path: "/var/log/app.log", Format: serverlog.FormatMonolog}
	sig := serverlog.Signature{Level: serverlog.LevelError, LastAt: now}
	bad := target.Target{Alias: "-oProxyCommand=/tmp/x", Host: "192.0.2.10", User: "deploy"}
	if c := detailCommand(bad, src, sig); strings.Contains(c, "-oProxyCommand") || strings.HasPrefix(c, "ssh -o") {
		t.Errorf("alias: %s", c)
	}
	// With a good host the command stays, by host: the odd alias is just not used.
	if c := detailCommand(bad, src, sig); !strings.HasPrefix(c, "ssh deploy@192.0.2.10 ") {
		t.Errorf("fallback: %s", c)
	}
	for _, tg := range []target.Target{
		{Host: "192.0.2.10", User: "-oProxyCommand=x"},
		{Host: "-oProxyCommand=x", User: "deploy"},
		{Alias: "-F/tmp/cfg"},
	} {
		if c := detailCommand(tg, src, sig); c != "" {
			t.Errorf("%+v gave %q", tg, c)
		}
	}
}

// A path of this computer in a server text is replaced on every platform: the
// home, the temporary folder, the working folder, the data folder (I7).
func TestScrubPosteRemovesThePathsOfThisComputer(t *testing.T) {
	roots := []string{"/home/dev", "/srv/michel-data", "/tmp"}
	for in, want := range map[string]string{
		"/home/dev/projects/app/Invoice.php:42": "<path>",
		"at /tmp/TestX/001/demo/Invoice.php":    "at <path>",
		"read /srv/michel-data/michel.db now":   "read <path> now",
		"/tmpfs/keep.php:1":                     "/tmpfs/keep.php:1",
		"/var/www/app/keep.php:1":               "/var/www/app/keep.php:1",
		"/home/developer/keep.php":              "/home/developer/keep.php",
		"Invoice.php:42":                        "Invoice.php:42",
		"/home/dev":                             "<path>",
		`'/home/dev/x' and "/tmp/y"`:            `'<path>' and "<path>"`,
	} {
		if got := scrubPoste(in, roots); got != want {
			t.Errorf("scrubPoste(%q) = %q, want %q", in, got, want)
		}
	}
	got := posteRoots("/srv/extra")
	home, _ := os.UserHomeDir()
	has := func(p string) bool {
		for _, r := range got {
			if r == p {
				return true
			}
		}
		return false
	}
	if !has("/srv/extra") || (home != "" && len(home) >= 3 && !has(strings.TrimRight(home, `/\`))) || !has(strings.TrimRight(os.TempDir(), `/\`)) {
		t.Errorf("roots = %v", got)
	}
	// The same through the handler: the answer holds none of the folders.
	lf := newLogFixture(t, "")
	lf.addSource("")
	bad := pdoRecord
	bad.Location = filepath.ToSlash(os.TempDir()) + "/leak/Invoice.php:42"
	bad.Type = "Boom"
	home2 := serverlog.Record{Level: serverlog.LevelError, Type: "HomeBoom", Location: filepath.ToSlash(home) + "/work/Home.php:9", Hour: now, Count: 1}
	lf.apply(bad, home2)
	var listed LogErrorsView
	lf.get(lf.url("/errors"), &listed)
	// The fields of the errors, not the detail command: that one names the log file,
	// a path of the server the user declared.
	for _, e := range listed.Errors {
		for _, field := range []string{e.Type, e.Location, e.Channel, e.Text} {
			for _, leak := range []string{filepath.ToSlash(os.TempDir()), filepath.ToSlash(home) + "/work", "leak/Invoice"} {
				if strings.Contains(field, leak) {
					t.Errorf("a field holds %q: %+v", leak, e)
				}
			}
		}
	}
	if len(listed.Errors) != 2 {
		t.Fatalf("errors = %+v", listed)
	}
	if ServerText("deploy", filepath.ToSlash(os.TempDir())+"/x.php") != "<path>" {
		t.Errorf("ServerText keeps a path of this computer")
	}
}

// Changing the path of a source: the positions go in the same step, the audit
// says where it points now, and the errors read from the old file give no
// command on the new one.
func TestSourcePathChangeResetsPositionsAndOldErrorsGiveNoCommand(t *testing.T) {
	lf := newLogFixture(t, "")
	src := lf.addSource("")
	ctx := context.Background()
	old := pdoRecord
	if _, _, _, err := lf.repo().Apply(ctx, lf.sourceRow(), []serverlog.Record{old}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := lf.repo().SaveCursors(ctx, []serverlog.Cursor{{SourceID: src.ID, File: lf.path(), FileID: "1:2", Offset: 5, ReadAt: now}}); err != nil {
		t.Fatal(err)
	}
	if errs := lf.errorsList(); len(errs) != 1 || errs[0].Detail == "" {
		t.Fatalf("before: %+v", errs)
	}
	other := shPath(filepath.Join(filepath.Dir(lf.file), "other.log"))
	if code, body := lf.send("PATCH", lf.url("/sources/"+src.ID), `{"path":"`+other+`"}`); code != http.StatusOK {
		t.Fatalf("patch = %d %s", code, body)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_cursor`); n != 0 {
		t.Errorf("positions after a path change = %d", n)
	}
	if errs := lf.errorsList(); len(errs) != 1 || errs[0].Detail != "" {
		t.Errorf("an error of the old file gives a command on the new one: %+v", errs)
	}
	// Read again on the new file after the change: its command points there.
	if _, _, _, err := lf.repo().Apply(ctx, lf.sourceRow(), []serverlog.Record{old}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if errs := lf.errorsList(); len(errs) != 1 || !strings.Contains(errs[0].Detail, "other.log") {
		t.Errorf("after: %+v", errs)
	}
	var ev string
	_ = lf.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'log.source_update'`).Scan(&ev)
	if !strings.Contains(ev, other) {
		t.Errorf("the audit does not say the new path: %s", ev)
	}
	// Turned off then on again: a first read again.
	if err := lf.repo().SaveCursors(ctx, []serverlog.Cursor{{SourceID: src.ID, File: other, FileID: "1:2", Offset: 5, ReadAt: now}}); err != nil {
		t.Fatal(err)
	}
	lf.send("PATCH", lf.url("/sources/"+src.ID), `{"active":false}`)
	if n := lf.count(`SELECT COUNT(*) FROM log_cursor`); n != 1 {
		t.Errorf("turning a source off must keep the positions: %d", n)
	}
	lf.send("PATCH", lf.url("/sources/"+src.ID), `{"active":true}`)
	if n := lf.count(`SELECT COUNT(*) FROM log_cursor`); n != 0 {
		t.Errorf("turning it on again must start over: %d", n)
	}
}

// The list of errors says when it was cut (500 at most).
func TestErrorsSayWhenTheListWasCut(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	var recs []serverlog.Record
	for i := 0; i < maxLogErrors+3; i++ {
		recs = append(recs, serverlog.Record{Level: serverlog.LevelError, Type: fmt.Sprintf("Boom%d", i), Location: "A.php:1", Hour: now, Count: 1})
	}
	lf.apply(recs...)
	var v LogErrorsView
	lf.get(lf.url("/errors"), &v)
	if len(v.Errors) != maxLogErrors || v.Total != maxLogErrors+3 || !v.Truncated {
		t.Errorf("errors = %d total %d truncated %v", len(v.Errors), v.Total, v.Truncated)
	}
	lf.apply(recs[0])
	small := newLogFixture(t, "")
	small.addSource("")
	small.apply(pdoRecord)
	var s LogErrorsView
	small.get(small.url("/errors"), &s)
	if s.Truncated || s.Total != 1 {
		t.Errorf("small = %+v", s)
	}
}

// A PostgreSQL source added by hand carries the note about %e, too.
func TestPostgresNoteOnAManuallyAddedSource(t *testing.T) {
	lf := newLogFixture(t, "")
	code, body := lf.send("POST", lf.url("/sources"), `{"path":"/var/log/postgresql/postgresql-*.log","format":"postgres"}`)
	var v LogSourceView
	if code != http.StatusCreated || json.Unmarshal([]byte(body), &v) != nil || !strings.Contains(v.Note, "%e") {
		t.Fatalf("add = %d %s", code, body)
	}
	code, body = lf.send("PATCH", lf.url("/sources/"+v.ID), `{"format":"php"}`)
	var p LogSourceView
	if code != http.StatusOK || json.Unmarshal([]byte(body), &p) != nil || p.Note != "" {
		t.Errorf("a php source has no such note: %d %s", code, body)
	}
	code, body = lf.send("PATCH", lf.url("/sources/"+v.ID), `{"format":"postgres"}`)
	if code != http.StatusOK || !strings.Contains(body, "log_line_prefix") {
		t.Errorf("patched to postgres: %d %s", code, body)
	}
}

// A source or an error of another server is not found (404), whoever asks.
func TestSourceAndErrorOfAnotherServerAreNotFound(t *testing.T) {
	lf := newLogFixture(t, "")
	src := lf.addSource("")
	lf.apply(pdoRecord)
	sig := lf.errorsList()[0].ID
	code, body := lf.send("POST", "/api/v1/targets", `{"name":"other-demo","host":"192.0.2.30","user":"deploy"}`)
	var o TargetView
	if code != http.StatusCreated || json.Unmarshal([]byte(body), &o) != nil {
		t.Fatalf("add = %d %s", code, body)
	}
	base := "/api/v1/targets/" + o.ID + "/logs"
	for _, r := range []struct{ method, path, body string }{
		{"PATCH", base + "/sources/" + src.ID, `{"active":false}`},
		{"DELETE", base + "/sources/" + src.ID, ""},
		{"PATCH", base + "/errors/" + sig, `{"status":"ignored"}`},
	} {
		if code, body := lf.send(r.method, r.path, r.body); code != http.StatusNotFound {
			t.Errorf("%s %s = %d %s", r.method, r.path, code, body)
		}
	}
	if len(lf.sources()) != 1 || !lf.sourceRow().Active || lf.errorsList()[0].Status != "new" {
		t.Errorf("another server's call changed something")
	}
}

func TestSettingsSpikeBoundsAndRetentionStep(t *testing.T) {
	lf := newLogFixture(t, "")
	if st := lf.settings(); st.SpikeFactor != 10 || st.SpikeMin != 100 {
		t.Errorf("defaults = %+v", st)
	}
	code, body := lf.send("PATCH", lf.url("/settings"), `{"spike_factor":3,"spike_min":20}`)
	var v LogSettingsView
	if code != http.StatusOK || json.Unmarshal([]byte(body), &v) != nil || v.SpikeFactor != 3 || v.SpikeMin != 20 {
		t.Fatalf("spike = %d %s", code, body)
	}
	for _, bad := range []string{`{"spike_factor":1}`, `{"spike_min":0}`, `{"read_cap_bytes":99999999999}`, `{"read_timeout_seconds":3600}`} {
		if code, body := lf.send("PATCH", lf.url("/settings"), bad); code != http.StatusBadRequest || !strings.Contains(body, "api.logs.bad_settings") {
			t.Errorf("%s = %d %s", bad, code, body)
		}
	}
	// 100 days is a step away from 90; 365 is another one.
	if code, _ := lf.send("PATCH", lf.url("/settings"), `{"retention_days":100,"confirmed":true}`); code != http.StatusOK {
		t.Fatal(code)
	}
	code, body = lf.send("PATCH", lf.url("/settings"), `{"retention_days":365}`)
	var c LogConfirmBody
	if code != http.StatusConflict || json.Unmarshal([]byte(body), &c) != nil || len(c.Deviations) != 1 || c.Deviations[0].Code != "retention" {
		t.Errorf("100 to 365 without confirmation = %d %s", code, body)
	}
	if st := lf.settings(); st.RetentionDays != 100 {
		t.Errorf("retention = %d", st.RetentionDays)
	}
}

// An error written before Michel read it (a computer off overnight, a late read):
// the command looks for the date of the line, not the date of the read, or it
// would find nothing.
func TestDetailCommandLooksForTheDateOfTheLine(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	rec := pdoRecord
	rec.Hour = now.Add(-72 * time.Hour)
	lf.apply(rec)
	errs := lf.errorsList()
	if len(errs) != 1 {
		t.Fatalf("errors: %+v", errs)
	}
	lineDay := rec.Hour.UTC().Format("02-Jan-2006")
	if !strings.Contains(errs[0].Detail, lineDay) {
		t.Errorf("the command does not look for the day of the line (%s): %s", lineDay, errs[0].Detail)
	}
	if readDay := now.UTC().Format("02-Jan-2006"); strings.Contains(errs[0].Detail, readDay) {
		t.Errorf("the command looks for the day of the read (%s): %s", readDay, errs[0].Detail)
	}
}
