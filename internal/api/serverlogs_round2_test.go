package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/target"
)

// passAt is pass with the clock of the read set by hand.
func (lf *logFixture) passAt(at time.Time) (serverlog.PassResult, error) {
	d := serverlog.Deps{Repo: lf.repo(), Targets: target.NewRepo(lf.st), Audit: lf.log, SSH: lf.deps.Servers.Check.SSH, Now: func() time.Time { return at }}
	return serverlog.Pass(context.Background(), d, lf.id)
}

// A wildcard source that reads nothing today (its file is gone) shows the day
// it last read something, never the time of the pass that found nothing.
func TestWildcardSourceThatReadsNothingKeepsItsLastReadDate(t *testing.T) {
	lf := newLogFixture(t, "")
	dir := filepath.Dir(lf.file)
	file := filepath.Join(dir, "app-1.log")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	lf.addPath(shPath(dir)+"/app-*.log", "php")
	t0 := now.Add(-3 * time.Hour)
	if _, err := lf.passAt(t0); err != nil { // the activation
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("PHP Warning:  x in /var/www/demo/a.php on line 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(time.Hour)
	if res, err := lf.passAt(t1); err != nil || res.Records != 1 {
		t.Fatalf("the read = %+v %v", res, err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	t2 := t1.Add(time.Hour)
	res, err := lf.passAt(t2)
	if err != nil || res.Unseen != 1 {
		t.Fatalf("the pass that finds nothing = %+v %v", res, err)
	}
	list := lf.sources()
	if len(list) != 1 || len(list[0].Unseen) != 1 {
		t.Fatalf("sources = %+v", list)
	}
	if got := list[0].LastReadAt; got == stamp(t2) || got != stamp(t1) {
		t.Errorf("last_read_at = %s, want the read of %s, not the pass of %s", got, stamp(t1), stamp(t2))
	}
}

// The gap, skipped and rotated notes show with their sentence (the unseen
// files have their own list).
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
		{Kind: serverlog.NoteGap, From: now.Add(-5 * time.Hour), To: now.Add(-4 * time.Hour)},
	} {
		n.TargetID, n.SourceID = lf.id, src.ID
		if err := lf.repo().AddNote(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	list := lf.sources()
	if len(list) != 1 || list[0].LastReadAt != stamp(now.Add(-3*time.Minute)) || len(list[0].Notes) != 3 {
		t.Fatalf("sources = %+v", list)
	}
	byKind := map[string]LogNoteView{}
	for _, n := range list[0].Notes {
		if n.Text == "" {
			t.Errorf("note without a sentence: %+v", n)
		}
		byKind[n.Kind] = n
	}
	if !strings.Contains(byKind["skipped"].Text, "40 MiB") || !strings.Contains(byKind["gap"].Text, "could not read") || !strings.Contains(byKind["rotated"].Text, "replaced or emptied") {
		t.Errorf("notes = %+v", byKind)
	}
}

// If Michel cannot erase the logs of a server it does not remove the server:
// the server is still there, and the removal can be tried again (B1).
func TestServerStaysWhenItsLogsCannotBeErased(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	lf.apply(pdoRecord)
	if _, err := lf.st.DB().Exec(`DROP TABLE log_unseen`); err != nil { // makes the erasure fail
		t.Fatal(err)
	}
	code, body := lf.send("DELETE", "/api/v1/targets/"+lf.id, "")
	var e FixErrorBody
	if code != http.StatusInternalServerError || json.Unmarshal([]byte(body), &e) != nil || e.Code != "api.target.logs_failed" || e.Hint == "" {
		t.Fatalf("remove = %d %s", code, body)
	}
	if strings.Contains(body, "log_unseen") || strings.Contains(body, "SQL") {
		t.Errorf("the answer repeats the cause: %s", body)
	}
	if v := lf.view(lf.id); v.ID != lf.id {
		t.Errorf("the server is gone: %+v", v)
	}
	if n := lf.count(`SELECT COUNT(*) FROM log_signature`); n != 1 {
		t.Errorf("signatures = %d (a failed erasure must change nothing)", n)
	}
	if lf.auditCount("target.remove") != 0 {
		t.Errorf("a removal that did not happen is audited")
	}
}

// A removal that works says in its audit row that the logs went.
func TestRemovalAuditSaysTheLogsWentWithoutError(t *testing.T) {
	lf := newLogFixture(t, "")
	lf.addSource("")
	if code, body := lf.send("DELETE", "/api/v1/targets/"+lf.id, ""); code != http.StatusOK || strings.Contains(body, "logs_not_erased") {
		t.Fatalf("remove = %d %s", code, body)
	}
	var ev string
	_ = lf.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'target.remove'`).Scan(&ev)
	if !strings.Contains(ev, `"logs_error":false`) {
		t.Errorf("evidence = %s", ev)
	}
}

// A read that runs blocks the removal with the sentence about the read (B2 text).
func TestRemovalBlockedByAReadSaysSo(t *testing.T) {
	lf := newLogFixture(t, "")
	unlock, ok := serverlog.TryLock(lf.id)
	if !ok {
		t.Fatal("lock")
	}
	defer unlock()
	code, body := lf.send("DELETE", "/api/v1/targets/"+lf.id, "")
	if code != http.StatusConflict || !strings.Contains(body, "api.logs.busy") || strings.Contains(body, "api.target.busy") {
		t.Errorf("remove = %d %s", code, body)
	}
}

// The scrub leaves a server location that starts with the home sign alone, and
// the caller's extra folders count.
func TestScrubKeepsAHomeSignedLocationAndKnowsExtraFolders(t *testing.T) {
	if got := scrubPoste("~/tmp/cache/Invoice.php:42", []string{"/tmp"}); got != "~/tmp/cache/Invoice.php:42" {
		t.Errorf("scrubPoste mangled a location: %q", got)
	}
	if got := ServerText("deploy", "/srv/michel-data/db/x.db", "/srv/michel-data"); got != "<path>" {
		t.Errorf("ServerText ignores the extra folder: %q", got)
	}
	if got := ServerText("deploy", "/home/deploy/www/Invoice.php:42", "/srv/michel-data"); got != "~/www/Invoice.php:42" {
		t.Errorf("ServerText = %q", got)
	}
}
