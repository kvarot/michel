package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/serverlog"
	"github.com/kvarot/michel/internal/target"
)

func TestSourceFailureOwnCauseWinsAndGeneralOneIsHonest(t *testing.T) {
	lf := newLogFixture(t, "")
	src := lf.addSource("")
	ctx := context.Background()
	list := func() LogSourceView {
		t.Helper()
		code, out := lf.send("GET", lf.url("/sources"), "")
		var body []LogSourceView
		if code != http.StatusOK || json.Unmarshal([]byte(out), &body) != nil || len(body) != 1 {
			t.Fatalf("list = %d %s", code, out)
		}
		return body[0]
	}
	// Both rows kept: the source's own cause wins over the server's.
	if err := lf.repo().SetFailures(ctx, lf.id, []serverlog.Failure{{Reason: serverlog.ReasonRefused}, {SourceID: src.ID, Reason: serverlog.ReasonTools}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f := list().Failure; !strings.Contains(f, "awk") || strings.Contains(f, "refused") {
		t.Errorf("own cause did not win: %q", f)
	}
	// A source that failed on its own for no known reason: the server was reached.
	if err := lf.repo().SetFailures(ctx, lf.id, []serverlog.Failure{{SourceID: src.ID, Reason: serverlog.ReasonError}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f := list().Failure; !strings.Contains(f, "reached the server") || strings.Contains(f, "Check now") {
		t.Errorf("source general cause = %q", f)
	}
	// The connection failed for no known reason: the page sends to the check.
	if err := lf.repo().SetFailures(ctx, lf.id, []serverlog.Failure{{Reason: serverlog.ReasonError}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f := list().Failure; !strings.Contains(f, "Check now") {
		t.Errorf("server general cause = %q", f)
	}
	// A server turned off is not read and its button is disabled: no cause.
	tg, err := target.NewRepo(lf.st).Get(ctx, lf.id)
	if err != nil {
		t.Fatal(err)
	}
	tg.Active = false
	if err := target.NewRepo(lf.st).Update(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if f := list().Failure; f != "" {
		t.Errorf("a server turned off says %q", f)
	}
}

func TestUnseenIsFolderNeedsAWildcard(t *testing.T) {
	plain := serverlog.Source{Path: "/var/log/demo/app.log"}
	wild := serverlog.Source{Path: "/var/log/demo/*.log"}
	if UnseenIsFolder(plain, plain.Path) {
		t.Error("a plain path is a file")
	}
	if !UnseenIsFolder(wild, wild.Path) || UnseenIsFolder(wild, "/var/log/demo/a.log") {
		t.Error("only the pattern itself is the folder")
	}
}
