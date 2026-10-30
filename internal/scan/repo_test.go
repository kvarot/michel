package scan

import (
	"context"
	"testing"
	"time"
)

// applyExternal runs ApplyExternal in its own transaction.
func (e env) applyExternal(t *testing.T, sourceKey, runID string, findings []Finding) (newN, still, gone int) {
	t.Helper()
	ctx := context.Background()
	tx, err := e.st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	current, err := currentDecisions(ctx, tx, e.proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	newN, still, gone, _, err = ApplyExternal(ctx, tx, e.proj.ID, sourceKey, runID, time.Now(), findings, current)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return newN, still, gone
}

func codeFinding(projectID, sourceKey, rule, location string) Finding {
	return Finding{ID: FindingID(projectID, sourceKey, "", rule, location), ProjectID: projectID, Kind: "code",
		SourceKey: sourceKey, RuleID: rule, Location: location, SeverityLabel: "high", Summary: "m"}
}

func TestApplyExternalGoneLimitedToSourceKey(t *testing.T) {
	e := newEnv(t, "project-a")
	e.run(t)
	osv := e.statuses(t)
	if len(osv) == 0 {
		t.Fatal("no OSV finding to protect")
	}
	semgrep := codeFinding(e.proj.ID, "plugin.semgrep", "php.exec", "src/a.php:12")
	trivy := codeFinding(e.proj.ID, "plugin.trivy", "DS002", "Dockerfile:1")
	if n, _, gone := e.applyExternal(t, "plugin.semgrep", "run-1", []Finding{semgrep}); n != 1 || gone != 0 {
		t.Fatalf("semgrep run: new %d gone %d", n, gone)
	}
	if n, _, gone := e.applyExternal(t, "plugin.trivy", "run-2", []Finding{trivy}); n != 1 || gone != 0 {
		t.Fatalf("trivy run: new %d gone %d (the semgrep finding is not trivy's)", n, gone)
	}
	// An OSV scan leaves the plugin findings alone.
	if r := e.run(t); r.Gone != 0 {
		t.Errorf("the OSV scan closed %d plugin findings", r.Gone)
	}
	// A semgrep run without findings closes semgrep's only.
	if n, still, gone := e.applyExternal(t, "plugin.semgrep", "run-3", nil); n != 0 || still != 0 || gone != 1 {
		t.Errorf("empty semgrep run: new %d still %d gone %d", n, still, gone)
	}
	all, err := e.repo.ListFindings(context.Background(), e.proj.ID, "all")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		switch f.SourceKey {
		case "":
			if f.Status == StatusGone {
				t.Errorf("OSV finding %s moved to %s", f.OSVID, f.Status)
			}
		case "plugin.semgrep":
			if f.Status != StatusGone || f.RuleID != "php.exec" || f.Location != "src/a.php:12" || f.Kind != "code" {
				t.Errorf("semgrep finding = %+v", f)
			}
		case "plugin.trivy":
			if f.Status != StatusNew {
				t.Errorf("trivy finding = %+v", f)
			}
		}
	}
	// Back again: pending, like an OSV finding that reappears.
	if n, still, _ := e.applyExternal(t, "plugin.semgrep", "run-4", []Finding{semgrep}); n != 0 || still != 1 {
		t.Errorf("reappeared: new %d still %d", n, still)
	}
}
