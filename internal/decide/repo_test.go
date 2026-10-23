package decide

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/store"
)

type fixture struct {
	st   *store.Store
	repo *Repo
	proj project.Project
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p, err := project.NewRepo(st).Add(context.Background(), project.Project{Name: "demo", Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{st: st, repo: NewRepo(st), proj: p}
}

// seedFinding inserts one finding of projectID with the given status,
// severity and fixed versions.
func (f fixture) seedFinding(t *testing.T, projectID, id, status, severity string, fixed ...string) {
	t.Helper()
	if fixed == nil {
		fixed = []string{}
	}
	fx, _ := json.Marshal(fixed)
	if _, err := f.st.DB().Exec(`INSERT INTO finding (id, project_id, manifest_rel_path, ecosystem, package, osv_id, severity_label,
		installed_version, fixed_versions, status, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at)
		VALUES (?, ?, 'composer.lock', 'Packagist', 'acme/lib', ?, ?, '1.0.0', ?, ?, 's1', 's1',
		'2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')`,
		id, projectID, "ACME-"+id, severity, string(fx), status); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) findingStatus(t *testing.T, id string) (status, changedAt string) {
	t.Helper()
	if err := f.st.DB().QueryRow(`SELECT status, status_changed_at FROM finding WHERE id = ?`, id).Scan(&status, &changedAt); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSetMovesFindingToDecided(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seedFinding(t, f.proj.ID, "f1", scan.StatusPending, "high", "1.2.5", "2.0.0")
	got, err := f.repo.Set(ctx, Decision{FindingID: "f1", Action: Fix, Author: "cli", Justification: " soon "}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.ProjectID != f.proj.ID || !got.CreatedAt.Equal(now) || got.Justification != "soon" ||
		got.SeenSeverity != "high" || len(got.SeenFixedVersions) != 2 || !got.SupersededAt.IsZero() {
		t.Errorf("stored decision = %+v", got)
	}
	if s, at := f.findingStatus(t, "f1"); s != scan.StatusDecided || at != now.Format(time.RFC3339) {
		t.Errorf("finding is %s since %s", s, at)
	}
	cur, ok, err := f.repo.Current(ctx, "f1")
	if err != nil || !ok || cur.ID != got.ID || cur.Action != Fix || cur.Author != "cli" || len(cur.SeenFixedVersions) != 2 {
		t.Errorf("Current = %+v %v %v", cur, ok, err)
	}
	if _, ok, err := f.repo.Current(ctx, "unknown"); ok || err != nil {
		t.Errorf("Current of an undecided finding: %v %v", ok, err)
	}
	if _, err := f.repo.Set(ctx, Decision{FindingID: "unknown", Action: Fix}, now); !errors.Is(err, ErrFindingNotFound) {
		t.Errorf("unknown finding: %v", err)
	}
	if _, err := f.repo.Set(ctx, Decision{FindingID: "f1", Action: Ignore}, now); !errors.Is(err, ErrJustificationRequired) {
		t.Errorf("Set does not validate: %v", err)
	}
}

func TestSetSupersedesPrevious(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seedFinding(t, f.proj.ID, "f1", scan.StatusNew, "high")
	first, err := f.repo.Set(ctx, Decision{FindingID: "f1", Action: Defer, Author: "cli"}, now)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	second, err := f.repo.Set(ctx, Decision{FindingID: "f1", Action: Ignore, Justification: "dev only", Author: "cli"}, later)
	if err != nil {
		t.Fatal(err)
	}
	all, err := f.repo.List(ctx, f.proj.ID, "all")
	if err != nil || len(all) != 2 || all[0].ID != second.ID || all[1].ID != first.ID {
		t.Fatalf("history = %+v %v", all, err)
	}
	if all[1].SupersededReason != Redecided || !all[1].SupersededAt.Equal(later) || !all[1].DueAt.Equal(now.Add(DefaultDefer)) {
		t.Errorf("first decision = %+v", all[1])
	}
	cur, ok, err := f.repo.Current(ctx, "f1")
	if err != nil || !ok || cur.ID != second.ID {
		t.Errorf("Current = %+v %v %v", cur, ok, err)
	}
	// The finding was already decided: its status did not change.
	if s, at := f.findingStatus(t, "f1"); s != scan.StatusDecided || at != now.Format(time.RFC3339) {
		t.Errorf("finding is %s since %s", s, at)
	}
}

func TestSetRefusesGoneFinding(t *testing.T) {
	f := newFixture(t)
	f.seedFinding(t, f.proj.ID, "f1", scan.StatusGone, "high")
	if _, err := f.repo.Set(context.Background(), Decision{FindingID: "f1", Action: Fix}, now); !errors.Is(err, ErrFindingGone) {
		t.Fatalf("err = %v", err)
	}
	if all, _ := f.repo.List(context.Background(), f.proj.ID, "all"); len(all) != 0 {
		t.Errorf("a decision was stored: %+v", all)
	}
	if s, _ := f.findingStatus(t, "f1"); s != scan.StatusGone {
		t.Errorf("status = %s", s)
	}
}

func TestExpireDue(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	other, err := project.NewRepo(f.st).Add(ctx, project.Project{Name: "other", Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f.seedFinding(t, f.proj.ID, "due", scan.StatusPending, "high")
	f.seedFinding(t, f.proj.ID, "future", scan.StatusPending, "high")
	f.seedFinding(t, f.proj.ID, "fixme", scan.StatusPending, "high")
	f.seedFinding(t, other.ID, "due-other", scan.StatusPending, "low")
	f.seedFinding(t, f.proj.ID, "due-gone", scan.StatusPending, "low")
	for _, d := range []Decision{
		{FindingID: "due", Action: Defer, DueAt: now.Add(time.Hour)},
		{FindingID: "future", Action: Defer, DueAt: now.Add(48 * time.Hour)},
		{FindingID: "fixme", Action: Fix},
		{FindingID: "due-other", Action: Defer, DueAt: now.Add(2 * time.Hour)},
		{FindingID: "due-gone", Action: Defer, DueAt: now.Add(time.Hour)},
	} {
		d.Author = "cli"
		if _, err := f.repo.Set(ctx, d, now); err != nil {
			t.Fatal(err)
		}
	}
	// A decided finding that disappeared keeps its decision: it describes
	// the past, and the scan checks the date if the finding comes back.
	if _, err := f.st.DB().Exec(`UPDATE finding SET status = 'gone' WHERE id = 'due-gone'`); err != nil {
		t.Fatal(err)
	}
	at := now.Add(2 * time.Hour) // due_at == now counts as reached
	log := audit.NewLogger(f.st, func() time.Time { return at })
	ids, err := f.repo.ExpireDue(ctx, at, log)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "due" || ids[1] != "due-other" {
		t.Fatalf("expired = %v", ids)
	}
	for id, want := range map[string]string{"due": scan.StatusPending, "due-other": scan.StatusPending, "future": scan.StatusDecided,
		"fixme": scan.StatusDecided, "due-gone": scan.StatusGone} {
		if s, _ := f.findingStatus(t, id); s != want {
			t.Errorf("%s is %s, want %s", id, s, want)
		}
	}
	if s, at2 := f.findingStatus(t, "due"); s != scan.StatusPending || at2 != at.Format(time.RFC3339) {
		t.Errorf("due is %s since %s", s, at2)
	}
	if _, ok, _ := f.repo.Current(ctx, "due"); ok {
		t.Error("the expired decision is still in force")
	}
	if _, ok, _ := f.repo.Current(ctx, "due-gone"); !ok {
		t.Error("the decision of a gone finding was superseded")
	}
	sup, _ := f.repo.List(ctx, f.proj.ID, "superseded")
	if len(sup) != 1 || sup[0].FindingID != "due" || sup[0].SupersededReason != DueReached || !sup[0].SupersededAt.Equal(at) {
		t.Errorf("superseded = %+v", sup)
	}
	rows, err := f.st.DB().Query(`SELECT actor, target, evidence FROM audit_event WHERE action = 'decision.superseded' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var actor, target, ev string
		if err := rows.Scan(&actor, &target, &ev); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(ev), &m)
		if n < len(ids) && (actor != "decide" || target != ids[n] || m["finding_id"] != ids[n] || m["reason"] != "due_reached" ||
			m["previous_action"] != "defer" || m["project_id"] == nil || m["project_id"] == "") {
			t.Errorf("event %d = %s %s %v", n, actor, target, m)
		}
		n++
	}
	if n != 2 {
		t.Errorf("%d decision.superseded events, want 2", n)
	}
	if again, err := f.repo.ExpireDue(ctx, at, nil); err != nil || len(again) != 0 {
		t.Errorf("second run = %v %v", again, err)
	}
}

func TestListFilters(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	other, _ := project.NewRepo(f.st).Add(ctx, project.Project{Name: "other", Path: t.TempDir()})
	for _, id := range []string{"a", "b", "c"} {
		f.seedFinding(t, f.proj.ID, id, scan.StatusPending, "high")
	}
	f.seedFinding(t, other.ID, "x", scan.StatusPending, "high")
	set := func(id string, a Action, at time.Time) {
		t.Helper()
		if _, err := f.repo.Set(ctx, Decision{FindingID: id, Action: a, Justification: "why", Author: "cli"}, at); err != nil {
			t.Fatal(err)
		}
	}
	set("a", Fix, now)
	set("b", Defer, now.Add(time.Minute))
	set("c", Ignore, now.Add(2*time.Minute))
	set("a", Ignore, now.Add(3*time.Minute)) // supersedes a/fix
	set("x", Fix, now)

	actions := func(filter string) []string {
		t.Helper()
		list, err := f.repo.List(ctx, f.proj.ID, filter)
		if err != nil {
			t.Fatalf("List(%q): %v", filter, err)
		}
		out := []string{}
		for _, d := range list {
			out = append(out, d.FindingID+"/"+string(d.Action))
		}
		return out
	}
	for filter, want := range map[string][]string{
		"":           {"a/ignore", "c/ignore", "b/defer"},
		"fix":        {},
		"defer":      {"b/defer"},
		"ignore":     {"a/ignore", "c/ignore"},
		"superseded": {"a/fix"},
		"all":        {"a/ignore", "c/ignore", "b/defer", "a/fix"},
	} {
		got := actions(filter)
		if len(got) != len(want) {
			t.Errorf("List(%q) = %v, want %v", filter, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("List(%q) = %v, want %v", filter, got, want)
				break
			}
		}
	}
	if _, err := f.repo.List(ctx, f.proj.ID, "later"); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("unknown filter: %v", err)
	}
	byProject, err := f.repo.CurrentByProject(ctx, f.proj.ID)
	if err != nil || len(byProject) != 3 || byProject["a"].Action != Ignore || byProject["x"].ID != "" {
		t.Errorf("CurrentByProject = %+v %v", byProject, err)
	}
}

func TestDecisionJSONHasSnakeCaseKeysAndEmptyTimes(t *testing.T) {
	b, err := json.Marshal(Decision{ID: "d1", FindingID: "f1", ProjectID: "p1", Action: Fix, Author: "cli", CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"id", "finding_id", "project_id", "action", "justification", "due_at", "author", "created_at",
		"seen_severity", "seen_fixed_versions", "superseded_at", "superseded_reason"} {
		if _, ok := m[k]; !ok {
			t.Errorf("key %q missing in %s", k, b)
		}
	}
	if len(m) != 12 {
		t.Errorf("unexpected keys in %s", b)
	}
	if m["due_at"] != "" || m["superseded_at"] != "" || m["created_at"] != "2026-10-23T09:30:00Z" {
		t.Errorf("times = %s", b)
	}
	if fv, ok := m["seen_fixed_versions"].([]any); !ok || len(fv) != 0 {
		t.Errorf("seen_fixed_versions = %v", m["seen_fixed_versions"])
	}
}
