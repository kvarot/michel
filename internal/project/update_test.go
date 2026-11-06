package project

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func (f *regFixture) updateRows(t *testing.T) []regRow {
	t.Helper()
	rs, err := f.st.DB().Query(`SELECT actor, target, result, evidence FROM audit_event WHERE action = 'project.update' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []regRow
	for rs.Next() {
		var r regRow
		var ev string
		if err := rs.Scan(&r.actor, &r.target, &r.result, &ev); err != nil {
			t.Fatal(err)
		}
		r.evidence = map[string]any{}
		if err := json.Unmarshal([]byte(ev), &r.evidence); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestUpdateAuditsFromBothEntries(t *testing.T) {
	f := newRegFixture(t)
	if _, err := f.register("demo", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	three, yes := 3, true
	for _, actor := range []string{"cli", "page"} {
		p, err := Update(context.Background(), f.repo, f.log, UpdateRequest{Actor: actor, Name: "demo",
			Patch: Patch{FixLevel: &three, AutoFixMinor: &yes}})
		if err != nil || p.FixLevel != 3 || !p.AutoFixMinor {
			t.Fatalf("%s: %+v, %v", actor, p, err)
		}
	}
	rows := f.updateRows(t)
	if len(rows) != 2 || rows[0].actor != "cli" || rows[1].actor != "page" || rows[0].result != "ok" ||
		rows[0].target != "demo" || rows[0].evidence["fix_level"] != float64(3) || rows[0].evidence["auto_fix_minor"] != true {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestUpdateRefusalsAreAudited(t *testing.T) {
	f := newRegFixture(t)
	if _, err := f.register("demo", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	four := 4
	_, err := Update(ctx, f.repo, f.log, UpdateRequest{Actor: "page", Name: "demo", Patch: Patch{FixLevel: &four}})
	var re *RefusalError
	if !errors.As(err, &re) || re.Key != "api.project.patch.bad_level" || !errors.Is(err, ErrInvalidFixLevel) {
		t.Fatalf("bad level: %v", err)
	}
	if _, err = Update(ctx, f.repo, f.log, UpdateRequest{Actor: "page", Name: "demo"}); !errors.As(err, &re) || re.Key != "api.project.patch.nothing" {
		t.Fatalf("nothing: %v", err)
	}
	one := 1
	if _, err = Update(ctx, f.repo, f.log, UpdateRequest{Actor: "page", Name: "ghost", Patch: Patch{FixLevel: &one}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ghost: %v", err)
	}
	rows := f.updateRows(t)
	if len(rows) != 3 || rows[0].result != "denied" || rows[0].evidence["reason"] != "api.project.patch.bad_level" ||
		rows[1].result != "denied" || rows[2].result != "not_found" || rows[2].target != "ghost" || rows[2].evidence["reason"] != "api.project_not_found" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestUpdateRefusesInactiveUnlessAllowed(t *testing.T) {
	f := newRegFixture(t)
	if _, err := f.register("demo", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := f.repo.Remove(ctx, "demo"); err != nil {
		t.Fatal(err)
	}
	two := 2
	if _, err := Update(ctx, f.repo, f.log, UpdateRequest{Actor: "page", Name: "demo", Patch: Patch{FixLevel: &two}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed project changed by the page: %v", err)
	}
	if _, err := Update(ctx, f.repo, f.log, UpdateRequest{Actor: "cli", Name: "demo", AllowInactive: true, Patch: Patch{FixLevel: &two}}); err != nil {
		t.Fatalf("project set on a removed project: %v", err)
	}
}

func TestGetActiveHidesInactive(t *testing.T) {
	f := newRegFixture(t)
	ctx := context.Background()
	if _, err := f.register("demo", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if p, err := f.repo.GetActive(ctx, "demo"); err != nil || p.Name != "demo" {
		t.Fatalf("active: %+v, %v", p, err)
	}
	if _, err := f.repo.Remove(ctx, "demo"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.GetActive(ctx, "demo"); !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "demo") {
		t.Fatalf("removed: %v", err)
	}
	if _, err := f.repo.Get(ctx, "demo"); err != nil {
		t.Fatalf("Get must still see it: %v", err)
	}
}
