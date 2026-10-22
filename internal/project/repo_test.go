package project

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/store"
)

func newRepo(t *testing.T) *Repo {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return NewRepo(s)
}

func TestAddRejectsMissingPath(t *testing.T) {
	r := newRepo(t)
	missing, _ := filepath.Abs(filepath.Join(t.TempDir(), "nope"))
	_, err := r.Add(context.Background(), Project{Name: "a", Path: missing})
	if !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("err = %v", err)
	}
	if _, err := r.Add(context.Background(), Project{Name: "a", Path: "relative/dir"}); !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("relative: err = %v", err)
	}
}

func TestAddRejectsFile(t *testing.T) {
	r := newRepo(t)
	f := filepath.Join(t.TempDir(), "f.txt")
	writeFile(t, f)
	if _, err := r.Add(context.Background(), Project{Name: "a", Path: f}); !errors.Is(err, ErrNotADirectory) {
		t.Fatalf("err = %v", err)
	}
}

func TestAddDefaults(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	p, err := r.Add(context.Background(), Project{Name: "shop", Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || p.SourceType != "local_path" || p.FixLevel != 1 || !p.Active ||
		p.Classification != policy.ClassSensitive || p.CreatedAt.IsZero() || p.Path != filepath.Clean(dir) {
		t.Errorf("p = %+v", p)
	}
	r.DefaultClassification = policy.ClassInternal
	q, err := r.Add(context.Background(), Project{Name: "two", Path: dir})
	if err != nil || q.Classification != policy.ClassInternal {
		t.Errorf("q = %+v err=%v", q, err)
	}
	got, err := r.Get(context.Background(), p.ID)
	if err != nil || got.Name != "shop" || got.CreatedAt.IsZero() {
		t.Errorf("got = %+v err=%v", got, err)
	}
}

func TestAddRejectsDuplicateName(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	if _, err := r.Add(context.Background(), Project{Name: "shop", Path: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(context.Background(), Project{Name: "shop", Path: dir}); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("err = %v", err)
	}
}

func TestAddValidation(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	ctx := context.Background()
	if _, err := r.Add(ctx, Project{Name: "", Path: dir}); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty name: %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "a", Path: dir, FixLevel: 4}); !errors.Is(err, ErrInvalidFixLevel) {
		t.Errorf("fix level 4: %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "a", Path: dir, FixLevel: -1}); !errors.Is(err, ErrInvalidFixLevel) {
		t.Errorf("fix level -1: %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "a", Path: dir, Classification: "secret"}); !errors.Is(err, ErrInvalidClassification) {
		t.Errorf("classification: %v", err)
	}
	if _, err := r.Add(ctx, Project{Name: "a", Path: dir, SourceType: "git"}); !errors.Is(err, ErrInvalidSourceType) {
		t.Errorf("source type: %v", err)
	}
	if l, _ := r.List(ctx); len(l) != 0 {
		t.Errorf("rows written on rejection: %v", l)
	}
}

func TestDuplicateNameRaceViaConstraint(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	ctx := context.Background()
	if _, err := r.Add(ctx, Project{Name: "shop", Path: dir}); err != nil {
		t.Fatal(err)
	}
	// Bypass the pre-check to prove the UNIQUE constraint maps to ErrDuplicateName.
	err := r.insert(ctx, Project{ID: "x", Name: "shop", SourceType: "local_path", Path: dir, Classification: policy.ClassPublic, Active: true})
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("err = %v", err)
	}
}

func TestListOrderedAndRemove(t *testing.T) {
	r := newRepo(t)
	dir := t.TempDir()
	ctx := context.Background()
	for _, n := range []string{"zeta", "alpha"} {
		if _, err := r.Add(ctx, Project{Name: n, Path: dir}); err != nil {
			t.Fatal(err)
		}
	}
	l, err := r.List(ctx)
	if err != nil || len(l) != 2 || l[0].Name != "alpha" {
		t.Fatalf("l=%v err=%v", l, err)
	}
	if err := r.Remove(ctx, "alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after remove: %v", err)
	}
	if err := r.Remove(ctx, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second remove: %v", err)
	}
}

func TestRemoveByID(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, _ := r.Add(ctx, Project{Name: "a", Path: t.TempDir()})
	if err := r.Remove(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAddExplicitFixLevelZero(t *testing.T) {
	r := newRepo(t)
	p, err := r.Add(context.Background(), Project{Name: "a", Path: t.TempDir(), FixLevel: 0, FixLevelSet: true})
	if err != nil || p.FixLevel != 0 {
		t.Fatalf("p=%+v err=%v", p, err)
	}
}
