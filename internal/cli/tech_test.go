package cli

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/store"
)

func TestTechAddListRemove(t *testing.T) {
	dir := t.TempDir()
	for _, tag := range []string{"nginx", "postgresql"} {
		if _, _, _, err := run(t, dir, "tech", "add", tag); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := run(t, dir, "tech", "add", "Nginx!"); err == nil || !strings.Contains(err.Error(), "Nginx!") {
		t.Errorf("invalid tag: %v", err)
	}
	_, out, _, err := run(t, dir, "tech", "list")
	if err != nil || out != "nginx\npostgresql\n" {
		t.Errorf("list = %q err %v", out, err)
	}
	if _, _, _, err := run(t, dir, "tech", "remove", "nginx"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := run(t, dir, "tech", "remove", "postgresql"); err != nil {
		t.Fatal(err)
	}
	_, out, _, err = run(t, dir, "tech", "list")
	if err != nil || !strings.HasPrefix(out, "No technology declared") {
		t.Errorf("empty list = %q err %v", out, err)
	}
	_, out, _, err = run(t, dir, "tech", "list", "--json")
	if err != nil || strings.TrimSpace(out) != "[]" {
		t.Errorf("json = %q err %v", out, err)
	}
	ev := auditRows(t, dir, "tech.set")
	if len(ev) != 4 || ev[0].target != "nginx" || ev[0].evidence["action"] != "add" || ev[3].evidence["action"] != "remove" {
		t.Errorf("tech.set events = %+v", ev)
	}
}

func TestProjectSetTech(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "demo", "--tech", "symfony"); err != nil {
		t.Fatal(err)
	}
	tech := func() []string {
		t.Helper()
		s, err := store.Open(filepath.Join(dir, "michel.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		p, err := project.NewRepo(s).Get(context.Background(), "demo")
		if err != nil {
			t.Fatal(err)
		}
		return p.Tech
	}
	if got := tech(); !reflect.DeepEqual(got, []string{"symfony"}) {
		t.Errorf("after add: %v", got)
	}
	if _, _, _, err := run(t, dir, "project", "set", "demo", "--tech", "php", "--tech", "nginx"); err != nil {
		t.Fatal(err)
	}
	if got := tech(); !reflect.DeepEqual(got, []string{"nginx", "php"}) {
		t.Errorf("after set: %v", got)
	}
	if _, _, _, err := run(t, dir, "project", "set", "demo", "--tech", "Bad Tag"); err == nil {
		t.Error("an invalid tag was accepted")
	}
	if _, _, _, err := run(t, dir, "project", "set", "demo", "--tech", ""); err != nil {
		t.Fatal(err)
	}
	if got := tech(); len(got) != 0 {
		t.Errorf("after clearing: %v", got)
	}
	ev := auditRows(t, dir, "project.set")
	if len(ev) != 3 || ev[0].evidence["tech"] == nil {
		t.Errorf("project.set events = %+v", ev)
	}
}
