package cli

import (
	"strings"
	"testing"
)

func TestProjectSetAutoScan(t *testing.T) {
	dir, proj := t.TempDir(), t.TempDir()
	if _, _, _, err := run(t, dir, "project", "add", proj, "--name", "demo"); err != nil {
		t.Fatal(err)
	}
	_, list, _, err := run(t, dir, "project", "list", "--json")
	if err != nil || !strings.Contains(list, `"auto_scan":true`) {
		t.Fatalf("list = %s, %v", list, err)
	}
	if _, _, _, err := run(t, dir, "project", "set", "demo", "--auto-scan=false"); err != nil {
		t.Fatal(err)
	}
	_, list, _, _ = run(t, dir, "project", "list", "--json")
	if !strings.Contains(list, `"auto_scan":false`) {
		t.Errorf("list = %s", list)
	}
	rows := auditRows(t, dir, "project.set")
	if len(rows) != 1 || rows[0].result != "ok" || rows[0].evidence["auto_scan"] != false {
		t.Errorf("events = %+v", rows)
	}
}
