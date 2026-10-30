package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

func pluginEntry(key, tool, format string, run bool) source.Entry {
	return source.Entry{ID: "src-" + tool, Key: key, Kind: source.KindPlugin, Origin: source.OriginCatalog, Name: tool, Enabled: true,
		Config: source.Config{Catalog: map[string]any{"format": format, "tool": tool, "run": run}}}
}

type env struct {
	deps RunDeps
	st   *store.Store
	proj project.Project
}

func newEnv(t *testing.T) env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "app.php"), []byte("<?php echo 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := project.NewRepo(st).Add(context.Background(), project.Project{Name: "demo", Path: root})
	if err != nil {
		t.Fatal(err)
	}
	return env{st: st, proj: p, deps: RunDeps{Store: st, Audit: audit.NewLogger(st, time.Now), Repo: source.NewRepo(st),
		DataDir: t.TempDir(), Now: time.Now}}
}

type event struct{ action, target, result, evidence string }

func (e env) events(t *testing.T, action string) []event {
	t.Helper()
	rows, err := e.st.DB().Query(`SELECT action, target, result, evidence FROM audit_event WHERE action = ? ORDER BY rowid`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []event
	for rows.Next() {
		var ev event
		if err := rows.Scan(&ev.action, &ev.target, &ev.result, &ev.evidence); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// treeDigest is the SHA-256 of every path, size and modification time under
// root: equal digests mean nothing was created, removed or written there.
func treeDigest(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00%v\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano(), info.Mode())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

var (
	fakeOnce sync.Once
	fakeBin  string
	fakeErr  error
)

// fakeTool builds testdata/faketool once (go build) and returns its path.
func fakeTool(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "michel-faketool")
		if err != nil {
			fakeErr = err
			return
		}
		fakeBin = filepath.Join(dir, "faketool")
		if runtime.GOOS == "windows" {
			fakeBin += ".exe"
		}
		out, err := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", fakeBin, "./testdata/faketool").CombinedOutput()
		if err != nil {
			fakeErr = fmt.Errorf("go build faketool: %v\n%s", err, out)
		}
	})
	if fakeErr != nil {
		t.Fatal(fakeErr)
	}
	return fakeBin
}

// installFake puts the fake tool on PATH under the name tool.
func installFake(t *testing.T, tool string) {
	t.Helper()
	b, err := os.ReadFile(fakeTool(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := tool
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeBin != "" {
		os.RemoveAll(filepath.Dir(fakeBin))
	}
	os.Exit(code)
}
