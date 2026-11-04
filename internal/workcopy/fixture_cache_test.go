package workcopy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The repositories the fixtures start from are built from scratch with git
// once per run, in a folder of their own, and every test gets a plain file
// copy of them: a dozen git calls per test cost seconds on Windows.

var (
	tplMu   sync.Mutex
	tplRoot string
	tplMade = map[string]*tplRemote{}
)

// tplRemote is a template holding proj, remote.git and, for the folder
// fixture, site, and the commits the remote fixture names.
type tplRemote struct {
	once              sync.Once
	dir               string
	sha, other, main_ string
}

func TestMain(m *testing.M) {
	code := m.Run()
	if tplRoot != "" {
		_ = os.RemoveAll(tplRoot)
	}
	if parHome != "" {
		_ = os.RemoveAll(parHome)
	}
	os.Exit(code)
}

// tplFolder is the folder where the templates are built.
func tplFolder(t *testing.T, name string) string {
	t.Helper()
	tplMu.Lock()
	defer tplMu.Unlock()
	if tplRoot == "" {
		d, err := os.MkdirTemp("", "michel-workcopy-tpl-")
		if err != nil {
			t.Fatal(err)
		}
		tplRoot = d
	}
	d := filepath.Join(tplRoot, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// template returns the template of the given kind, built on the first call:
// "project" (proj only), "remote" (proj and remote.git) or "folder" (proj,
// remote.git and site).
func template(t *testing.T, kind string) *tplRemote {
	t.Helper()
	tplMu.Lock()
	tp := tplMade[kind]
	if tp == nil {
		tp = &tplRemote{}
		tplMade[kind] = tp
	}
	tplMu.Unlock()
	tp.once.Do(func() {
		tp.dir = tplFolder(t, kind)
		env := testGitEnv(t)
		root := filepath.Join(tp.dir, "proj")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		buildProject(t, env, root)
		if kind == "project" {
			return
		}
		tp.main_, tp.other, tp.sha = buildRemote(t, env, root, remoteAddress(tp.dir))
		if kind == "folder" {
			gitT(t, env, root, "remote", "add", "origin", remoteAddress(tp.dir))
			site := filepath.Join(tp.dir, "site")
			gitT(t, env, tp.dir, "clone", "-q", remoteAddress(tp.dir), site)
		}
	})
	return tp
}

func remoteAddress(dir string) string {
	return filepath.ToSlash(filepath.Join(dir, "remote.git"))
}

// copyTree copies src to dst, keeping modes and modification times. In the
// config files of a .git folder it replaces each old address by its new one.
func copyTree(t *testing.T, src, dst string, repl []string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		to := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(to, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if len(repl) > 0 && info.Name() == "config" && filepath.Base(filepath.Dir(p)) == ".git" {
			s := string(b)
			for i := 0; i+1 < len(repl); i += 2 {
				s = strings.ReplaceAll(s, repl[i], repl[i+1])
			}
			b = []byte(s)
		}
		if err := os.WriteFile(to, b, info.Mode().Perm()|0o600); err != nil {
			return err
		}
		return os.Chtimes(to, info.ModTime(), info.ModTime())
	})
	if err != nil {
		t.Fatal(err)
	}
}

var (
	parMu    sync.Mutex
	parNamed = map[string]bool{}
	parOnce  sync.Once
	parHome  string
)

// parallel marks a top-level test that runs with the others, after every test
// that runs alone. Such a test never sets the environment and writes nothing
// in the person's home: the fixtures it makes use one shared, empty home, which
// the process environment names from then on, as isolatePerson would.
func parallel(t *testing.T) {
	t.Helper()
	parMu.Lock()
	parNamed[t.Name()] = true
	parMu.Unlock()
	t.Parallel()
	sharedPerson(t) // before any of them runs
}

// inParallel says whether the test, or the top-level test above it, is one
// marked by parallel.
func inParallel(t *testing.T) bool {
	parMu.Lock()
	defer parMu.Unlock()
	name, _, _ := strings.Cut(t.Name(), "/")
	return parNamed[name]
}

// sharedPerson is the empty home of the tests run by parallel. The process
// environment is set once, at the first call, when no test that runs alone is
// left.
func sharedPerson(t *testing.T) string {
	t.Helper()
	parOnce.Do(func() {
		d, err := os.MkdirTemp("", "michel-workcopy-home-")
		if err != nil {
			t.Fatal(err)
		}
		parHome = d
		os.Setenv("HOME", d)
		os.Setenv("USERPROFILE", d)
		os.Setenv("XDG_CONFIG_HOME", filepath.Join(d, "xdg"))
		for _, k := range []string{"GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
			os.Unsetenv(k)
		}
	})
	return parHome
}
