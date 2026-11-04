//go:build !michel_local_remote

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The usual build refuses a remote on this disk, through the same stack as serve.
func TestDefaultBuildRefusesALocalRemote(t *testing.T) {
	if allowLocalRemote {
		t.Fatal("allowLocalRemote is on in the default build")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	t.Setenv("GIT_AUTHOR_NAME", "demo")
	t.Setenv("GIT_AUTHOR_EMAIL", "demo@example.test")
	t.Setenv("GIT_COMMITTER_NAME", "demo")
	t.Setenv("GIT_COMMITTER_EMAIL", "demo@example.test")
	folder, remote := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git(remote, "init", "--bare", "--quiet")
	git(folder, "init", "--quiet")
	git(folder, "add", "a.txt")
	git(folder, "commit", "--quiet", "-m", "first")
	git(folder, "remote", "add", "origin", remote)

	if _, err := runServe(t, t.TempDir(), func(base *url.URL, token string) {
		call := func(method, p, body string) (int, []byte) {
			t.Helper()
			req, _ := http.NewRequest(method, base.String()+strings.TrimPrefix(p, "/"), strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			if body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, b
		}
		add, _ := json.Marshal(map[string]string{"path": folder, "name": "demo"})
		if code, b := call("POST", "/api/v1/projects", string(add)); code != http.StatusCreated {
			t.Fatalf("add = %d %s", code, b)
		}
		code, b := call("GET", "/api/v1/projects/demo/git", "")
		if code != http.StatusOK {
			t.Fatalf("git = %d %s", code, b)
		}
		var v struct {
			Reason    string `json:"reason"`
			CanAttach bool   `json:"can_attach"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		if v.Reason != "unsupported" || v.CanAttach {
			t.Errorf("a remote on this disk: %s", b)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

// What is shipped is built without the tag of the trial.
func TestShippedBuildsDoNotUseTheTag(t *testing.T) {
	for _, name := range []string{"Makefile", "README.md", "README.fr.md", ".github/workflows/ci.yml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "michel_local_remote") {
			t.Errorf("%s uses the tag michel_local_remote", name)
		}
	}
}
