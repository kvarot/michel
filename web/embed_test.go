package web

import (
	"io/fs"
	"os"
	"strings"
	"testing"
)

// TestDistEmbedsIndexAfterBuild checks that a built front (npm run build) is
// embedded whole: index.html, its hashed assets, the service worker and the
// manifest. Without a build, dist holds only .gitkeep and the test skips.
func TestDistEmbedsIndexAfterBuild(t *testing.T) {
	if _, err := os.Stat("dist/index.html"); err != nil {
		t.Skip("web/dist/index.html absent: run make web")
	}
	sub, ok := Dist()
	if !ok {
		t.Fatal("Dist() = false although dist/index.html exists")
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(index)
	if strings.Contains(page, "<script>") || strings.Contains(page, "<script type=\"module\">") {
		t.Error("index.html holds an inline script: the CSP forbids it")
	}
	for _, name := range []string{"sw.js", "manifest.webmanifest", "sw-manifest.json", "icons/icon-192.png", "icons/icon-512.png"} {
		if _, err := fs.Stat(sub, name); err != nil {
			t.Errorf("%s is not embedded: %v", name, err)
		}
	}
	assets, err := fs.ReadDir(sub, "assets")
	if err != nil || len(assets) == 0 {
		t.Fatalf("no assets embedded: %v", err)
	}
	referenced := false
	for _, a := range assets {
		if strings.HasSuffix(a.Name(), ".js") && strings.Contains(page, "/assets/"+a.Name()) {
			referenced = true
		}
	}
	if !referenced {
		t.Error("index.html loads no script from /assets/")
	}
}
