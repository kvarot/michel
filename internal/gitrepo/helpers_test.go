package gitrepo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

const (
	shaA = "1111111111111111111111111111111111111111"
	shaB = "2222222222222222222222222222222222222222"
)

// tarEntry is one member of an archive built in memory.
type tarEntry struct {
	name string
	body string
	mode int64
	typ  byte
	link string
}

// file is a regular member under the root folder codeload puts first.
func file(name, body string) tarEntry {
	return tarEntry{name: "skill-" + shaA + "/" + name, body: body, mode: 0o644, typ: tar.TypeReg}
}

// buildTarGz builds a gzip-compressed tar archive, as codeload serves it
// (a pax global header first, then a root folder).
func buildTarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header",
		PAXRecords: map[string]string{"comment": shaA}, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: typ, Linkname: e.link, ModTime: time.Unix(0, 0)}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// skillArchive is a healthy repository with one skill under skills/demo.
func skillArchive(t *testing.T, skillBody string) []byte {
	return buildTarGz(t,
		tarEntry{name: "skill-" + shaA + "/", typ: tar.TypeDir, mode: 0o755},
		file("LICENSE", "Permission is hereby granted, free of charge, to any person obtaining a copy"),
		file("README.md", "# example/skill\n"),
		file("skills/demo/SKILL.md", skillBody),
		tarEntry{name: "skill-" + shaA + "/skills/demo/run.sh", body: "echo hi\n", mode: 0o755},
		file("other/notes.md", "outside the skill\n"),
	)
}

// fakeGitHub serves archives by sha on /archive/<owner>/<repo>/tar.gz/<sha>
// and counts the requests.
type fakeGitHub struct {
	mu       sync.Mutex
	archives map[string][]byte
	requests []string
	srv      *httptest.Server
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{archives: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.URL.Path)
		body, ok := f.archives[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	restore := SetBaseURLsForTest(f.srv.URL, f.srv.URL)
	t.Cleanup(restore)
	return f
}

func (f *fakeGitHub) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// testDeps opens a store with the catalog and a client allowed to reach the
// local test server for source.repo.
func testDeps(t *testing.T) Deps {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	repo := source.NewRepo(s)
	if _, _, err := source.Sync(context.Background(), repo); err != nil {
		t.Fatal(err)
	}
	return Deps{Repo: repo, Audit: audit.NewLogger(s, time.Now), Client: testClient(policy.PurposeRepo),
		DataDir: t.TempDir(), SkillsDir: t.TempDir(), Now: time.Now}
}

func testClient(purpose string) *http.Client {
	var p policy.Policy
	p.Sovereignty.Network.Allow = []policy.AllowRule{{Host: "127.0.0.1", Purpose: purpose}}
	return egress.New(p, nil).Client(purpose)
}

// addEntry registers a user skill or mcp entry pinned to shaA.
func addEntry(t *testing.T, d Deps, kind source.Kind, name, path string, extra map[string]any) source.Entry {
	t.Helper()
	user := map[string]any{"repo": "example/" + name, "pinned": shaA}
	if path != "" {
		user["path"] = path
	}
	for k, v := range extra {
		user[k] = v
	}
	e, err := d.Repo.Upsert(context.Background(), source.Entry{Key: source.KeyFor(kind, name), Kind: kind, Origin: source.OriginUser,
		Name: name, URL: "https://github.com/example/" + name, Hosts: []string{"api.github.com", "codeload.github.com"},
		Purpose: policy.PurposeRepo, Config: source.Config{Catalog: map[string]any{}, User: user}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}
