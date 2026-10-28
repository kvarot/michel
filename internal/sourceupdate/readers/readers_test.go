package readers

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/egress"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/sourceupdate"
	"github.com/kvarot/michel/internal/store"
)

func deps(t *testing.T, rules ...policy.AllowRule) sourceupdate.Deps {
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
	var p policy.Policy
	p.Sovereignty.Network.Allow = rules
	return sourceupdate.Deps{Store: s, Repo: repo, Audit: audit.NewLogger(s, time.Now), Gateway: egress.New(p, nil),
		OSVRoot: filepath.Join(t.TempDir(), "osv"), Now: time.Now}
}

func TestOSVReaderDownloadsThenHonoursNotModified(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, n := range []string{"A-1.json", "A-2.json"} {
		f, _ := w.Create(n)
		f.Write([]byte("{}"))
	}
	w.Close()
	var sinces []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ims := r.Header.Get("If-Modified-Since")
		sinces = append(sinces, ims)
		if ims != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Write(b.Bytes())
	}))
	defer srv.Close()
	defer osvdb.SetBaseURLForTest(srv.URL)()
	d := deps(t, policy.AllowRule{Host: osvdb.Host, Purpose: policy.PurposeOSV}, policy.AllowRule{Host: "127.0.0.1", Purpose: policy.PurposeOSV})
	ctx := context.Background()
	rep, err := sourceupdate.Run(ctx, d, []string{"osv.npm"}, "")
	if err != nil || !reflect.DeepEqual(rep.Updated, []string{"osv.npm"}) || rep.Items["osv.npm"] != 2 {
		t.Fatalf("first run: %v %+v", err, rep)
	}
	rep, err = sourceupdate.Run(ctx, d, []string{"osv.npm"}, "")
	if err != nil || rep.SkipReasons["osv.npm"] != sourceupdate.SkipNotModified || len(rep.Failed) != 0 {
		t.Fatalf("second run: %v %+v", err, rep)
	}
	if len(sinces) != 2 || sinces[0] != "" || sinces[1] == "" {
		t.Errorf("If-Modified-Since headers = %q", sinces)
	}
	e, _ := d.Repo.Get(ctx, "osv.npm")
	if e.LastReadResult != "ok" || e.LastReadItems != 2 {
		t.Errorf("entry = %q %d", e.LastReadResult, e.LastReadItems)
	}
	if st, _ := osvdb.Statuses(d.OSVRoot, []string{"npm"}); !st[0].Present {
		t.Error("database removed by the 304")
	}
}

func TestEnrichReaderRefusesUnknownFormat(t *testing.T) {
	d := deps(t)
	e := source.Entry{Key: "enrich.mine", Kind: source.KindEnrichment, Config: source.Config{User: map[string]any{"format": "nope"}}}
	if _, err := (enrichReader{}).Read(context.Background(), e, d); err == nil || !strings.Contains(err.Error(), "unknown enrichment format") {
		t.Errorf("err = %v", err)
	}
}
