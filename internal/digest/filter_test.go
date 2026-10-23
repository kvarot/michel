package digest

import (
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
)

func TestFilterRecomputesCounters(t *testing.T) {
	d := Digest{SchemaVersion: SchemaVersion, Lang: i18n.EN, Assistant: "Michel", Projects: []ProjectDigest{
		{Name: "demo", New: []Package{{Name: "acme/lib", FindingIDs: []string{"a", "b"}}}, Attention: 1, LastScanStatus: scan.ScanOK},
		{Name: "project-a", New: []Package{{Name: "vuln-pkg", FindingIDs: []string{"c"}}}, Attention: 0, LastScanStatus: scan.ScanFailed},
	}, NewTotal: 3, AttentionTotal: 1, FailedScans: 1}
	retitle(&d)
	if d.Title != "Michel found 3 new findings since the last digest, 1 needs your attention" {
		t.Fatalf("title = %q", d.Title)
	}
	f := Filter(d, []string{"project-a"})
	if len(f.Projects) != 1 || f.Projects[0].Name != "project-a" || f.NewTotal != 1 || f.AttentionTotal != 0 || f.FailedScans != 1 {
		t.Fatalf("filtered = %+v", f)
	}
	if f.Title != "Michel found 1 new finding since the last digest" {
		t.Errorf("title = %q", f.Title)
	}
	if len(d.Projects) != 2 || d.NewTotal != 3 {
		t.Errorf("Filter changed its input: %+v", d)
	}
	if e := Filter(d, []string{"absent"}); len(e.Projects) != 0 || e.NewTotal != 0 || e.Word == "" {
		t.Errorf("empty = %+v", e)
	}
	if all := Filter(d, nil); len(all.Projects) != 2 || all.Title != d.Title {
		t.Errorf("no filter = %+v", all)
	}
}
