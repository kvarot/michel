package project

import (
	"context"
	"testing"
)

func TestAutoScanDefaultsTrueAndUpdates(t *testing.T) {
	r := newRepo(t)
	ctx := context.Background()
	p, err := r.Add(ctx, Project{Name: "demo", Path: t.TempDir()})
	if err != nil || !p.AutoScan {
		t.Fatalf("added = %+v, %v", p, err)
	}
	if got, _ := r.Get(ctx, "demo"); !got.AutoScan {
		t.Fatalf("stored auto_scan = false")
	}
	p.AutoScan = false
	if err := r.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(ctx, "demo"); got.AutoScan {
		t.Errorf("auto_scan still true after Update")
	}
}
