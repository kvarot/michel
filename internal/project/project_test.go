package project

import (
	"context"
	"errors"
	"testing"
)

func TestPatchThreshold(t *testing.T) {
	f := newRegFixture(t)
	p, err := f.register("demo", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if p.GateThreshold != ThresholdNormal {
		t.Fatalf("new project threshold = %q, want normal", p.GateThreshold)
	}
	if got, err := f.repo.Get(context.Background(), "demo"); err != nil || got.GateThreshold != ThresholdNormal {
		t.Fatalf("stored = %q, %v", got.GateThreshold, err)
	}
	strict, loose := ThresholdStrict, Threshold("loose")
	if _, err := Update(context.Background(), f.repo, f.log, UpdateRequest{Actor: "test", Name: "demo", Patch: Patch{GateThreshold: &strict}}); err != nil {
		t.Fatal(err)
	}
	if got, err := f.repo.Get(context.Background(), "demo"); err != nil || got.GateThreshold != ThresholdStrict {
		t.Fatalf("after patch = %q, %v", got.GateThreshold, err)
	}
	_, err = Update(context.Background(), f.repo, f.log, UpdateRequest{Actor: "test", Name: "demo", Patch: Patch{GateThreshold: &loose}})
	var re *RefusalError
	if !errors.Is(err, ErrInvalidThreshold) || !errors.As(err, &re) || re.Key != "api.project.bad_threshold" {
		t.Fatalf("loose: %v", err)
	}
	if got, _ := f.repo.Get(context.Background(), "demo"); got.GateThreshold != ThresholdStrict {
		t.Errorf("a refused value changed the threshold to %q", got.GateThreshold)
	}
	// The repo itself refuses a bad value too.
	got, _ := f.repo.Get(context.Background(), "demo")
	got.GateThreshold = loose
	if err := f.repo.Update(context.Background(), got); !errors.Is(err, ErrInvalidThreshold) {
		t.Errorf("repo.Update loose: %v", err)
	}
}
