package serverlog

import (
	"context"
	"testing"

	"github.com/kvarot/michel/internal/target"
)

func TestEraseTargetForgetsTheKeptFailures(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	if err := pe.repo.SetFailures(ctx, pe.tgt.ID, []Failure{{Reason: ReasonRefused}}, pe.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := pe.repo.EraseTarget(ctx, pe.tgt.ID); err != nil {
		t.Fatal(err)
	}
	if fs, _ := pe.repo.Failures(ctx, pe.tgt.ID); len(fs) != 0 {
		t.Fatalf("erase kept %v", fs)
	}
}

// A pass with nothing to read clears what a failed one kept.
func TestPassWithNoActiveSourceClearsTheKeptFailures(t *testing.T) {
	pe := newPassEnv(t, target.EnvProd, FormatMonolog)
	ctx := context.Background()
	if err := pe.repo.SetFailures(ctx, pe.tgt.ID, []Failure{{Reason: ReasonRefused}}, pe.clock.Now()); err != nil {
		t.Fatal(err)
	}
	src := pe.src
	src.Active = false
	if err := pe.repo.UpdateSource(ctx, src); err != nil {
		t.Fatal(err)
	}
	pe.run()
	if fs, _ := pe.repo.Failures(ctx, pe.tgt.ID); len(fs) != 0 {
		t.Fatalf("an empty pass kept %v", fs)
	}
}
