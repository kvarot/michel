package fix

import (
	"context"
	"testing"
)

// TestRefuseWhileTheAgentWorks: refusing an attempt whose agent is still
// working ends it refused, not failed by the end of its session.
func TestRefuseWhileTheAgentWorks(t *testing.T) {
	f := newFixture(t)
	f.consent()
	release := make(chan struct{})
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) { <-release }
	defer close(release)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	if err := Refuse(context.Background(), f.d, a.ID, ""); err != nil {
		t.Fatalf("Refuse: %v", err)
	}
	if got := f.attempt(a.ID); got.State != StateRefused {
		t.Errorf("state = %s (%s)", got.State, got.Cause)
	}
}
