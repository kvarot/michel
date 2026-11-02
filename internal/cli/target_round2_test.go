package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/store"
	"github.com/kvarot/michel/internal/target"
)

// seedAttempt stores a server fix of server name in state st.
func seedAttempt(t *testing.T, dir, name string, st fix.State, ex target.Executor) string {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	tg, err := target.NewRepo(s).Get(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	repo := fix.NewRepo(s)
	a, err := repo.CreateAttempt(ctx, fix.Attempt{FindingID: "f1", ProjectID: tg.ID, Origin: fix.OriginServer, Work: fix.Work{Server: &fix.ServerWork{TargetID: tg.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.AddProposal(ctx, fix.Proposal{AttemptID: a.ID, Summary: "x", Hash: "h", Scripts: &serverfix.Bundle{Apply: "a", Undo: "u", Hash: "s"}, Server: &fix.ServerFix{TargetID: tg.ID, Executor: ex}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE fix_attempt SET state = ? WHERE id = ?`, string(st), a.ID); err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func TestTargetRemoveNamesTheWayOutOfAPendingFix(t *testing.T) {
	e := newTargetEnv(t)
	if _, _, _, err := run(t, e.dir, "target", "add", "192.0.2.80", "--user", "deploy", "--name", "pending"); err != nil {
		t.Fatal(err)
	}
	unknown := seedAttempt(t, e.dir, "pending", fix.StateUnknown, target.ExecMichel)
	_, _, _, err := run(t, e.dir, "target", "remove", "pending")
	if err == nil || !strings.Contains(err.Error(), "michel fix resolve") {
		t.Fatalf("unknown fix: %v", err)
	}
	// The way out: the user says they checked the server.
	_, out, _, err := run(t, e.dir, "fix", "resolve", unknown)
	if err != nil || !strings.Contains(out, "checked") {
		t.Fatalf("resolve: %q %v", out, err)
	}
	if rows := auditRows(t, e.dir, "server_fix.resolved"); len(rows) != 1 || rows[0].evidence["author"] != "cli" {
		t.Errorf("audit = %+v", rows)
	}
	if _, _, _, err := run(t, e.dir, "fix", "resolve", unknown); err == nil {
		t.Error("a second resolve was accepted")
	}
	approved := seedAttempt(t, e.dir, "pending", fix.StateApproved, target.ExecUser)
	_, _, _, err = run(t, e.dir, "target", "remove", "pending")
	if err == nil || !strings.Contains(err.Error(), "michel fix refuse") {
		t.Fatalf("approved fix: %v", err)
	}
	if _, _, _, err := run(t, e.dir, "fix", "refuse", approved); err != nil {
		t.Fatal(err)
	}
	preparing := seedAttempt(t, e.dir, "pending", fix.StatePreparing, target.ExecMichel)
	if _, _, _, err := run(t, e.dir, "target", "remove", "pending"); err == nil || !strings.Contains(err.Error(), "wait") {
		t.Errorf("preparing fix: %v", err)
	}
	_ = preparing
}
