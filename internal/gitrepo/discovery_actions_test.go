package gitrepo

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/source"
	"github.com/kvarot/michel/internal/store"
)

func actionsFixture(t *testing.T) (DiscoveryActions, *store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	found := []Discovery{{Repo: "Example/Skill", Topic: "claude-skills"}, {Repo: "example/other", Topic: "mcp-security"}}
	if _, err := NewDiscoveryRepo(s).Save(context.Background(), found, nil, time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	return DiscoveryActions{Store: s, Audit: audit.NewLogger(s, time.Now), Actor: "tester"}, s
}

func auditCount(t *testing.T, s *store.Store, action string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM audit_event WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDiscoveryAddMatchesIgnoringCaseAndAudits(t *testing.T) {
	d, s := actionsFixture(t)
	ctx := context.Background()
	pin := "0123456789abcdef0123456789abcdef01234567"
	e, err := d.Add(ctx, "example/skill", source.UserEntryRequest{Kind: source.KindSkill, Name: "demo skill", Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.NewRepo(s).Get(ctx, e.Key); err != nil {
		t.Errorf("entry not stored: %v", err)
	}
	if list, _ := NewDiscoveryRepo(s).List(ctx, StateAdded); len(list) != 1 {
		t.Errorf("added discoveries = %+v", list)
	}
	if n := auditCount(t, s, "source.add"); n != 1 {
		t.Errorf("source.add events = %d", n)
	}
	if _, err := d.Add(ctx, "Example/Skill", source.UserEntryRequest{Kind: source.KindSkill, Name: "demo skill", Pin: pin}); !errors.Is(err, source.ErrExists) {
		t.Errorf("second add: %v, want ErrExists", err)
	}
	if n := auditCount(t, s, "source.add"); n != 1 {
		t.Errorf("source.add events after a refusal = %d", n)
	}
}

func TestDiscoveryAddRefusals(t *testing.T) {
	d, s := actionsFixture(t)
	ctx := context.Background()
	if _, err := d.Add(ctx, "nobody/none", source.UserEntryRequest{Kind: source.KindSkill}); !errors.Is(err, ErrUnknownDiscovery) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := d.Add(ctx, "example/other", source.UserEntryRequest{Kind: source.KindFeed}); !errors.Is(err, ErrBadDiscoveryKind) {
		t.Errorf("kind: %v", err)
	}
	var refusal *source.Refusal
	if _, err := d.Add(ctx, "example/other", source.UserEntryRequest{Kind: source.KindMCP, Name: "x", Pin: "short"}); !errors.As(err, &refusal) || refusal.Code != "bad_pin" {
		t.Errorf("pin: %v", err)
	}
	if n := auditCount(t, s, "source.add"); n != 0 {
		t.Errorf("source.add events = %d, want none", n)
	}
}

func TestDiscoveryIgnoreAudits(t *testing.T) {
	d, s := actionsFixture(t)
	ctx := context.Background()
	repo, err := d.Ignore(ctx, "EXAMPLE/OTHER")
	if err != nil || repo != "example/other" {
		t.Fatalf("ignore = %q, %v", repo, err)
	}
	if list, _ := NewDiscoveryRepo(s).List(ctx, StateIgnored); len(list) != 1 {
		t.Errorf("ignored = %+v", list)
	}
	if n := auditCount(t, s, "source.discover"); n != 1 {
		t.Errorf("source.discover events = %d", n)
	}
	if _, err := d.Ignore(ctx, "nobody/none"); !errors.Is(err, ErrUnknownDiscovery) {
		t.Errorf("unknown: %v", err)
	}
}
