package fix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
)

func TestConsentScreenPerProject(t *testing.T) {
	f := newFixture(t)
	f.consent()
	// A second project: the policy already allows the hosts, but this
	// project never agreed. The screen still says what leaves and what runs.
	p2, err := project.NewRepo(f.st).Add(context.Background(), project.Project{Name: "second", Path: f.proj.Path, Classification: "sensitive"})
	if err != nil {
		t.Fatal(err)
	}
	texts := ConsentNeeded(p2, f.d.Policy, false)
	keys := map[string]bool{}
	for _, c := range texts {
		keys[c.What] = true
		if c.Host != "" {
			t.Errorf("host line %+v although the rule exists", c)
		}
	}
	for _, k := range []string{"fix.consent.what_leaves", "fix.consent.runs_code", "fix.consent.sensitive"} {
		if !keys[k] {
			t.Errorf("second project's screen lacks %s: %+v", k, texts)
		}
	}
	if keys["fix.consent.external_providers"] {
		t.Error("external providers line although already enabled")
	}
	fi := f.seed("acme/second", "GHSA-2222-aaaa-bbbb", "1.0.0", "1.0.1", "composer.lock", "Packagist")
	if _, err := f.st.DB().Exec(`UPDATE finding SET project_id = ? WHERE id = ?`, p2.ID, fi.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), f.d, fi.ID, OriginAgent); !errors.Is(err, ErrConsentRequired) {
		t.Errorf("Start on the second project: %v, want ErrConsentRequired", err)
	}
	if n := len(ConsentNeeded(f.proj, f.d.Policy, true)); n != 0 {
		t.Errorf("the consented project still has %d lines", n)
	}
}

func TestCreateAttemptIsAtomic(t *testing.T) {
	r := newRepo(t)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.CreateAttempt(context.Background(), Attempt{FindingID: "f1", ProjectID: "p1", Origin: OriginAgent})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok, busy := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrBusy):
			busy++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 || busy != 7 {
		t.Errorf("ok %d busy %d, want 1 and 7", ok, busy)
	}
	// Another project is free; the same one is free again once finished.
	if _, err := r.CreateAttempt(context.Background(), Attempt{FindingID: "f2", ProjectID: "p2", Origin: OriginAgent}); err != nil {
		t.Errorf("other project: %v", err)
	}
	list, _ := r.ListAttempts(context.Background(), "p1", "")
	if err := r.SetState(context.Background(), list[0].ID, []State{StatePreparing}, StateFailed, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateAttempt(context.Background(), Attempt{FindingID: "f1", ProjectID: "p1", Origin: OriginAgent}); err != nil {
		t.Errorf("after the failure: %v", err)
	}
}

func TestMessagesHidePathsAndSecrets(t *testing.T) {
	f := newFixture(t)
	f.consent()
	secret := "AKIA" + "ABCDEFGHIJKLMNOP"
	f.rec.fail = "vendor/bin/phpunit"
	f.rec.failOutput = "FAIL in " + filepath.Join(f.d.DataDir, "worktrees", "x", "src", "app.php") + " token=" + secret + "\n"
	michelsUpdate(t, f)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	msgs, _ := f.d.Repo.ListMessages(context.Background(), a.ID)
	var all []string
	for _, m := range msgs {
		all = append(all, m.Text)
	}
	text := strings.Join(all, "\n")
	if !strings.Contains(text, "FAIL in") {
		t.Fatalf("the test output did not reach the conversation:\n%s", text)
	}
	if strings.Contains(text, secret) || strings.Contains(text, f.d.DataDir) || strings.Contains(text, filepath.ToSlash(f.d.DataDir)) {
		t.Errorf("a secret or a path reached the conversation:\n%s", text)
	}
	if !strings.Contains(text, "[secret-") || !strings.Contains(text, "<path>") {
		t.Errorf("no token or path placeholder:\n%s", text)
	}
	p, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if strings.Contains(p.TestsOutput, secret) || strings.Contains(p.TestsOutput, f.d.DataDir) {
		t.Errorf("proposal output leaks: %q", p.TestsOutput)
	}
}

func TestAuditHasNoRawErrors(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, p := approved(t, f)
	// The branch already exists: Apply fails.
	gitT(t, f.env, f.proj.Path, "branch", Branch(a.ID))
	if err := Apply(context.Background(), f.d, a.ID); err == nil {
		t.Fatal("Apply succeeded with an existing branch")
	}
	rows, err := f.st.DB().Query(`SELECT action, result, evidence FROM audit_event WHERE action LIKE 'fix.%' OR action = 'ai.consent'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seenApply := false
	for rows.Next() {
		var action, result, ev string
		if err := rows.Scan(&action, &result, &ev); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(ev, f.d.DataDir) || strings.Contains(ev, filepath.ToSlash(f.d.DataDir)) || strings.Contains(ev, f.proj.Path) {
			t.Errorf("%s/%s evidence holds a path: %s", action, result, ev)
		}
		if action == "fix.apply" && result == "error" {
			seenApply = true
			var m map[string]any
			_ = json.Unmarshal([]byte(ev), &m)
			if m["error"] != "apply_failed" || m["detail"] == "" || len(m["detail"].(string)) > 210 {
				t.Errorf("fix.apply error evidence = %s", ev)
			}
		}
	}
	if !seenApply {
		t.Error("no fix.apply error event")
	}
	_ = p
}

func TestSweepDropsTokensAndMasks(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID) // proposed: the session is gone, its token with it
	if tokenStillSet(f.d.Secrets, a.ID) {
		t.Error("token of a proposed attempt kept after its session ended")
	}
	// Give it a token again (as if serve had died before the session end).
	if err := SetAttemptToken(f.d.Secrets, a.ID, "again"); err != nil {
		t.Fatal(err)
	}
	if err := Sweep(context.Background(), f.d); err != nil {
		t.Fatal(err)
	}
	if tokenStillSet(f.d.Secrets, a.ID) {
		t.Error("token of a non-preparing attempt survived the sweep")
	}
	// The mask table lives while the attempt is recent, goes with its
	// messages once old and finished.
	if _, err := f.d.Secrets.Get("mask-" + strings.ToLower(a.ID)); err != nil {
		t.Fatalf("mask table missing before the purge: %v", err)
	}
	if err := Refuse(context.Background(), f.d, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET updated_at = ? WHERE id = ?`, f.d.Now().Add(-40*24*time.Hour).Format(time.RFC3339), a.ID); err != nil {
		t.Fatal(err)
	}
	if err := Sweep(context.Background(), f.d); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.Secrets.Get("mask-" + strings.ToLower(a.ID)); err == nil {
		t.Error("mask table survived the purge of an old finished attempt")
	}
}

func TestPurgeProjectForgetsSecrets(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if err := SetAttemptToken(f.d.Secrets, a.ID, "again"); err != nil {
		t.Fatal(err)
	}
	if err := PurgeProject(context.Background(), f.d, f.proj.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.Secrets.Get("mask-" + strings.ToLower(a.ID)); err == nil {
		t.Error("mask table survived the project purge")
	}
	if tokenStillSet(f.d.Secrets, a.ID) {
		t.Error("token survived the project purge")
	}
	for _, sub := range []string{"worktrees", "fix-mirrors"} {
		if _, err := os.Lstat(filepath.Join(f.d.DataDir, sub, f.proj.ID)); err == nil {
			t.Errorf("%s of the project survived the purge", sub)
		}
	}
}

func TestConsentStatus(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	st, err := ConsentStatus(ctx, f.d, f.proj, f.d.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if st.Refusal != nil || len(st.Lines) == 0 || st.Ready {
		t.Errorf("before consent: %+v", st)
	}
	f.consent()
	st, err = ConsentStatus(ctx, f.d, f.proj, f.d.Policy)
	if err != nil || !st.Consented || st.GivenAt.IsZero() {
		t.Fatalf("after consent: %+v %v", st, err)
	}
	if st.Ready != (len(st.Lines) == 0) || st.Refusal != nil {
		t.Errorf("ready = %v with %d lines, refusal %v", st.Ready, len(st.Lines), st.Refusal)
	}
	strict := f.d.Policy
	strict.Sovereignty.Mode = policy.ModeStrictLocal
	if st, _ = ConsentStatus(ctx, f.d, f.proj, strict); !errors.Is(st.Refusal, ErrStrictLocal) || st.Ready {
		t.Errorf("strict_local: %+v", st)
	}
	health := f.proj
	health.Classification = policy.ClassHealth
	if st, _ = ConsentStatus(ctx, f.d, health, strict); !errors.Is(st.Refusal, ErrHealthForbidden) || st.Ready {
		t.Errorf("health wins over strict_local: %+v", st)
	}
}
