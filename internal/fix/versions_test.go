package fix

import (
	"context"
	"testing"
)

// TestProposalRecordsTheVersions: a proposal keeps the installed version
// and the version the fix commit's lockfile resolves, even when it is not
// the planned target.
func TestProposalRecordsTheVersions(t *testing.T) {
	f := newFixture(t)
	f.consent()
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"v1.2.7"}]}`+"\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "Upgrade acme/lib."}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, err := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if err != nil || !ok {
		t.Fatalf("no proposal: %v (attempt %+v)", err, f.attempt(a.ID))
	}
	if p.FromVersion != f.finding.InstalledVersion || p.ToVersion != "1.2.7" {
		t.Errorf("versions = %q -> %q, want %q -> 1.2.7", p.FromVersion, p.ToVersion, f.finding.InstalledVersion)
	}
}

func TestLockVersionAndCleanVersion(t *testing.T) {
	composer := `{"packages":[{"name":"other/x","version":"2.0.0"}],"packages-dev":[{"name":"acme/lib","version":"v1.2.5"}]}`
	if got := lockVersion([]byte(composer), "Packagist", "acme/lib"); got != "v1.2.5" {
		t.Errorf("composer = %q", got)
	}
	npm := `{"packages":{"node_modules/left-pad":{"version":"1.0.1"}}}`
	if got := lockVersion([]byte(npm), "npm", "left-pad"); got != "1.0.1" {
		t.Errorf("npm = %q", got)
	}
	for _, lock := range []string{`not json`, `{"packages":[]}`, `{}`} {
		if got := lockVersion([]byte(lock), "Packagist", "acme/lib"); got != "" {
			t.Errorf("%s: %q", lock, got)
		}
	}
	for in, want := range map[string]string{"v1.2.5": "1.2.5", " 1.0.0 ": "1.0.0", "": "", "1.0; rm -rf": "", "dev-main": "dev-main"} {
		if got := cleanVersion(in); got != want {
			t.Errorf("cleanVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
