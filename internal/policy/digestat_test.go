package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDigestAtDefaultsToEightAndLoads(t *testing.T) {
	if got := Defaults().Notify.DigestAt; got != "08:00" {
		t.Fatalf("default digest_at = %q", got)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	for _, c := range []struct{ yaml, want string }{
		{"notify:\n  page_url: http://127.0.0.1:7331/\n", "08:00"},
		{"notify:\n  digest_at: \"06:45\"\n", "06:45"},
		{"notify:\n  digest_at: off\n", "off"},
	} {
		if err := os.WriteFile(path, []byte(c.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		p, _, err := Load(path, dir)
		if err != nil || p.Notify.DigestAt != c.want || Validate(p) != nil {
			t.Errorf("%q: digest_at = %q, %v, %v", c.yaml, p.Notify.DigestAt, err, Validate(p))
		}
	}
}

func TestDigestAtIsValidated(t *testing.T) {
	for _, bad := range []string{"8h", "25:00", "08:60", "8:00", "08:00:00", "off ", "never", "24:00", "-1:00"} {
		mustFail(t, func(p *Policy) { p.Notify.DigestAt = bad }, "notify.digest_at")
	}
	for _, good := range []string{"", "00:00", "08:00", "23:59", "off"} {
		p := Defaults()
		p.Notify.DigestAt = good
		if err := Validate(p); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	err := ValidateNotify(NotifyConfig{DigestAt: "9am"}, nil)
	if err == nil || !strings.Contains(err.Error(), "HH:MM") || !strings.Contains(err.Error(), "off") {
		t.Errorf("the error does not say what to write: %v", err)
	}
}

func TestDigestHour(t *testing.T) {
	for _, c := range []struct {
		at      string
		h, m    int
		enabled bool
	}{{"", 8, 0, true}, {"08:00", 8, 0, true}, {"23:59", 23, 59, true}, {"off", 0, 0, false}} {
		h, m, ok := NotifyConfig{DigestAt: c.at}.DigestHour()
		if h != c.h || m != c.m || ok != c.enabled {
			t.Errorf("%q = %d:%d %v", c.at, h, m, ok)
		}
	}
}
