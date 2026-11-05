package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchDefaults(t *testing.T) {
	p := Defaults()
	if !p.Watch.IsEnabled() || p.Watch.ScanAt != "" {
		t.Fatalf("default watch = %+v", p.Watch)
	}
	h, m, on := p.WatchHour()
	if h != 7 || m != 0 || !on {
		t.Errorf("default watch hour = %02d:%02d %v, want 07:00", h, m, on)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("watch:\n  enabled: false\n  scan_at: \"05:30\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _, err := Load(path, dir)
	if err != nil || Validate(p) != nil {
		t.Fatalf("load: %v %v", err, Validate(p))
	}
	if p.Watch.IsEnabled() || p.Watch.ScanAt != "05:30" {
		t.Errorf("loaded watch = %+v", p.Watch)
	}
	if _, _, on := p.WatchHour(); on {
		t.Error("a watch turned off still has an hour")
	}
}

func TestWatchScanAtIsValidated(t *testing.T) {
	for _, bad := range []string{"7h", "24:00", "07:60", "7:00", "off"} {
		mustFail(t, func(p *Policy) { p.Watch.ScanAt = bad }, "watch.scan_at")
	}
	p := Defaults()
	p.Watch.ScanAt = "x"
	if err := Validate(p); err == nil || !strings.Contains(err.Error(), "HH:MM") {
		t.Errorf("the error does not say what to write: %v", err)
	}
	for _, good := range []string{"", "00:00", "06:15", "23:59"} {
		p := Defaults()
		p.Watch.ScanAt = good
		if err := Validate(p); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}

func TestWatchHourFollowsTheDigest(t *testing.T) {
	for _, c := range []struct {
		digest, scan string
		h, m         int
	}{
		{"", "", 7, 0},
		{"09:15", "", 8, 15},
		{"00:30", "", 0, 0}, // never the day before
		{"off", "", 7, 0},
		{"09:15", "05:45", 5, 45},
	} {
		p := Defaults()
		p.Notify.DigestAt, p.Watch.ScanAt = c.digest, c.scan
		h, m, on := p.WatchHour()
		if h != c.h || m != c.m || !on {
			t.Errorf("digest %q scan %q: %02d:%02d %v, want %02d:%02d", c.digest, c.scan, h, m, on, c.h, c.m)
		}
	}
}
