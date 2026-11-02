package vulnmatch

import (
	"testing"

	"github.com/kvarot/michel/internal/target"
)

func TestEcosystemFromOSRelease(t *testing.T) {
	cases := []struct {
		id, ver, want string
		ok            bool
	}{
		{"debian", "12", "Debian:12", true},
		{"ubuntu", "22.04", "Ubuntu:22.04:LTS", true},
		{"ubuntu", "23.10", "Ubuntu:23.10", true},
		{"alpine", "3.19.1", "Alpine:v3.19", true},
		{"almalinux", "9.3", "AlmaLinux:9", true},
		{"rocky", "9.2", "Rocky Linux:9", true},
		{"arch", "", "", false},
		{"debian", "", "", false},
		{"fedora", "39", "", false},
		{"ubuntu", "22.04.3", "Ubuntu:22.04:LTS", true},
		{"alpine", "3.20_alpha20240329", "Alpine:v3.20", true},
	}
	for _, c := range cases {
		got, ok := Ecosystem(target.OSInfo{ID: c.id, VersionID: c.ver})
		if got != c.want || ok != c.ok {
			t.Errorf("%s %s: got %q,%v want %q,%v", c.id, c.ver, got, ok, c.want, c.ok)
		}
	}
	if k := CatalogKey("Debian:12"); k != "osv.debian" {
		t.Errorf("key %q", k)
	}
	if k := CatalogKey("Rocky Linux:9"); k != "osv.rocky-linux" {
		t.Errorf("key %q", k)
	}
}

const dsa = `{"id":"DSA-0000-1","aliases":["CVE-0000-0001"],"database_specific":{"severity":"High"},
"affected":[{"package":{"ecosystem":"Debian:12","name":"php8.2"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.2.20-1"}]}]}]}`

const dsaEpoch = `{"id":"DSA-0000-2","aliases":["CVE-0000-0002"],
"affected":[{"package":{"ecosystem":"Debian:12","name":"epochpkg"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:8.2.20-1"}]}]}]}`

const dsaOther = `{"id":"DSA-0000-3","affected":[{"package":{"ecosystem":"Debian:11","name":"php8.2"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]}]}`
