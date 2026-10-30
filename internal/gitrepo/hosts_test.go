package gitrepo

import (
	"net/url"
	"slices"
	"testing"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/source"
)

// TestBaseURLHostsAreInTheCatalog ties the fixed GitHub endpoints to the
// catalog: every skill and MCP server declares the API host (status,
// installation) and the archive host (installation), and discovery the API
// host. A moved endpoint fails here before it is refused by the gateway.
func TestBaseURLHostsAreInTheCatalog(t *testing.T) {
	host := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u.Hostname()
	}
	api, load := host(apiBase), host(codeloadBase)
	cat, _, err := source.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, c := range cat {
		switch {
		case c.Kind == source.KindSkill || c.Kind == source.KindMCP:
			if !slices.Contains(c.Hosts, api) || !slices.Contains(c.Hosts, load) || c.Purpose != policy.PurposeRepo {
				t.Errorf("%s declares %v for %s, its reader uses %s and %s for %s", c.Key, c.Hosts, c.Purpose, api, load, policy.PurposeRepo)
			}
			checked++
		case c.Key == "discover.github":
			if !slices.Contains(c.Hosts, api) || c.Purpose != policy.PurposeDiscover {
				t.Errorf("%s declares %v for %s, discovery uses %s for %s", c.Key, c.Hosts, c.Purpose, api, policy.PurposeDiscover)
			}
			checked++
		}
	}
	if checked < 3 {
		t.Errorf("only %d entries checked", checked)
	}
}
