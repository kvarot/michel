package target

import (
	"encoding/json"
	"testing"
)

func TestClassifyListen(t *testing.T) {
	for addr, want := range map[string]ListenScope{
		"0.0.0.0":            ScopeOpen,
		"::":                 ScopeOpen,
		"*":                  ScopeOpen,
		"203.0.113.7":        ScopeOpen,
		"2001:db8::1":        ScopeOpen,
		"::ffff:203.0.113.7": ScopeOpen,
		"::ffff:0.0.0.0":     ScopeOpen,

		"127.0.0.1":        ScopeServer,
		"127.0.0.53":       ScopeServer,
		"127.255.255.254":  ScopeServer,
		"::1":              ScopeServer,
		"::ffff:127.0.0.1": ScopeServer,

		"10.0.0.5":        ScopePrivate,
		"172.16.0.1":      ScopePrivate,
		"172.31.255.255":  ScopePrivate,
		"192.168.1.10":    ScopePrivate,
		"fd00::1":         ScopePrivate,
		"fc00::1":         ScopePrivate,
		"fe80::1":         ScopePrivate,
		"febf::1":         ScopePrivate,
		"100.64.0.1":      ScopePrivate,
		"100.127.255.255": ScopePrivate,
		"::ffff:10.0.0.5": ScopePrivate,

		// Just outside the reserved blocks.
		"172.32.0.1":  ScopeOpen,
		"100.63.0.1":  ScopeOpen,
		"100.128.0.1": ScopeOpen,
		"fec0::1":     ScopeOpen,
		// R11 names its blocks: IPv4 link-local is not one of them.
		"169.254.1.1": ScopeOpen,
		// An interface does not make an address narrower (R11)...
		"0.0.0.0%eth0": ScopeOpen,
		"*%eth0":       ScopeOpen,
		"::%eth0":      ScopeOpen,
		// ...and the zone of a narrow address does not widen it.
		"127.0.0.53%lo": ScopeServer,
		"fe80::1%eth0":  ScopePrivate,
		// What cannot be read is never narrowed.
		"":          ScopeOpen,
		"localhost": ScopeOpen,
		"$(id)":     ScopeOpen,
	} {
		if got := ClassifyListen(addr); got != want {
			t.Errorf("ClassifyListen(%q) = %q, want %q", addr, got, want)
		}
	}
}

// An inventory stored before listeners were read says they were not read.
func TestOldInventoryHasNotReadListeners(t *testing.T) {
	var inv Inventory
	if err := json.Unmarshal([]byte(`{"TargetID":"01TARGETDEMO","Unseen":null}`), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.ListenersRead || len(inv.Listeners) != 0 {
		t.Fatalf("%+v", inv)
	}
}
