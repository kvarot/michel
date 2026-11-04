package fix

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// The services that listen stay out of what an agent reads: no field of the
// view can hold them, and neither the view nor the prompt shows them.
func TestAgentViewHasNoListeners(t *testing.T) {
	inv := target.Inventory{At: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC), ListenersRead: true,
		Listeners: []target.Listener{{Address: "203.0.113.7", Port: 9200, Scope: target.ScopeOpen}}}
	tg := target.Target{Kind: target.KindVPS, Env: target.EnvProd}
	f := scan.Finding{ID: "01FINDINGDEMO", Kind: "config", OSVID: "expose_php", Summary: "demo"}
	view := serverInventoryView(tg, inv, f)
	body, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	prompt := ServerPrompt(view, i18n.EN)
	for _, out := range []string{string(body), prompt} {
		for _, bad := range []string{"203.0.113.7", "9200", "listener", "Listener"} {
			if strings.Contains(out, bad) {
				t.Errorf("the agent reads %q:\n%s", bad, out)
			}
		}
	}
	noListenField(t, reflect.TypeOf(view), map[reflect.Type]bool{})

	// A failed reading is one line, as for anything else not read: no value.
	inv = target.Inventory{Unseen: []target.Unseen{{What: "listeners", Reason: "collect.unseen.listeners"}}}
	view = serverInventoryView(tg, inv, f)
	if len(view.NotRead) != 1 || view.NotRead[0] != (ServerUnseenView{What: "listeners", Reason: "collect.unseen.listeners"}) {
		t.Fatalf("not read %+v", view.NotRead)
	}
}

func noListenField(t *testing.T, ty reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	switch ty.Kind() {
	case reflect.Slice, reflect.Pointer, reflect.Map:
		noListenField(t, ty.Elem(), seen)
	case reflect.Struct:
		if seen[ty] {
			return
		}
		seen[ty] = true
		for i := 0; i < ty.NumField(); i++ {
			sf := ty.Field(i)
			name := strings.ToLower(sf.Name + " " + sf.Tag.Get("json"))
			for _, bad := range []string{"listen", "port", "address", "scope"} {
				if strings.Contains(name, bad) {
					t.Errorf("%s.%s: the agent's view may not hold %s", ty.Name(), sf.Name, bad)
				}
			}
			if sf.Type == reflect.TypeOf(target.Listener{}) {
				t.Errorf("%s.%s is a listener", ty.Name(), sf.Name)
			}
			noListenField(t, sf.Type, seen)
		}
	}
}
