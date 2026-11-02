package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/servercheck"
)

// Final wave: a server alert on a generic webhook carries its own marker
// and its kind, never the marker of the "a fix waits" message, so a
// consumer can tell them apart.
func TestServerAlertWebhookHasItsOwnMarker(t *testing.T) {
	h := startHook(t, http.StatusNoContent, "")
	n, err := New(hookChannel(h.URL, "", ""), hookDeps(nil, memSecrets{}))
	if err != nil {
		t.Fatal(err)
	}
	out := SendServerAlert(context.Background(), []Notifier{n}, servercheck.AlertInput{Target: demoServer(), Kind: servercheck.AlertRolledBack},
		"", time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC))
	if len(out) != 1 || out[0].Result != ResultOK {
		t.Fatalf("deliveries %+v", out)
	}
	_, body := h.last()
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body: %v\n%s", err, body)
	}
	if doc["michel_server_alert"] != float64(1) || doc["kind"] != servercheck.AlertRolledBack {
		t.Errorf("server alert payload: %s", body)
	}
	if _, ok := doc["michel_fix_waiting"]; ok {
		t.Errorf("server alert reuses the fix-waiting marker: %s", body)
	}
	if doc["title"] == "" || doc["text"] == "" {
		t.Errorf("no text: %s", body)
	}
	// The fix-waiting message keeps its own.
	SendFixWaiting(context.Background(), []Notifier{n}, 1, "")
	_, body = h.last()
	doc = nil
	if err := json.Unmarshal(body, &doc); err != nil || doc["michel_fix_waiting"] != float64(1) {
		t.Errorf("fix waiting payload: %v %s", err, body)
	}
}
