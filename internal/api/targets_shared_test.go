package api

import (
	"net/http"
	"reflect"
	"testing"
)

// The page leaves the trace michel target add leaves: same action, same
// evidence (internal/cli TestTargetAddAuditIsTheSharedOne).
func TestTargetAddAuditIsTheSharedOne(t *testing.T) {
	tf := newTargetFixture(t)
	code, body := tf.send("POST", "/api/v1/targets", `{"name":"shared","host":"192.0.2.96","user":"d","kind":"shared","env":"preprod","fix_level":2}`)
	if code != http.StatusCreated {
		t.Fatalf("add = %d %s", code, body)
	}
	rows := tf.auditRows("target.add")
	want := map[string]any{"name": "shared", "kind": "shared", "env": "preprod", "fix_level": float64(2), "links": float64(0), "rules_written": float64(1)}
	if len(rows) != 1 || rows[0].actor != targetActor || !reflect.DeepEqual(rows[0].evidence, want) {
		t.Errorf("audit = %+v, want %v", rows, want)
	}
}

// The page leaves the trace michel target set leaves (internal/cli
// TestTargetSetAuditIsTheSharedOne).
func TestTargetUpdateAuditIsTheSharedOne(t *testing.T) {
	tf := newTargetFixture(t)
	code, body := tf.send("POST", "/api/v1/targets", `{"name":"upd","host":"192.0.2.98","user":"d"}`)
	if code != http.StatusCreated {
		t.Fatalf("add = %d %s", code, body)
	}
	code, body = tf.send("PATCH", "/api/v1/targets/upd", `{"fix_level":2,"site_url":"https://www.example.test/","check_interval":"12h"}`)
	if code != http.StatusOK {
		t.Fatalf("patch = %d %s", code, body)
	}
	rows := tf.auditRows("target.update")
	want := map[string]any{"name": "upd", "changed": []any{"site_url", "fix_level", "check_interval"}, "rules_written": float64(1),
		"rules_removed": float64(0), "host_key_reset": false}
	if len(rows) != 1 || rows[0].actor != targetActor || !reflect.DeepEqual(rows[0].evidence, want) {
		t.Errorf("audit = %+v, want %v", rows, want)
	}
}
