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
