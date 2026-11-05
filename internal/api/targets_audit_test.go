package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kvarot/michel/internal/target"
)

// A host-key refusal whose audit row cannot be written answers 500, not the
// plain refusal: the refusal left no trace.
func TestHostKeyRefusalAuditFailure(t *testing.T) {
	tf := newTargetFixture(t)
	v := tf.add("")
	if _, err := tf.st.DB().Exec(`CREATE TRIGGER fail_refusal BEFORE INSERT ON audit_event WHEN NEW.action = 'target.hostkey' AND NEW.result = 'refused'
		BEGIN SELECT RAISE(ABORT, 'disk on fire'); END`); err != nil {
		t.Fatal(err)
	}
	check := func(what, body string) {
		t.Helper()
		code, out := tf.send("POST", "/api/v1/targets/"+v.ID+"/hostkey", body)
		var eb FixErrorBody
		_ = json.Unmarshal([]byte(out), &eb)
		if code != http.StatusInternalServerError || eb.Code != "api.target.refusal_audit_failed" {
			t.Errorf("%s = %d %s", what, code, out)
		}
		if got := tf.view(v.ID); got.HostKey != "" && got.HostKey != "SHA256:previous" {
			t.Errorf("%s pinned %q", what, got.HostKey)
		}
	}
	check("wrong fingerprint", `{"fingerprint":"SHA256:wrong"}`)
	if err := target.NewRepo(tf.st).SetHostKey(context.Background(), v.ID, "SHA256:previous"); err != nil {
		t.Fatal(err)
	}
	check("changed key", `{"fingerprint":"`+tf.ssh.HostKeyFingerprint()+`"}`)
}
