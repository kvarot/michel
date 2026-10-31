package fix

import (
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/secret"
)

func TestAttemptTokenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := secret.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const id = "01JABCDEFGHJKMNPQRSTVWXYZ0"
	if CheckAttemptToken(st, id, "tok-1") {
		t.Fatal("check passes before any token is set")
	}
	if err := SetAttemptToken(st, id, "tok-1"); err != nil {
		t.Fatal(err)
	}
	raw, err := st.Get("fix-token-" + strings.ToLower(id))
	if err != nil || strings.Contains(string(raw), "tok-1") || len(raw) != 64 {
		t.Fatalf("stored value = %q, %v (want the SHA-256 hex, never the token)", raw, err)
	}
	for _, c := range []struct {
		attempt, token string
		want           bool
	}{
		{id, "tok-1", true},
		{strings.ToLower(id), "tok-1", true},
		{id, "tok-2", false},
		{id, "", false},
		{"01JOTHERATTEMPT00000000000", "tok-1", false},
		{"../x", "tok-1", false},
	} {
		if got := CheckAttemptToken(st, c.attempt, c.token); got != c.want {
			t.Errorf("CheckAttemptToken(%q, %q) = %v, want %v", c.attempt, c.token, got, c.want)
		}
	}
	if err := SetAttemptToken(st, id, ""); err == nil {
		t.Error("empty token accepted")
	}
	if err := DeleteAttemptToken(st, id); err != nil {
		t.Fatal(err)
	}
	if CheckAttemptToken(st, id, "tok-1") {
		t.Error("check passes after delete")
	}
	if err := DeleteAttemptToken(st, id); err != nil {
		t.Errorf("second delete: %v", err)
	}
	if CheckAttemptToken(nil, id, "tok-1") {
		t.Error("nil store passes")
	}
}
