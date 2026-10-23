package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kvarot/michel/internal/secret"
	"github.com/kvarot/michel/internal/store"
)

// runIn is run with stdin fed from in.
func runIn(t *testing.T, dir string, in io.Reader, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	deps := &Deps{Stdout: &out, Stderr: &errOut, Now: time.Now, Stdin: in}
	t.Cleanup(func() { deps.Close() })
	cmd := NewRootCmd(deps)
	cmd.SetArgs(append([]string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", dir, "--lang", "en"}, args...))
	err := cmd.Execute()
	deps.Close()
	return out.String(), errOut.String(), err
}

// allAuditText returns every audit row as one text, for leak checks.
func allAuditText(t *testing.T, dir string) string {
	t.Helper()
	s, err := store.Open(filepath.Join(dir, "michel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.DB().Query(`SELECT action, target, result, correlation_id, evidence FROM audit_event`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var a, tg, r, c, ev string
		if err := rows.Scan(&a, &tg, &r, &c, &ev); err != nil {
			t.Fatal(err)
		}
		b.WriteString(a + " " + tg + " " + r + " " + c + " " + ev + "\n")
	}
	return b.String()
}

func TestSecretSetFromStdinNeverPrintsValue(t *testing.T) {
	const value = "hunter2-tok"
	dir := t.TempDir()
	var outputs []string
	check := func(stdout, stderr string, err error) {
		outputs = append(outputs, stdout, stderr)
		if err != nil {
			outputs = append(outputs, err.Error())
		}
	}

	stdout, stderr, err := runIn(t, dir, strings.NewReader(value+"\r\n"), "secret", "set", "smtp-password")
	check(stdout, stderr, err)
	if err != nil {
		t.Fatalf("set: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stdout, "smtp-password") {
		t.Errorf("stdout = %q", stdout)
	}
	warned := strings.Contains(stderr, "plain text")
	if warned == (runtime.GOOS == "windows") {
		t.Errorf("plain-storage warning shown=%v on %s: %q", warned, runtime.GOOS, stderr)
	}

	st, err := secret.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("smtp-password")
	if err != nil || string(got) != value {
		t.Fatalf("stored = %q, %v (one trailing newline must be trimmed)", got, err)
	}

	rows := auditRows(t, dir, "secret.set")
	if len(rows) != 1 || rows[0].target != "smtp-password" || rows[0].result != "ok" ||
		!reflect.DeepEqual(rows[0].evidence, map[string]any{"name": "smtp-password"}) {
		t.Fatalf("secret.set rows = %+v", rows)
	}

	// Refusals: reserved name, invalid name, empty value. None prints the value.
	stdout, stderr, err = runIn(t, dir, strings.NewReader(value), "secret", "set", secret.ReservedAPIToken)
	check(stdout, stderr, err)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("reserved name: err = %v", err)
	}
	stdout, stderr, err = runIn(t, dir, strings.NewReader(value), "secret", "set", "Bad/Name")
	check(stdout, stderr, err)
	if err == nil || !strings.Contains(err.Error(), "secret name is not valid") {
		t.Errorf("invalid name: err = %v", err)
	}
	stdout, stderr, err = runIn(t, dir, strings.NewReader("\n"), "secret", "set", "empty")
	check(stdout, stderr, err)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty value: err = %v", err)
	}
	stdout, stderr, err = runIn(t, dir, nil, "secret", "list", "--json")
	check(stdout, stderr, err)
	if err != nil {
		t.Fatal(err)
	}

	if names, _ := st.List(); !reflect.DeepEqual(names, []string{"smtp-password"}) {
		t.Errorf("names after refusals = %v", names)
	}
	if n := len(auditRows(t, dir, "secret.set")); n != 1 {
		t.Errorf("refusals were audited as set: %d rows", n)
	}
	for _, o := range outputs {
		if strings.Contains(o, value) {
			t.Fatalf("value leaked in output %q", o)
		}
	}
	if a := allAuditText(t, dir); strings.Contains(a, value) {
		t.Fatalf("value leaked in audit_event:\n%s", a)
	}
}

func TestSecretListAndDelete(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := runIn(t, dir, nil, "secret", "list")
	if err != nil || !strings.Contains(stdout, "No secret") {
		t.Fatalf("empty list: %q %v", stdout, err)
	}
	for _, n := range []string{"webhook", "smtp-password"} {
		if _, stderr, err := runIn(t, dir, strings.NewReader("v-"+n), "secret", "set", n); err != nil {
			t.Fatalf("set %s: %v %s", n, err, stderr)
		}
	}
	// api-token is written by michel serve, never by secret set.
	st, _ := secret.Open(dir)
	if err := st.Set(secret.ReservedAPIToken, []byte("tok")); err != nil {
		t.Fatal(err)
	}

	stdout, _, err = runIn(t, dir, nil, "secret", "list")
	if err != nil || stdout != "api-token\nsmtp-password\nwebhook\n" {
		t.Fatalf("list = %q, %v", stdout, err)
	}
	stdout, _, err = runIn(t, dir, nil, "secret", "list", "--json")
	var js struct {
		Names     []string `json:"names"`
		Protected bool     `json:"protected"`
	}
	if err != nil || json.Unmarshal([]byte(stdout), &js) != nil {
		t.Fatalf("list --json = %q, %v", stdout, err)
	}
	if !reflect.DeepEqual(js.Names, []string{"api-token", "smtp-password", "webhook"}) || js.Protected != secret.Protected() {
		t.Fatalf("json = %+v", js)
	}
	if strings.Contains(stdout, "v-webhook") {
		t.Fatal("list shows a value")
	}

	stdout, _, err = runIn(t, dir, nil, "secret", "delete", "webhook")
	if err != nil || !strings.Contains(stdout, "webhook") {
		t.Fatalf("delete: %q %v", stdout, err)
	}
	if _, _, err := runIn(t, dir, nil, "secret", "delete", secret.ReservedAPIToken); err != nil {
		t.Fatalf("delete api-token: %v", err)
	}
	_, _, err = runIn(t, dir, nil, "secret", "delete", "webhook")
	if err == nil || !strings.Contains(err.Error(), "no secret named webhook") {
		t.Fatalf("second delete: %v", err)
	}
	stdout, _, _ = runIn(t, dir, nil, "secret", "list")
	if stdout != "smtp-password\n" {
		t.Fatalf("list after delete = %q", stdout)
	}
	rows := auditRows(t, dir, "secret.delete")
	if len(rows) != 2 || rows[0].target != "webhook" || !reflect.DeepEqual(rows[0].evidence, map[string]any{"name": "webhook"}) ||
		rows[1].target != "api-token" {
		t.Fatalf("secret.delete rows = %+v", rows)
	}
	if n := len(auditRows(t, dir, "secret.list")); n != 0 {
		t.Fatalf("secret.list audited %d times", n)
	}
}
