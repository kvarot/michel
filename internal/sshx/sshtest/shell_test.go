package sshtest_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/sshx/sshtest"
)

func TestShellRefusesUnknownConstructs(t *testing.T) {
	sh := &sshtest.Shell{UID: 0}
	srv := sshtest.New(t, sshtest.Options{Files: map[string]string{"/etc/a.ini": "x = 1\n"}, Shell: sh.Func()})
	for _, s := range []string{
		"cat '/etc/a.ini' | sh", "rm -rf /", "echo $X", "echo `id`", "x=1 echo", "cat /etc/*.ini", "eval x",
		"echo a && echo b", "sed -i 's/a/b/' '/etc/a.ini'", "echo \"$(reboot)\"", "( echo x )",
	} {
		var out, errb bytes.Buffer
		if code := sh.Run(srv, s, &out, &errb); code == 0 {
			t.Errorf("%q ran (exit 0)", s)
		}
	}
	if v, _ := srv.File("/etc/a.ini"); v != "x = 1\n" {
		t.Error("file changed")
	}
}

func TestShellErrexitAndTrap(t *testing.T) {
	sh := &sshtest.Shell{UID: 0}
	srv := sshtest.New(t, sshtest.Options{Files: map[string]string{"/etc/a.ini": "x = 1\n"}, Shell: sh.Func()})
	script := "set -eu\nundo() {\n  echo undone >&2\n}\ntrap 'undo' EXIT\ncmp -s '/etc/a.ini' '/missing' || true\n[ -e '/missing' ]\necho never\n"
	var out, errb bytes.Buffer
	code := sh.Run(srv, script, &out, &errb)
	if code != 1 || strings.Contains(out.String(), "never") || !strings.Contains(errb.String(), "undone") {
		t.Fatalf("exit %d out %q err %q", code, out.String(), errb.String())
	}
}
