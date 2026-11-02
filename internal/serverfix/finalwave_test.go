package serverfix_test

import (
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/sshx/sshtest"
)

// Final wave I2: a command that fails after the change with an exit code
// of the scripts' own (systemctl reload exiting 5, "unit not found") is
// never read as that code. POSIX sh exits with the failing command's status
// after an EXIT trap that does not call exit: the rollback ends with its own
// code instead, 9 when the files were put back.
func TestFailureAfterChangeEndsWithTheRollbackCode(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	for _, failing := range []int{3, 4, 5, 6, 7, 126, 127, 1} {
		h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
		h.rels = []int{failing} // the reload after the change; the rollback's reload works
		code, stderr := h.run(b.Apply)
		if code != serverfix.ExitRolledBack || !strings.Contains(stderr, "echec: fichiers remis") {
			t.Errorf("reload exit %d: script exit %d, stderr %q", failing, code, stderr)
		}
		if h.file(t, fpmIni) != iniText {
			t.Errorf("reload exit %d: php.ini not restored", failing)
		}
	}
	// The rollback that fails still says 8.
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	h.rels = []int{5, 5}
	if code, stderr := h.run(b.Apply); code != serverfix.ExitRollbackFail || !strings.Contains(stderr, "retour en arriere incomplet") {
		t.Errorf("failed rollback: exit %d %q", code, stderr)
	}
}

// The scripts' own exit 5 (the line changed) comes before the trap is
// armed: nothing was changed, nothing is rolled back, and the rollback code
// cannot hide it.
func TestLineMovedStopsBeforeTheTrap(t *testing.T) {
	b := render(t, setDirective("fpm", "display_errors", "0", ""), demoTarget())
	trap := strings.Index(b.Apply, "trap 'rollback' EXIT")
	moved := strings.Index(b.Apply, "ligne introuvable")
	if trap < 0 || moved < 0 || moved > trap {
		t.Fatalf("exit 5 after the trap (trap %d, exit 5 %d):\n%s", trap, moved, b.Apply)
	}
	if !strings.Contains(b.Apply, "\n  exit 9\n") {
		t.Errorf("the rollback does not end with exit 9:\n%s", b.Apply)
	}
	h := newHarness(t, &sshtest.Shell{UID: 0, Home: "/root"})
	h.srv.SetFile(fpmIni, "[PHP]\nengine = On\n\ndisplay_errors = On\n")
	code, stderr := h.run(b.Apply)
	if code != serverfix.ExitLineMoved || strings.Contains(stderr, "fichiers remis") {
		t.Errorf("moved line: exit %d %q", code, stderr)
	}
	if strings.Contains(strings.Join(h.sh.Ran(), "\n"), "systemctl") {
		t.Error("moved line: a reload ran")
	}
}
