package project

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// makeJunction makes a Windows junction, which needs no privilege: it always
// runs on Windows, and a failure to make one is a failure of the test.
func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("cmd", "/c", "rmdir", link).Run() })
}

func TestReparsePointOnTheWay(t *testing.T) {
	dir := t.TempDir()
	if reparsePointOnTheWay(dir) {
		t.Errorf("an ordinary folder is seen as a link: %s", dir)
	}
	if reparsePointOnTheWay(filepath.Join(dir, "missing", "deeper")) {
		t.Error("a folder that does not exist is not a link")
	}
	if runtime.GOOS != "windows" {
		t.Skip("NOT CHECKED: reparse points exist only on Windows")
	}
	makeJunction(t, filepath.Join(dir, "j"), t.TempDir())
	if !reparsePointOnTheWay(filepath.Join(dir, "j")) || !reparsePointOnTheWay(filepath.Join(dir, "j", "below")) {
		t.Error("the junction was not seen")
	}
}

func TestOnlyADriveLetter(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\Sites\a`: true, `d:\a`: true,
		`\??\C:\Windows`: false, `\\?\C:\Windows`: false, `\\.\C:\Windows`: false, `\\host\share\a`: false,
		`1:\a`: false, `C:a`: false, `C:`: false, `\a`: false, ``: false, `é:\a`: false,
	} {
		if got := isDriveLetterPath(p); got != want {
			t.Errorf("isDriveLetterPath(%q) = %v", p, got)
		}
	}
}

func TestDeviceNames(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\NUL`: true, `C:\Sites\con`: true, `C:\Sites\COM1.txt`: true, `C:\Sites\LPT9`: true, `C:\a\conin$`: true,
		`C:\a\AUX \b`: true, `C:\a\COM¹`: true, `C:\a\prn.x.y`: true,
		`C:\Sites\conference`: false, `C:\Sites\com10`: false, `C:\Sites\lpt`: false, `C:\Sites\nullable`: false, `C:\Sites\my.con`: false,
	} {
		if got := hasDeviceName(p); got != want {
			t.Errorf("hasDeviceName(%q) = %v", p, got)
		}
	}
}
