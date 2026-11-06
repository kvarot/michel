package project

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode"
)

// maxPathLen bounds the path of a project; maxProjectName its name, in runes.
const (
	maxPathLen     = 4096
	maxProjectName = 64
)

// projectNameRe keeps a name readable in a list and in an address: letters and
// digits, with spaces, dots, dashes and underscores inside.
var projectNameRe = regexp.MustCompile(`^[\p{L}\p{N}](?:[\p{L}\p{M}\p{N} ._-]*[\p{L}\p{M}\p{N}_-])?$`)

func validProjectName(name string) bool {
	return len([]rune(name)) <= maxProjectName && !strings.Contains(name, "..") && projectNameRe.MatchString(name)
}

// Folders are the folders of this computer that a project may never hold nor
// sit in, besides those of the system: Michel's own data and the home folder.
// An empty Home is the home folder of the user.
type Folders struct {
	DataDir string
	Home    string
}

// projectFolder checks the path given for a project and returns the folder it
// really is (links followed, nothing to come back to later), or the code of the
// refusal. A project is a folder that a later fix copies, so it is never by
// surprise a folder of the system, a whole disk, the home folder, Michel's own
// data or a network share.
func projectFolder(raw string, f Folders) (string, string) {
	if isNetworkPath(raw) {
		return "", "api.project.forbidden_path"
	}
	if raw == "" || !filepath.IsAbs(raw) || hasDotDot(raw) {
		return "", "api.project.relative_path"
	}
	if len(raw) > maxPathLen || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", "api.project.not_dir"
	}
	clean := filepath.Clean(raw)
	// Before anything touches the disk: opening \??\UNC\host\share would send
	// the Windows session's credentials to that host.
	if runtime.GOOS == "windows" && (!isDriveLetterPath(clean) || hasDeviceName(clean)) {
		return "", "api.project.forbidden_path"
	}
	if strangeOnWindows(raw) || forbiddenFolder(clean, f) {
		return "", "api.project.forbidden_path"
	}
	// Each step from the top, without going through a link: a link is refused
	// before the Stat below follows it, wherever it leads.
	if reparsePointOnTheWay(clean) {
		return "", "api.project.forbidden_path"
	}
	fi, err := os.Stat(clean)
	if err != nil || !fi.IsDir() {
		return "", "api.project.not_dir"
	}
	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", "api.project.not_dir"
	}
	if forbiddenFolder(real, f) {
		return "", "api.project.forbidden_path"
	}
	return real, ""
}

// hasDotDot tells whether a segment of the path is "..", whatever the slash.
func hasDotDot(p string) bool {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

// isNetworkPath tells \\host\share and //host/share (and the \\?\ forms): just
// opening one sends the Windows session's credentials to that host. On Unix
// //etc is /etc, a spelling refused as well.
func isNetworkPath(p string) bool {
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`) || strings.HasPrefix(p, `\/`) || strings.HasPrefix(p, `/\`)
}

// isDriveLetterPath is the only form of path accepted on Windows: a letter, a
// colon and a backslash, on a cleaned path. Everything else (\??\, \\?\, \\.\,
// a share) is a way around what the other checks read.
func isDriveLetterPath(clean string) bool {
	if len(clean) < 3 || clean[1] != ':' || clean[2] != '\\' {
		return false
	}
	c := clean[0] | 0x20
	return 'a' <= c && c <= 'z'
}

// hasDeviceName tells a segment that Windows reads as a device, whatever its
// extension or the spaces after it: C:\Sites\NUL.txt is not a folder.
func hasDeviceName(p string) bool {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		base, _, _ := strings.Cut(seg, ".")
		switch strings.ToUpper(strings.TrimRight(base, " ")) {
		case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
			"COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
			"LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³":
			return true
		}
	}
	return false
}

// reparsePointOnTheWay walks a cleaned path from its top and tells whether the
// path or one of its parents is a reparse point (a junction or a link), without
// ever going through one. EvalSymlinks does not follow a junction. A step that
// cannot be read for lack of rights is passed; one that does not exist ends the
// walk, and the caller says the folder is not there.
func reparsePointOnTheWay(clean string) bool {
	vol := filepath.VolumeName(clean)
	cur := vol + string(filepath.Separator)
	for _, seg := range strings.FieldsFunc(clean[len(vol):], func(r rune) bool { return r == filepath.Separator }) {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrPermission):
			continue
		case err != nil:
			return false
		case isReparsePoint(fi):
			return true
		}
	}
	return false
}

// strangeOnWindows tells the spellings Windows reads as another name: a
// segment ending with a dot or a space (C:\Windows. is C:\Windows), or a second
// colon (a hidden stream of the folder).
func strangeOnWindows(p string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	rest := p[len(filepath.VolumeName(p)):]
	if strings.Contains(rest, ":") {
		return true
	}
	for _, seg := range strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' }) {
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return true
		}
	}
	return false
}

// SystemFolders are the folders that belong to the system, with everything
// under them: no project is one of them or inside one.
func SystemFolders() []string {
	switch runtime.GOOS {
	case "windows":
		out := []string{}
		for _, env := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"} {
			if v := os.Getenv(env); v != "" {
				out = append(out, filepath.Clean(v))
			}
		}
		return append(out, `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`)
	case "darwin":
		return []string{"/System", "/Library", "/Applications", "/bin", "/sbin", "/usr", "/etc", "/dev", "/private/etc"}
	}
	return []string{"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/proc", "/run", "/sbin", "/sys", "/usr"}
}

// sharedFolders hold many things, and are no project themselves; a folder
// under them is fine (/var/www/site). The folder that holds the home folders
// on Windows is covered by the rule on the parents of the home folder.
var sharedFolders = []string{"/home", "/Users", "/var", "/opt", "/srv", "/mnt", "/media", "/tmp", "/private", "/private/var", "/Volumes"}

// forbiddenFolder applies the list to a cleaned absolute path.
func forbiddenFolder(p string, f Folders) bool {
	if filepath.Dir(p) == p {
		return true // a disk, or /
	}
	for _, sys := range SystemFolders() {
		if isUnder(p, sys) {
			return true
		}
	}
	for _, shared := range sharedFolders {
		if foldPath(p) == foldPath(shared) {
			return true
		}
	}
	data := f.DataDir
	home := f.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	for _, kept := range []string{home, data} {
		if kept == "" {
			continue
		}
		for _, k := range []string{filepath.Clean(kept), resolved(kept)} {
			if isUnder(k, p) { // the home or the data folder is inside p, or is p
				return true
			}
		}
	}
	for _, k := range []string{filepath.Clean(data), resolved(data)} {
		if data != "" && isUnder(p, k) {
			return true
		}
	}
	if home != "" && (hiddenBelow(p, filepath.Clean(home)) || hiddenBelow(p, resolved(home))) {
		return true
	}
	return false
}

// hiddenBelow tells whether p is under root through a folder whose name starts
// with a dot, where the home folder keeps its secrets (.ssh, .config).
func hiddenBelow(p, root string) bool {
	if !isUnder(p, root) {
		return false
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg != "." && strings.HasPrefix(seg, ".") {
			return true
		}
	}
	return false
}

// resolved is p with its links followed, or p cleaned when that fails.
func resolved(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// foldPath is the path as this system compares it.
func foldPath(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(p)
	}
	return p
}

// isUnder tells whether p is root or inside it.
func isUnder(p, root string) bool {
	p, root = foldPath(p), foldPath(root)
	if p == root {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(p, strings.TrimSuffix(root, sep)+sep)
}
