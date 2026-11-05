package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/fix"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

// ErrNothingToScan is what Deps.ScanProject returns for a folder holding no
// list of dependencies Michel reads.
var ErrNothingToScan = errors.New("nothing to scan")

// scanBound bounds a scan started from the page: past it, the sweep of the
// next start would call it interrupted anyway.
const scanBound = scan.StaleScanAfter

// AddProjectRequest is the body of POST /projects. Nothing else: a test
// command stays on the command line (R13), and an unknown field is refused.
type AddProjectRequest struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

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

// addProject registers a folder of this computer, as michel project add does:
// same defaults (classification of the policy, level 1), audited, refusals
// included. The answer holds no path.
func (s *server) addProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	var req AddProjectRequest
	if !s.readJSONHint(w, r, &req, i18n.T(lang, "api.project.add.bad_json_hint")) {
		return
	}
	raw, name := strings.TrimSpace(req.Path), strings.TrimSpace(req.Name)
	refuse := func(status int, key string) {
		// The audit keeps what was asked, bounded and without control characters.
		ev := map[string]any{"path": boundedForAudit(raw, maxPathLen), "reason": key}
		if _, err := s.deps.Audit.Record(ctx, audit.Event{Actor: decisionAuthor, Action: "project.add",
			Target: boundedForAudit(name, maxProjectName), Result: "denied", Evidence: ev}); err != nil {
			s.auditFailed(w, r)
			return
		}
		s.failedBody(w, status, lang, key, key+"_hint")
	}
	if !validProjectName(name) {
		refuse(http.StatusBadRequest, "api.project.bad_name")
		return
	}
	path, key := s.projectFolder(raw)
	if key != "" {
		refuse(http.StatusBadRequest, key)
		return
	}
	repo := project.NewRepo(s.deps.Store)
	repo.DefaultClassification = s.currentPolicy().Sovereignty.DataClassification
	list, err := repo.List(ctx)
	if err != nil {
		s.internal(w, r)
		return
	}
	for _, p := range list {
		if p.Active && foldPath(p.Path) == foldPath(path) {
			refuse(http.StatusConflict, "api.project.duplicate")
			return
		}
	}
	added, err := repo.Add(ctx, project.Project{Name: name, Path: path})
	switch {
	case errors.Is(err, project.ErrDuplicateName):
		refuse(http.StatusConflict, "api.project.duplicate")
		return
	case errors.Is(err, project.ErrNotADirectory):
		refuse(http.StatusBadRequest, "api.project.not_dir")
		return
	case err != nil:
		s.internal(w, r)
		return
	}
	if _, err := s.deps.Audit.Record(ctx, audit.Event{Actor: decisionAuthor, Action: "project.add", Target: added.Name, Result: "ok",
		Evidence: map[string]any{"path": added.Path, "classification": string(added.Classification), "fix_level": added.FixLevel}}); err != nil {
		// No project without its trace.
		_, _ = repo.Purge(ctx, added.ID)
		s.auditFailed(w, r)
		return
	}
	v, err := s.projectView(ctx, lang, added)
	if err != nil {
		s.internal(w, r)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

// boundedForAudit is s without control characters, cut at max runes.
func boundedForAudit(s string, max int) string {
	s = scan.SanitizeText(s)
	if rs := []rune(s); len(rs) > max {
		return string(rs[:max])
	}
	return s
}

// projectFolder checks the path typed on the page and returns the folder it
// really is (links followed, nothing to come back to later), or the code of the
// refusal. The page is reachable with the token alone: a project is a folder
// that a later fix copies, so it is never by surprise a folder of the system,
// a whole disk, the home folder, Michel's own data or a network share.
func (s *server) projectFolder(raw string) (string, string) {
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
	if strangeOnWindows(raw) || s.forbiddenFolder(clean) {
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
	if s.forbiddenFolder(real) {
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

// systemFolders are the folders that belong to the system, with everything
// under them.
func systemFolders() []string {
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
func (s *server) forbiddenFolder(p string) bool {
	if filepath.Dir(p) == p {
		return true // a disk, or /
	}
	for _, sys := range systemFolders() {
		if isUnder(p, sys) {
			return true
		}
	}
	for _, shared := range sharedFolders {
		if foldPath(p) == foldPath(shared) {
			return true
		}
	}
	data := s.dataDir()
	home := s.deps.Servers.Home
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

// scanProject starts the check of a project in the background and answers
// 202; GET /projects follows it (scanning, last_failure). One at a time per
// project: a second click is told so.
func (s *server) scanProject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lang, ok := s.requestLang(w, r)
	if !ok {
		return
	}
	if s.deps.ScanProject == nil {
		s.failedBody(w, http.StatusServiceUnavailable, lang, "api.project.scan_unavailable", "api.project.scan_unavailable_hint")
		return
	}
	p, found, err := s.activeProject(ctx, r.PathValue("name"))
	if err != nil {
		s.internal(w, r)
		return
	}
	if !found {
		s.fail(w, http.StatusNotFound, i18n.T(lang, "api.project_not_found"), "")
		return
	}
	// A check of this project that runs holds the lock: its own sentence first.
	if run, _ := s.scans.get(p.ID); run.running {
		s.failedBody(w, http.StatusConflict, lang, "api.project.scan_running", "api.project.scan_running_hint")
		return
	}
	// A check does not read a folder a click is writing, and no click starts
	// during a check (R35).
	unlock := func() {}
	if s.deps.Fix != nil {
		var free bool
		if unlock, free = fix.TryGitLock(*s.deps.Fix, p.ID); !free {
			s.failedBody(w, http.StatusConflict, lang, "api.git.busy", "api.git.busy_hint")
			return
		}
	}
	if !s.scans.begin(p.ID) {
		unlock()
		s.failedBody(w, http.StatusConflict, lang, "api.project.scan_running", "api.project.scan_running_hint")
		return
	}
	if _, err := s.deps.Audit.Record(ctx, audit.Event{Actor: decisionAuthor, Action: "project.scan", Target: p.Name, Result: "started",
		Evidence: map[string]any{}}); err != nil {
		s.scans.end(p.ID, s.deps.Now(), "api.project.scan_failed")
		unlock()
		s.auditFailed(w, r)
		return
	}
	run := s.deps.ScanProject
	started := s.goBackground(func(ctx context.Context) {
		defer unlock()
		ctx, cancel := context.WithTimeout(ctx, scanBound)
		defer cancel()
		code := "api.project.scan_failed"
		defer func() {
			// A parser that panics on an odd file ends this check, not michel
			// serve. The reason may name files: the terminal only.
			if r := recover(); r != nil {
				fmt.Fprintln(os.Stderr, i18n.T(s.deps.Lang, "api.project.scan_panic", p.Name, scan.SanitizeText(fmt.Sprint(r))))
			}
			s.scans.end(p.ID, s.deps.Now(), code)
		}()
		code = codeOfScan(run(ctx, p))
	})
	if !started {
		s.scans.end(p.ID, s.deps.Now(), "api.project.scan_failed")
		unlock()
		s.fail(w, http.StatusServiceUnavailable, i18n.T(lang, "api.closing"), "")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

// codeOfScan is the catalog key of how a scan ended, "" for done: only a code
// reaches the page, the error may name files.
func codeOfScan(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, osvdb.ErrDatabaseMissing):
		return "api.project.no_database"
	case errors.Is(err, ErrNothingToScan):
		return "api.project.nothing_to_scan"
	case errors.Is(err, scan.ErrScanRunning):
		return "api.project.scan_elsewhere"
	}
	return "api.project.scan_failed"
}

// scanState adds to v how the scan started from the page stands.
func (s *server) scanState(lang i18n.Lang, p project.Project, v *ProjectView) {
	run, tracked := s.scans.get(p.ID)
	if !tracked {
		return
	}
	v.Scanning = run.running
	if run.running || run.ok {
		return
	}
	v.LastFailure = &TargetLastCheck{At: stamp(run.at), Code: run.code, Error: i18n.T(lang, run.code)}
	if i18n.Has(run.code + "_hint") {
		v.LastFailure.Hint = i18n.T(lang, run.code+"_hint")
	}
}
