package serverfix

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/target"
)

// correctionRe is a correction id (a ULID in practice).
var correctionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// RootBackups is the folder of the backups of a root bundle on the server:
// root owns it, nobody else may write it, Michel never empties it.
const RootBackups = "/var/lib/michel/backups"

// Fixed texts of the scripts: short, ASCII, the same whoever runs them.
const (
	msgRoot       = "lance ce script en root"
	msgNotRoot    = "ne lance pas ce script en root"
	msgOwner      = "lance ce script en tant que proprietaire du fichier"
	msgApplied    = "correction deja appliquee"
	msgNoBackup   = "sauvegarde absente"
	msgUnsafeBak  = "sauvegarde non sure"
	msgUnsafeDir  = "dossier non sur"
	msgUnsafeFile = "fichier non sur"
	msgNoLine     = "ligne introuvable"
	msgChanged    = "fichier modifie depuis la verification"
	msgRolled     = "echec: fichiers remis"
	msgRollFailed = "retour en arriere incomplet"
	msgSnapshot   = "retour par ton snapshot"
	msgDoneA      = "correction appliquee"
	msgDoneU      = "correction annulee"
	msgLink       = "lien refuse"
)

// Exit codes the scripts use.
const (
	ExitNotRoot      = 3 // wrong user (not root, or root for a .user.ini)
	ExitApplied      = 4 // already applied (Apply), or a backup missing (Undo)
	ExitLineMoved    = 5 // the line changed since the collection
	ExitLink         = 6 // a target file is a symbolic link
	ExitUnsafe       = 7 // a folder, file, binary or backup is not root's and closed
	ExitRollbackFail = 8 // the rollback itself failed: urgent alert
	ExitRolledBack   = 9 // a step failed after the change, the files were put back
)

// The lines rollback() prints on the error output, last: the files were put
// back (then exit 9), or not all of them (then exit 8). Only rollback()
// prints them, so only after the trap was armed.
const (
	MsgRolledBack     = msgRolled
	MsgRollbackFailed = msgRollFailed
)

// ExitLines are the lines a script prints on its error output with each of
// its own refusals (codes 3 to 7), always before any change: an exit code
// in that range without one of its lines is not the script's own (a
// package manager's, or another command's).
func ExitLines(code int) []string {
	switch code {
	case ExitNotRoot:
		return []string{msgRoot, msgNotRoot, msgOwner}
	case ExitApplied:
		return []string{msgApplied, msgNoBackup}
	case ExitLineMoved:
		return []string{msgNoLine, msgChanged}
	case ExitLink:
		return []string{msgLink}
	case ExitUnsafe:
		return []string{msgUnsafeBak, msgUnsafeDir, msgUnsafeFile}
	}
	return nil
}

// Building blocks of the grammar. A case pattern is unquoted: quoted, its
// ? would be a literal character; ? also stands for the space of stat. A
// quoted path, binary, service or package never holds a quote: the
// character sets refuse it upstream. Paths and keys follow the same rules
// as Validate: a written file is in PHP's own trees (rootTreeParts) or is a
// .user.ini, a key is a directive of the embedded rules.
const (
	gUserIni  = `/(?:` + treeSeg + `/)+\.user\.ini`
	gDir      = `'/[A-Za-z0-9._/@+-]+'`
	gFPM      = `'/usr/(?:local/)?s?bin/php-fpm[0-9.]*'`
	gCLI      = `'/usr/(?:local/)?s?bin/php[0-9.]*'`
	gBak      = `"\$B/[0-9]+(?:\.[0-9]+)?"`
	gVal      = `[A-Za-z0-9_./:,@+%-]*`
	gSvc      = `'[A-Za-z0-9][A-Za-z0-9._@-]*'`
	gPkg      = `[A-Za-z0-9][A-Za-z0-9.+_-]*`
	gVer      = `[0-9][A-Za-z0-9.+~:_-]*`
	gID       = `[A-Za-z0-9_-]+`
	gReload   = `(?:systemctl reload ` + gSvc + `|rc-service ` + gSvc + ` reload)`
	gStat     = `case "\$\(stat -c '%u %A' `
	gSafeDir  = `\)" in 0\?d\?\?\?\?-\?\?-\?\) ;; \*\) echo "` + msgUnsafeDir + `" >&2; exit 7;; esac`
	gSafeFile = `\)" in 0\?-\?\?\?\?-\?\?-\?\) ;; \*\) echo "` + msgUnsafeFile + `" >&2; exit 7;; esac`
)

// gPath is a file a script reads or writes; gKey a key as written in the
// file, gKeyRe the same key as the escaped basic regular expression of sed.
var gPath, gKey, gKeyRe = func() (string, string, string) {
	set, err := serverrules.Rules()
	if err != nil {
		panic(err)
	}
	var plain, escaped []string
	for _, r := range set.Config {
		plain = append(plain, regexp.QuoteMeta(r.Directive))
		escaped = append(escaped, strings.ReplaceAll(regexp.QuoteMeta(r.Directive), `\.`, `\\\.`))
	}
	n, e := `(?:`+strings.Join(plain, "|")+`)`, `(?:`+strings.Join(escaped, "|")+`)`
	return `'(?:` + rootTreeRe + `|` + gUserIni + `)'`,
		`(?:` + n + `|php_(?:admin_)?(?:value|flag)\[` + n + `\])`,
		`(?:` + e + `|php_(?:admin_)?(?:value|flag)\\\[` + e + `\\\])`
}()

// Grammar lists the templates every non-empty line of a rendered script
// matches, whole line. Lint refuses any other line. It checks lines one by
// one, not their order: Render builds the order and Hash freezes it.
var Grammar = []string{
	`#!/bin/sh`,
	`# michel correction ` + gID + `: (?:apply|undo)`,
	`# [a-z ,]+`,
	`set -eu`,
	`umask 077`,
	`PATH=/usr/sbin:/usr/bin:/sbin:/bin`,
	`export PATH`,
	`unset PHPRC PHP_INI_SCAN_DIR`,
	`rollback\(\) \{`,
	`  trap - EXIT`,
	`  R=0`,
	`  if \[ ! -L ` + gPath + ` \]; then cat ` + gBak + ` > ` + gPath + ` \|\| R=1; else R=1; fi`,
	`  ` + gReload + ` \|\| R=1`,
	`  \[ "\$R" = 0 \] \|\| \{ echo "` + msgRollFailed + `" >&2; exit 8; \}`,
	`  echo "` + msgRolled + `" >&2`,
	`  exit 9`,
	`\}`,
	`main\(\) \{`,
	`main </dev/null`,
	`\[ "\$\(id -u\)" = 0 \] \|\| \{ echo "` + msgRoot + `" >&2; exit 3; \}`,
	`\[ "\$\(id -u\)" != 0 \] \|\| \{ echo "` + msgNotRoot + `" >&2; exit 3; \}`,
	`B="` + RootBackups + `/` + gID + `"`,
	`B="\$HOME/\.michel/backups/` + gID + `"`,
	gStat + gDir + gSafeDir,
	gStat + gPath + gSafeFile,
	`case "\$\(stat -L -c '%u %A' (?:` + gFPM + `|` + gCLI + `)` + gSafeFile,
	`case "\$\(readlink -f (?:` + gFPM + `|` + gCLI + `)\)" in /usr/(?:local/)?s?bin/php\*/\*\) echo "` + msgUnsafeFile + `" >&2; exit 7;; /usr/(?:local/)?s?bin/php\*\) ;; \*\) echo "` + msgUnsafeFile + `" >&2; exit 7;; esac`,
	gStat + `"\$B"\)" in 0\?d\?\?\?------\) ;; \*\) echo "` + msgUnsafeBak + `" >&2; exit 7;; esac`,
	gStat + gBak + `\)" in 0\?-\?\?\?------\) ;; \*\) echo "` + msgUnsafeBak + `" >&2; exit 7;; esac`,
	`\[ ! -L ` + gPath + ` \] \|\| \{ echo "` + msgLink + `" >&2; exit 6; \}`,
	`\[ -w ` + gPath + ` \] \|\| \{ echo "` + msgOwner + `" >&2; exit 3; \}`,
	`\[ -f ` + gBak + ` \] \|\| \{ echo "` + msgNoBackup + `" >&2; exit 4; \}`,
	`mkdir -p -m 700 '` + path.Dir(RootBackups) + `'`,
	`mkdir -p -m 700 '` + RootBackups + `'`,
	`mkdir -p -m 700 "\$HOME/\.michel/backups"`,
	`case "\$\(sha256sum ` + gPath + `\)" in [0-9a-f]{64}\*\) ;; \*\) echo "` + msgChanged + `" >&2; exit 5;; esac`,
	`mkdir -m 700 "\$B" \|\| \{ echo "` + msgApplied + `" >&2; exit 4; \}`,
	`cat ` + gPath + ` > ` + gBak,
	`trap 'rollback' EXIT`,
	`trap 'exit 1' HUP INT TERM`,
	`trap - EXIT`,
	`sed '[1-9][0-9]*s\|\^\[\[:space:\]\]\*` + gKeyRe + `\[\[:space:\]\]\*=\.\*\$\|` + gKey + ` = ` + gVal + `\|' ` + gBak + ` > ` + gBak,
	`if cmp -s ` + gBak + ` ` + gBak + `; then echo "` + msgNoLine + `" >&2; exit 5; fi`,
	`cat ` + gBak + ` > ` + gBak,
	`printf '\\n%s\\n' '` + gKey + ` = ` + gVal + `' >> ` + gBak,
	`printf '\\n\[PHP\]\\n%s\\n' '` + gKey + ` = ` + gVal + `' >> ` + gBak,
	`cat ` + gBak + ` > ` + gPath,
	gFPM + ` -t`,
	gCLI + ` -c ` + gPath + ` -r ''`,
	gReload,
	`env DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFOLD=1 apt-get install -y --no-remove -o Dpkg::Options::=--force-confold --only-upgrade '` + gPkg + `=` + gVer + `'`,
	`dnf -y --setopt=obsoletes=False upgrade '` + gPkg + `-` + gVer + `'`,
	`apk add --upgrade '` + gPkg + `>=` + gVer + `'`,
	`echo "` + msgSnapshot + `"`,
	`echo "` + msgDoneA + `"`,
	`echo "` + msgDoneU + `"`,
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

var grammar = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(Grammar))
	for i, g := range Grammar {
		out[i] = regexp.MustCompile(`^` + g + `$`)
	}
	return out
}()

// Lint checks that every non-empty line of script matches a template of
// Grammar.
func Lint(script string) error {
	for i, line := range strings.Split(script, "\n") {
		if line == "" {
			continue
		}
		ok := false
		for _, g := range grammar {
			if g.MatchString(line) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: line %d: %q", ErrGrammar, i+1, line)
		}
	}
	return nil
}

// q single-quotes a word for POSIX sh. The character sets already refuse
// quotes; this is the second wall.
func q(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// checkRendered re-checks what Render needs from an action, without the
// inventory, before it checks the seal.
func checkRendered(t target.Target, a Action) error {
	switch a.Op {
	case OpBackup:
		return pathRefusal(t, a.Path)
	case OpSetDirective:
		if err := pathRefusal(t, a.Path); err != nil {
			return err
		}
		if !checkKey(a.Key) {
			return fmt.Errorf("%w: key %q", ErrUnknownDirective, a.Key)
		}
		if a.Append == (a.Line > 0) || a.Line < 0 {
			return fmt.Errorf("%w: line %d append %v", ErrBadAction, a.Line, a.Append)
		}
		return checkValue(a.Directive, a.Value)
	case OpTestConfig:
		if !phpBinary(a.Binary, a.SAPI) {
			return fmt.Errorf("%w: %q", ErrUntestableBinary, a.Binary)
		}
		switch {
		case a.SAPI == SAPIFPM:
			return nil
		case a.SAPI != SAPICLI || isUserIni(a.Path):
			// A .user.ini is never parsed as a php.ini (php -c would let
			// its owner load an extension).
			return fmt.Errorf("%w: test of %q", ErrBadAction, a.Path)
		}
		return pathRefusal(t, a.Path)
	case OpReload:
		if !serviceRe.MatchString(a.Service) || (a.Manager != "systemctl" && a.Manager != "rc-service") {
			return fmt.Errorf("%w: %q", ErrUnknownService, a.Service)
		}
		return nil
	case OpPackageUpgrade:
		if !pkgRe.MatchString(a.Package) || !versionRe.MatchString(a.Version) {
			return fmt.Errorf("%w: %q %q", ErrUnknownPackage, a.Package, a.Version)
		}
		switch a.Manager {
		case "apt", "dnf", "apk":
			return nil
		}
		return fmt.Errorf("%w: manager %q", ErrUnknownPackage, a.Manager)
	case OpCheckSite:
		return nil
	}
	return fmt.Errorf("%w: op %q", ErrBadAction, a.Op)
}

// ancestors lists the folders above p, from the top, "/" excluded.
func ancestors(p string) []string {
	var out []string
	for d := path.Dir(p); d != "/" && d != "."; d = path.Dir(d) {
		out = append([]string{d}, out...)
	}
	return out
}

// script accumulates lines.
type script struct{ b strings.Builder }

func (s *script) l(parts ...string) {
	for _, p := range parts {
		s.b.WriteString(p)
	}
	s.b.WriteByte('\n')
}

// Render turns a plan Validate returned into its bundle. It re-checks every
// action, refuses a plan Validate did not seal, lints both scripts and
// fails rather than produce a line outside the grammar.
//
// Two shapes, by what the plan touches:
//   - root (php.ini, pool, package): the whole script runs as root, checks
//     that every parent folder of every file is root's and closed, keeps
//     its backups in /var/lib/michel/backups/<correction>;
//   - user (.user.ini): the script runs as the SSH user, refuses root, keeps
//     its backups in ~/.michel/backups/<correction>.
//
// The body is a function called on the last line with stdin closed: a
// script cut short runs nothing, and no child reads the script's own text.
func Render(p Plan, t target.Target, correctionID string) (Bundle, error) {
	if !correctionRe.MatchString(correctionID) {
		return Bundle{}, fmt.Errorf("%w: correction id %q", ErrBadAction, correctionID)
	}
	var (
		files   []string // backed up, in order
		idx     = map[string]int{}
		writes  []Action
		tests   []Action
		reloads []Action
		pkgs    []Action
		checks  = []Action{}
	)
	for _, a := range p.Actions {
		if err := checkRendered(t, a); err != nil {
			return Bundle{}, err
		}
		switch a.Op {
		case OpBackup:
			if idx[a.Path] == 0 {
				files = append(files, a.Path)
				idx[a.Path] = len(files)
			}
		case OpSetDirective:
			if idx[a.Path] == 0 {
				return Bundle{}, fmt.Errorf("%w: %s is written before it is backed up", ErrBadAction, a.Path)
			}
			writes = append(writes, a)
		case OpTestConfig:
			tests = append(tests, a)
		case OpReload:
			reloads = append(reloads, a)
		case OpPackageUpgrade:
			pkgs = append(pkgs, a)
		case OpCheckSite:
			checks = append(checks, a)
		}
	}
	if len(writes) == 0 && len(pkgs) == 0 {
		return Bundle{}, fmt.Errorf("%w: nothing to change", ErrBadAction)
	}
	if len(pkgs) > 1 {
		return Bundle{}, fmt.Errorf("%w: one package per fix", ErrBadAction)
	}
	if err := checkMix(files, len(pkgs) > 0); err != nil {
		return Bundle{}, err
	}
	userMode := len(files) > 0 && isUserIni(files[0])
	if userMode {
		if err := checkOwner(t); err != nil {
			return Bundle{}, err
		}
	}
	if p.TargetID != t.ID || p.seal == "" || p.seal != sealOf(p, t) {
		return Bundle{}, ErrNotValidated
	}

	bak := func(n int) string { return `"$B/` + strconv.Itoa(n) + `"` }
	stage := func(n, k int) string { return `"$B/` + strconv.Itoa(n) + "." + strconv.Itoa(k) + `"` }
	safeDir := func(s *script, d string) {
		s.l(`case "$(stat -c '%u %A' `, q(d), `)" in 0?d????-??-?) ;; *) echo "`+msgUnsafeDir+`" >&2; exit 7;; esac`)
	}
	linkCheck := func(s *script, f string) {
		s.l("[ ! -L ", q(f), ` ] || { echo "`+msgLink+`" >&2; exit 6; }`)
	}
	// header writes the start of a script up to the user check and $B.
	header := func(s *script, what string) {
		s.l("#!/bin/sh")
		s.l("# michel correction ", correctionID, ": ", what)
		s.l("set -eu")
		s.l("umask 077")
		// The script trusts nothing it inherits: commands from the system
		// folders (the root and not-root guards included), no PHP ini
		// override (a kept PHP_INI_SCAN_DIR would make root load an
		// extension).
		s.l("PATH=/usr/sbin:/usr/bin:/sbin:/bin")
		s.l("export PATH")
		s.l("unset PHPRC PHP_INI_SCAN_DIR")
	}
	start := func(s *script) {
		s.l("main() {")
		if userMode {
			s.l(`[ "$(id -u)" != 0 ] || { echo "` + msgNotRoot + `" >&2; exit 3; }`)
		} else {
			s.l(`[ "$(id -u)" = 0 ] || { echo "` + msgRoot + `" >&2; exit 3; }`)
		}
		if len(files) == 0 {
			return
		}
		if userMode {
			s.l(`B="$HOME/.michel/backups/`, correctionID, `"`)
		} else {
			s.l(`B="`, RootBackups, "/", correctionID, `"`)
		}
	}
	// fileChecks: no link, and for root every parent folder root's and closed;
	// for a .user.ini, the user can write it.
	seenDir := map[string]bool{}
	fileChecks := func(s *script) {
		for k := range seenDir {
			delete(seenDir, k)
		}
		for _, f := range files {
			if !userMode {
				for _, d := range ancestors(f) {
					if !seenDir[d] {
						seenDir[d] = true
						safeDir(s, d)
					}
				}
			}
			linkCheck(s, f)
			if userMode {
				s.l("[ -w ", q(f), ` ] || { echo "`+msgOwner+`" >&2; exit 3; }`)
			} else {
				s.l(`case "$(stat -c '%u %A' `, q(f), `)" in 0?-????-??-?) ;; *) echo "`+msgUnsafeFile+`" >&2; exit 7;; esac`)
			}
		}
		// The PHP binaries root runs: their folders and the real file
		// (through a link such as Debian's alternatives) root's and closed.
		seenBin := map[string]bool{}
		for _, a := range tests {
			if userMode || seenBin[a.Binary] {
				continue
			}
			seenBin[a.Binary] = true
			for _, d := range ancestors(a.Binary) {
				if !seenDir[d] {
					seenDir[d] = true
					safeDir(s, d)
				}
			}
			// The real file sits in the same checked folder (Debian's
			// alternatives end there), never in a folder nobody checked.
			// php*/* comes first: a case * matches "/" (even after [!/]),
			// so php* alone would let in a file below a php* subfolder.
			bad := `) echo "` + msgUnsafeFile + `" >&2; exit 7;; `
			dir := path.Dir(a.Binary)
			s.l(`case "$(readlink -f `, q(a.Binary), `)" in `, dir, `/php*/*`, bad, dir, `/php*) ;; *`, bad, `esac`)
			s.l(`case "$(stat -L -c '%u %A' `, q(a.Binary), `)" in 0?-????-??-?) ;; *) echo "`+msgUnsafeFile+`" >&2; exit 7;; esac`)
		}
	}
	reloadLine := func(a Action) string {
		if a.Manager == "rc-service" {
			return "rc-service " + q(a.Service) + " reload"
		}
		return "systemctl reload " + q(a.Service)
	}
	testLine := func(a Action) string {
		if a.SAPI == SAPIFPM {
			return q(a.Binary) + " -t"
		}
		return q(a.Binary) + " -c " + q(a.Path) + " -r ''"
	}
	pkgLine := func(a Action) string {
		switch a.Manager {
		case "apt":
			return "env DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFOLD=1 apt-get install -y --no-remove -o Dpkg::Options::=--force-confold --only-upgrade " + q(a.Package+"="+a.Version)
		case "dnf":
			return "dnf -y --setopt=obsoletes=False upgrade " + q(a.Package+"-"+a.Version)
		}
		return "apk add --upgrade " + q(a.Package+">="+a.Version)
	}

	// Apply.
	var ap script
	header(&ap, "apply")
	if len(files) > 0 {
		ap.l("rollback() {")
		ap.l("  trap - EXIT")
		ap.l("  R=0")
		for i, f := range files {
			ap.l("  if [ ! -L ", q(f), " ]; then cat ", bak(i+1), " > ", q(f), " || R=1; else R=1; fi")
		}
		for _, r := range reloads {
			ap.l("  ", reloadLine(r), " || R=1")
		}
		ap.l(`  [ "$R" = 0 ] || { echo "` + msgRollFailed + `" >&2; exit 8; }`)
		ap.l(`  echo "` + msgRolled + `" >&2`)
		// Its own code: without it, sh exits with the status of the command
		// that failed, which may be one of the scripts' own (a reload that
		// exits 5).
		ap.l("  exit 9")
		ap.l("}")
	}
	start(&ap)
	if len(files) > 0 {
		ap.l("# checks before any change")
		fileChecks(&ap)
		// Before any folder is made: a file that is not the one Michel read
		// leaves the server exactly as it was.
		hashed := map[string]bool{}
		for _, w := range writes {
			if w.SHA256 == "" || hashed[w.Path] {
				continue
			}
			if !sha256Re.MatchString(w.SHA256) {
				return Bundle{}, fmt.Errorf("%w: file hash %q", ErrBadAction, w.SHA256)
			}
			hashed[w.Path] = true
			ap.l(`case "$(sha256sum `, q(w.Path), `)" in `, w.SHA256, `*) ;; *) echo "`+msgChanged+`" >&2; exit 5;; esac`)
		}
		if userMode {
			ap.l(`mkdir -p -m 700 "$HOME/.michel/backups"`)
		} else {
			// Each level is checked before the next one is made, so root
			// never creates a folder through a link.
			for _, d := range append(ancestors(RootBackups), RootBackups) {
				if d == path.Dir(RootBackups) || d == RootBackups {
					ap.l("mkdir -p -m 700 '", d, "'")
				}
				if !seenDir[d] {
					seenDir[d] = true
					safeDir(&ap, d)
				}
			}
		}
		ap.l(`mkdir -m 700 "$B" || { echo "` + msgApplied + `" >&2; exit 4; }`)
		ap.l("# backups")
		for i, f := range files {
			ap.l("cat ", q(f), " > ", bak(i+1))
		}
		// The new copies are made, and each line checked (exit 5), before
		// the trap is armed: nothing has changed yet, so the scripts' own
		// exit 5 never meets a rollback. Then the trap, then the writes.
		ap.l("# new copies")
		last := make([]string, len(files))
		for i, f := range files {
			n, k, cur := i+1, 0, bak(i+1)
			for _, w := range writes {
				if w.Path != f {
					continue
				}
				k++
				next := stage(n, k)
				line := iniLine(w.Key, w.Value)
				switch {
				case w.Append && userMode:
					ap.l("cat ", cur, " > ", next)
					ap.l(`printf '\n%s\n' `, q(line), " >> ", next)
				case w.Append:
					// A php.ini may end inside a [PATH=] or [HOST=] section:
					// [PHP] brings the line back to the main section.
					ap.l("cat ", cur, " > ", next)
					ap.l(`printf '\n[PHP]\n%s\n' `, q(line), " >> ", next)
				default:
					ap.l("sed '", strconv.Itoa(w.Line), "s|", sedPattern(w.Key), "|", line, "|' ", cur, " > ", next)
					ap.l("if cmp -s ", cur, " ", next, `; then echo "`+msgNoLine+`" >&2; exit 5; fi`)
				}
				cur = next
			}
			last[i] = cur
		}
		ap.l("trap 'rollback' EXIT")
		ap.l("trap 'exit 1' HUP INT TERM")
		ap.l("# changes")
		for i, f := range files {
			linkCheck(&ap, f)
			ap.l("cat ", last[i], " > ", q(f))
		}
	}
	if len(tests)+len(reloads) > 0 {
		ap.l("# test, reload")
	}
	for _, a := range tests {
		ap.l(testLine(a))
	}
	for _, a := range reloads {
		ap.l(reloadLine(a))
	}
	if len(pkgs) > 0 {
		ap.l("# package")
		ap.l(pkgLine(pkgs[0]))
	}
	if len(files) > 0 {
		ap.l("trap - EXIT")
	}
	ap.l(`echo "` + msgDoneA + `"`)
	ap.l("}")
	ap.l("main </dev/null")

	// Undo.
	var un script
	header(&un, "undo")
	start(&un)
	if len(files) > 0 {
		un.l("# checks before any change")
		for i := range files {
			un.l("[ -f ", bak(i+1), ` ] || { echo "`+msgNoBackup+`" >&2; exit 4; }`)
		}
		if !userMode {
			for _, d := range append(ancestors(RootBackups), RootBackups) {
				safeDir(&un, d)
			}
			un.l(`case "$(stat -c '%u %A' "$B")" in 0?d???------) ;; *) echo "` + msgUnsafeBak + `" >&2; exit 7;; esac`)
			for i := range files {
				un.l(`case "$(stat -c '%u %A' `, bak(i+1), `)" in 0?-???------) ;; *) echo "`+msgUnsafeBak+`" >&2; exit 7;; esac`)
			}
		}
		fileChecks(&un)
		un.l("# restore")
		for i, f := range files {
			linkCheck(&un, f)
			un.l("cat ", bak(i+1), " > ", q(f))
		}
		if len(tests)+len(reloads) > 0 {
			un.l("# test, reload")
		}
		for _, a := range tests {
			un.l(testLine(a))
		}
		for _, a := range reloads {
			un.l(reloadLine(a))
		}
	}
	if len(pkgs) > 0 {
		un.l(`echo "` + msgSnapshot + `"`)
	}
	un.l(`echo "` + msgDoneU + `"`)
	un.l("}")
	un.l("main </dev/null")

	b := Bundle{Apply: ap.b.String(), Undo: un.b.String(), Checks: checks, RunAsRoot: !userMode}
	if err := Lint(b.Apply); err != nil {
		return Bundle{}, err
	}
	if err := Lint(b.Undo); err != nil {
		return Bundle{}, err
	}
	b.Explain = explain(p, correctionID, userMode)
	b.Hash = Hash(b)
	return b, nil
}

// Hash is the SHA-256 of Apply, Undo and Checks, each framed by its length
// so no part can be shifted into another.
func Hash(b Bundle) string {
	checks := b.Checks
	if checks == nil {
		checks = []Action{}
	}
	cj, _ := json.Marshal(checks)
	h := sha256.New()
	for _, part := range []struct {
		name string
		data []byte
	}{{"apply", []byte(b.Apply)}, {"undo", []byte(b.Undo)}, {"checks", cj}} {
		fmt.Fprintf(h, "%s %d\n", part.name, len(part.data))
		h.Write(part.data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// explain says in plain words what the scripts do. It names files of the
// server only, never a path of the workstation.
func explain(p Plan, correctionID string, userMode bool) string {
	var s script
	dir := RootBackups + "/" + correctionID
	if userMode {
		dir = "~/.michel/backups/" + correctionID
	}
	n := 0
	for _, a := range p.Actions {
		switch a.Op {
		case OpBackup:
			n++
			s.l(fmt.Sprintf("- Back up %s to %s/%d (never deleted).", a.Path, dir, n))
		case OpSetDirective:
			if a.Append {
				s.l(fmt.Sprintf("- Add the line %q at the end of %s.", iniLine(a.Key, a.Value), a.Path))
			} else {
				s.l(fmt.Sprintf("- Replace line %d of %s (%s) by %q.", a.Line, a.Path, a.Key, iniLine(a.Key, a.Value)))
			}
		case OpTestConfig:
			if a.SAPI == SAPIFPM {
				s.l(fmt.Sprintf("- Test the PHP-FPM configuration (%s -t); a failure puts the files back.", a.Binary))
			} else {
				s.l(fmt.Sprintf("- Let PHP read %s (%s -c); a failure puts the files back.", a.Path, a.Binary))
			}
		case OpReload:
			s.l(fmt.Sprintf("- Reload %s (no restart).", a.Service))
		case OpPackageUpgrade:
			s.l(fmt.Sprintf("- Upgrade the package %s to %s, removing nothing.", a.Package, a.Version))
		case OpCheckSite:
			s.l("- Then Michel checks the site from your computer.")
		}
	}
	if userMode {
		s.l("- A .user.ini is changed by its owner, the SSH user, never as root: the script refuses to run as root.")
	} else {
		s.l("- The script runs wholly as root and stops at once otherwise; it writes only in folders root owns and nobody else may write.")
	}
	s.l("- A file that is a symbolic link is never read nor written.")
	s.l("- If a step fails after a change, the script puts the saved files back and reloads; if that fails too, it says so.")
	if p.NeedsSnapshot {
		s.l("- Undo cannot downgrade a package: your snapshot is the way back.")
	} else {
		s.l("- Undo puts the saved files back, tests and reloads.")
	}
	return s.b.String()
}
