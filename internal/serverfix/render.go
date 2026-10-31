package serverfix

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/kvarot/michel/internal/target"
)

// correctionRe is a correction id (a ULID in practice).
var correctionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Fixed texts of the scripts: short, ASCII, the same whoever runs them.
const (
	msgRoot     = "lance ce script en root"
	msgApplied  = "correction deja appliquee"
	msgNoBackup = "sauvegarde absente"
	msgNoLine   = "ligne introuvable"
	msgRolled   = "echec: fichiers remis"
	msgSnapshot = "retour par ton snapshot"
	msgDoneA    = "correction appliquee"
	msgDoneU    = "correction annulee"
	msgLink     = "lien refuse"
	msgNotRoot  = "ne lance pas ce script en root"
	msgOwner    = "lance ce script en tant que proprietaire du fichier"
)

// Building blocks of the grammar. A quoted path, binary, service or
// package never holds a quote: the character sets refuse it upstream.
const (
	gPath   = `'/[A-Za-z0-9._/@+-]+'`
	gBin    = `'/[A-Za-z0-9._/+-]+'`
	gBak    = `"\$B/[0-9]+(?:\.[0-9]+)?"`
	gSudo   = `(?:sudo -n )?`
	gKey    = `[A-Za-z0-9_.\[\]]+`
	gKeyRe  = `(?:[A-Za-z0-9_]|\\[.\[\]])+`
	gVal    = `[A-Za-z0-9_./:,@+%-]*`
	gSvc    = `'[A-Za-z0-9][A-Za-z0-9._@-]*'`
	gPkg    = `[A-Za-z0-9][A-Za-z0-9.+_-]*`
	gVer    = `[0-9][A-Za-z0-9.+~:_-]*`
	gRoot   = ` \|\| \{ echo "` + msgRoot + `" >&2; exit 3; \}`
	gLink   = `\[ ! -L ` + gPath + ` \]`
	gReload = gSudo + `(?:systemctl reload ` + gSvc + `|rc-service ` + gSvc + ` reload)`
)

// Grammar lists the templates every non-empty line of a rendered script
// matches, whole line. Lint refuses any other line.
var Grammar = []string{
	`#!/bin/sh`,
	`# michel correction [A-Za-z0-9_-]+: (?:apply|undo)`,
	`# [a-z ,]+`,
	`set -eu`,
	`umask 077`,
	`B="\$HOME/\.michel/backups/[A-Za-z0-9_-]+"`,
	`\[ -w ` + gPath + ` \]` + gRoot,
	`sudo -n test -w ` + gPath + gRoot,
	`\[ -w ` + gPath + ` \] \|\| \{ echo "` + msgOwner + `" >&2; exit 3; \}`,
	`\[ "\$\(id -u\)" = 0 \]` + gRoot,
	`\[ "\$\(id -u\)" != 0 \] \|\| \{ echo "` + msgNotRoot + `" >&2; exit 3; \}`,
	gLink + ` \|\| \{ echo "` + msgLink + `" >&2; exit 6; \}`,
	`\[ ! -e ` + gBak + ` \] \|\| \{ echo "` + msgApplied + `" >&2; exit 4; \}`,
	`\[ -f ` + gBak + ` \] \|\| \{ echo "` + msgNoBackup + `" >&2; exit 4; \}`,
	`mkdir -p "\$B"`,
	gSudo + `cat ` + gPath + ` > ` + gBak,
	`rollback\(\) \{`,
	`  trap - EXIT`,
	`  if ` + gLink + `; then ` + gSudo + `cp ` + gBak + ` ` + gPath + ` \|\| true; fi`,
	`  ` + gReload + ` \|\| true`,
	`  echo "` + msgRolled + `" >&2`,
	`\}`,
	`trap 'rollback' EXIT`,
	`trap 'exit 1' HUP INT TERM`,
	`trap - EXIT`,
	`sed '[1-9][0-9]*s\|\^\[\[:space:\]\]\*` + gKeyRe + `\[\[:space:\]\]\*=\.\*\$\|` + gKey + ` = ` + gVal + `\|' ` + gBak + ` > ` + gBak,
	`if cmp -s ` + gBak + ` ` + gBak + `; then echo "` + msgNoLine + `" >&2; exit 5; fi`,
	`cat ` + gBak + ` > ` + gBak,
	`printf '\\n%s\\n' '` + gKey + ` = ` + gVal + `' >> ` + gBak,
	gSudo + `cp ` + gBak + ` ` + gPath,
	gSudo + gBin + ` -t`,
	gSudo + gBin + ` -c ` + gPath + ` -r ''`,
	gReload,
	gSudo + `apt-get install -y -o Dpkg::Options::=--force-confold --only-upgrade '` + gPkg + `=` + gVer + `'`,
	gSudo + `dnf -y upgrade '` + gPkg + `-` + gVer + `'`,
	gSudo + `apk add '` + gPkg + `=` + gVer + `'`,
	`echo "` + msgSnapshot + `"`,
	`echo "` + msgDoneA + `"`,
	`echo "` + msgDoneU + `"`,
}

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
// inventory: Render must never trust a plan it did not see validated.
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
		if !binaryRe.MatchString(a.Binary) || strings.Contains(a.Binary, "..") {
			return fmt.Errorf("%w: binary %q", ErrBadAction, a.Binary)
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

// script accumulates lines.
type script struct{ b strings.Builder }

func (s *script) l(parts ...string) {
	for _, p := range parts {
		s.b.WriteString(p)
	}
	s.b.WriteByte('\n')
}

// Render turns a validated plan into its bundle. It re-checks every action,
// lints both scripts and fails rather than produce a line outside the
// grammar.
func Render(p Plan, t target.Target, correctionID string) (Bundle, error) {
	if !correctionRe.MatchString(correctionID) {
		return Bundle{}, fmt.Errorf("%w: correction id %q", ErrBadAction, correctionID)
	}
	sudo := ""
	if t.Sudo == target.SudoNopasswd {
		sudo = "sudo -n "
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
	// A .user.ini is written by its owner, the SSH user, never by root:
	// no sudo, and the script refuses to run as root.
	userMode := len(files) > 0 && isUserIni(files[0])
	if userMode {
		if err := checkOwner(t); err != nil {
			return Bundle{}, err
		}
		sudo = ""
	}
	bak := func(n int) string { return `"$B/` + strconv.Itoa(n) + `"` }
	stage := func(n, k int) string { return `"$B/` + strconv.Itoa(n) + "." + strconv.Itoa(k) + `"` }
	writeCheck := func(s *script, f string) {
		if userMode {
			s.l("[ -w ", q(f), ` ] || { echo "`+msgOwner+`" >&2; exit 3; }`)
		} else if sudo != "" {
			s.l("sudo -n test -w ", q(f), ` || { echo "`+msgRoot+`" >&2; exit 3; }`)
		} else {
			s.l("[ -w ", q(f), ` ] || { echo "`+msgRoot+`" >&2; exit 3; }`)
		}
	}
	linkCheck := func(s *script, f string) {
		s.l("[ ! -L ", q(f), ` ] || { echo "`+msgLink+`" >&2; exit 6; }`)
	}
	rootCheck := func(s *script) {
		if userMode {
			s.l(`[ "$(id -u)" != 0 ] || { echo "` + msgNotRoot + `" >&2; exit 3; }`)
		}
	}
	reloadLine := func(a Action) string {
		if a.Manager == "rc-service" {
			return sudo + "rc-service " + q(a.Service) + " reload"
		}
		return sudo + "systemctl reload " + q(a.Service)
	}
	testLine := func(a Action) string {
		if a.SAPI == SAPIFPM {
			return sudo + q(a.Binary) + " -t"
		}
		return sudo + q(a.Binary) + " -c " + q(a.Path) + " -r ''"
	}
	pkgLine := func(a Action) string {
		switch a.Manager {
		case "apt":
			return sudo + "apt-get install -y -o Dpkg::Options::=--force-confold --only-upgrade " + q(a.Package+"="+a.Version)
		case "dnf":
			return sudo + "dnf -y upgrade " + q(a.Package+"-"+a.Version)
		}
		return sudo + "apk add " + q(a.Package+"="+a.Version)
	}

	// Apply.
	var ap script
	ap.l("#!/bin/sh")
	ap.l("# michel correction ", correctionID, ": apply")
	ap.l("set -eu")
	ap.l("umask 077")
	if len(files) > 0 {
		ap.l(`B="$HOME/.michel/backups/`, correctionID, `"`)
	}
	ap.l("# checks before any change")
	rootCheck(&ap)
	for _, f := range files {
		linkCheck(&ap, f)
		writeCheck(&ap, f)
	}
	if len(pkgs) > 0 && sudo == "" {
		ap.l(`[ "$(id -u)" = 0 ] || { echo "` + msgRoot + `" >&2; exit 3; }`)
	}
	if len(files) > 0 {
		ap.l("[ ! -e ", bak(1), ` ] || { echo "`+msgApplied+`" >&2; exit 4; }`)
		ap.l(`mkdir -p "$B"`)
		ap.l("# backups")
		for i, f := range files {
			linkCheck(&ap, f)
			ap.l(sudo, "cat ", q(f), " > ", bak(i+1))
		}
		ap.l("rollback() {")
		ap.l("  trap - EXIT")
		for i, f := range files {
			ap.l("  if [ ! -L ", q(f), " ]; then ", sudo, "cp ", bak(i+1), " ", q(f), " || true; fi")
		}
		for _, r := range reloads {
			ap.l("  ", reloadLine(r), " || true")
		}
		ap.l(`  echo "` + msgRolled + `" >&2`)
		ap.l("}")
		ap.l("trap 'rollback' EXIT")
		ap.l("trap 'exit 1' HUP INT TERM")
		ap.l("# changes")
		for i, f := range files {
			n, k, cur := i+1, 0, bak(i+1)
			for _, w := range writes {
				if w.Path != f {
					continue
				}
				k++
				next := stage(n, k)
				line := iniLine(w.Key, w.Value)
				if w.Append {
					ap.l("cat ", cur, " > ", next)
					ap.l(`printf '\n%s\n' `, q(line), " >> ", next)
				} else {
					ap.l("sed '", strconv.Itoa(w.Line), "s|", sedPattern(w.Key), "|", line, "|' ", cur, " > ", next)
					ap.l("if cmp -s ", cur, " ", next, `; then echo "`+msgNoLine+`" >&2; exit 5; fi`)
				}
				cur = next
			}
			linkCheck(&ap, f)
			ap.l(sudo, "cp ", cur, " ", q(f))
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

	// Undo.
	var un script
	un.l("#!/bin/sh")
	un.l("# michel correction ", correctionID, ": undo")
	un.l("set -eu")
	un.l("umask 077")
	if len(files) > 0 {
		un.l(`B="$HOME/.michel/backups/`, correctionID, `"`)
		un.l("# checks before any change")
		for i := range files {
			un.l("[ -f ", bak(i+1), ` ] || { echo "`+msgNoBackup+`" >&2; exit 4; }`)
		}
		rootCheck(&un)
		for _, f := range files {
			linkCheck(&un, f)
			writeCheck(&un, f)
		}
		un.l("# restore")
		for i, f := range files {
			linkCheck(&un, f)
			un.l(sudo, "cp ", bak(i+1), " ", q(f))
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

	b := Bundle{Apply: ap.b.String(), Undo: un.b.String(), Checks: checks}
	if err := Lint(b.Apply); err != nil {
		return Bundle{}, err
	}
	if err := Lint(b.Undo); err != nil {
		return Bundle{}, err
	}
	b.Explain = explain(p, correctionID, sudo != "", userMode)
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
func explain(p Plan, correctionID string, sudo, userMode bool) string {
	var s script
	n := 0
	for _, a := range p.Actions {
		switch a.Op {
		case OpBackup:
			n++
			s.l(fmt.Sprintf("- Back up %s to ~/.michel/backups/%s/%d (never deleted).", a.Path, correctionID, n))
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
			s.l(fmt.Sprintf("- Upgrade the package %s to %s, after a simulation that removes nothing.", a.Package, a.Version))
		case OpCheckSite:
			s.l("- Then Michel checks the site from your computer.")
		}
	}
	switch {
	case userMode:
		s.l("- A .user.ini is changed by its owner, the SSH user, never as root: the script refuses to run as root.")
	case sudo:
		s.l("- Commands that need root run with sudo -n.")
	default:
		s.l("- The script stops before any change when it cannot write a file: run it as root.")
	}
	s.l("- A file that became a symbolic link is never read nor written.")
	s.l("- If a step fails after a change, the script puts the saved files back and reloads.")
	if p.NeedsSnapshot {
		s.l("- Undo cannot downgrade a package: your snapshot is the way back.")
	} else {
		s.l("- Undo puts the saved files back, tests and reloads.")
	}
	return s.b.String()
}
