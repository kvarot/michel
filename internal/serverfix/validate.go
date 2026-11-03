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

	"github.com/google/osv-scalibr/semantic"

	"github.com/kvarot/michel/internal/target"
	"github.com/kvarot/michel/internal/vulnmatch"
)

// pathRe is the whole set of characters a written path may hold.
var pathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]+$`)

// configFile matches the files Michel may write.
var configFile = regexp.MustCompile(`(\.ini|\.conf)$`)

// secretFile matches key and password files, never written.
var secretFile = regexp.MustCompile(`(?i)(^id_|\.key$|\.pem$|\.p12$|\.pfx$|^shadow-?$|^gshadow-?$|^\.?htpasswd$)`)

// refusedDirs are never written.
var refusedDirs = []string{
	"/proc/", "/sys/", "/dev/", "/run/", "/var/log/", "/var/backups/", "/var/lib/", "/boot/",
}

// rootTreeParts are the only files root writes: PHP's own configuration
// trees, nothing else under /etc. The script checks every parent folder
// and the file itself again (owned by root, not writable by group or
// others) before any change.
//   - /etc/php/ (Debian, Ubuntu), /etc/php[0-9]+/ (Alpine)
//   - /etc/php.ini, /etc/php.d/, /etc/php-fpm.conf, /etc/php-fpm.d/ (RHEL)
//   - /usr/local/etc/php.ini, /usr/local/etc/php/, /usr/local/etc/php-fpm.conf,
//     /usr/local/etc/php-fpm.d/ (PHP built from source, official images)
//   - /opt/remi/php[0-9]+/root/etc/, /etc/opt/remi/php[0-9]+/ (Remi's
//     software collections)
var rootTreeParts = []string{
	`/etc/php/` + treeChars + treeExt,
	`/etc/php[0-9]+/` + treeChars + treeExt,
	`/etc/php\.ini`,
	`/etc/php\.d/` + treeChars + treeExt,
	`/etc/php-fpm\.conf`,
	`/etc/php-fpm\.d/` + treeChars + treeExt,
	`/usr/local/etc/php\.ini`,
	`/usr/local/etc/php/` + treeChars + treeExt,
	`/usr/local/etc/php-fpm\.conf`,
	`/usr/local/etc/php-fpm\.d/` + treeChars + treeExt,
	`/opt/remi/php[0-9]+/root/etc/` + treeChars + treeExt,
	`/etc/opt/remi/php[0-9]+/` + treeChars + treeExt,
}

const (
	// treeSeg is one path segment, never "." or "..".
	treeSeg = `(?:[A-Za-z0-9_@+-][A-Za-z0-9._@+-]*|\.[A-Za-z0-9_@+-][A-Za-z0-9._@+-]*|\.\.[A-Za-z0-9._@+-]+)`
	// treeChars is the rest of a path under a tree: folders, then the start
	// of the file name (treeExt ends it).
	treeChars = `(?:` + treeSeg + `/)*[A-Za-z0-9._@+-]*`
	treeExt   = `\.(?:ini|conf)`
)

// rootTreeRe is the alternation of rootTreeParts, unanchored, shared by
// Validate and the grammar.
var rootTreeRe = `(?:` + strings.Join(rootTreeParts, "|") + `)`

var rootTrees = regexp.MustCompile(`^` + rootTreeRe + `$`)

// debianConfD matches Debian's conf.d files: links into mods-available,
// which Michel never writes through.
var debianConfD = regexp.MustCompile(`^/etc/php/[0-9.]+/[a-z0-9]+/conf\.d/`)

// pathRefusal checks a path on its own: absolute, clean, no "..", plain
// characters, a configuration file, no key file, no system folder. A file
// root writes (anything but a .user.ini) must be in rootTrees; a .user.ini,
// written as the SSH user, never in /root or another user's /home.
func pathRefusal(t target.Target, p string) error {
	switch {
	case !pathRe.MatchString(p) || path.Clean(p) != p || strings.Contains(p, ".."):
		return fmt.Errorf("%w: %q", ErrPathNotAllowed, p)
	case !configFile.MatchString(path.Base(p)) || secretFile.MatchString(path.Base(p)):
		return fmt.Errorf("%w: not a configuration file", ErrPathNotAllowed)
	case !isUserIni(p) && !rootTrees.MatchString(p):
		return fmt.Errorf("%w: root writes only in PHP's own configuration folders", ErrPathNotAllowed)
	case strings.HasPrefix(p, "/root/"):
		return fmt.Errorf("%w: /root", ErrPathNotAllowed)
	case strings.HasPrefix(p, "/home/") && (t.User == "" || !strings.HasPrefix(p, "/home/"+t.User+"/")):
		return fmt.Errorf("%w: another user's home", ErrPathNotAllowed)
	}
	for _, d := range refusedDirs {
		if strings.HasPrefix(p, d) {
			return fmt.Errorf("%w: system folder", ErrPathNotAllowed)
		}
	}
	return nil
}

// readByCollect reports whether the collection read p: only then is it
// known to exist and to have passed the collection's rules, the real file
// behind a link included.
func readByCollect(inv target.Inventory, p string) bool {
	for _, f := range inv.Files {
		if f.Path == p {
			return true
		}
	}
	return false
}

// collectedHash is the hash of p as the collection read it, "" if unknown.
func collectedHash(inv target.Inventory, p string) string {
	for _, f := range inv.Files {
		if f.Path == p {
			return f.SHA256
		}
	}
	return ""
}

// allowedFile checks a file a plan writes or backs up.
func allowedFile(t target.Target, inv target.Inventory, p string) error {
	if err := pathRefusal(t, p); err != nil {
		return err
	}
	// Each file by its role: an ini file ends in .ini, a pool in .conf,
	// and no runtime may list as an ini file what another lists as a pool
	// (a forged inventory would have root parse a pool as a php.ini).
	ok := contains(userInis(inv), p)
	ini, conf := strings.HasSuffix(p, ".ini"), strings.HasSuffix(p, ".conf")
	asIni, asPool := false, false
	for _, rt := range inv.PHP {
		asIni = asIni || p == rt.LoadedIni || contains(rt.ScannedFiles, p)
		asPool = asPool || contains(rt.PoolFiles, p)
	}
	if asIni && asPool {
		return fmt.Errorf("%w: %q is listed both as an ini file and as a pool", ErrPathNotAllowed, p)
	}
	if ini && asIni || conf && asPool {
		ok = true
	}
	if !ok || !readByCollect(inv, p) {
		return fmt.Errorf("%w: %q was not read as PHP configuration", ErrPathNotAllowed, p)
	}
	return nil
}

var (
	serviceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)
	pkgRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]*$`)
	versionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:_-]*$`)
	debFPM    = regexp.MustCompile(`^php-fpm([0-9]+\.[0-9]+)$`)
	branchRe  = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+)\.([0-9]+)`)
	majorRe   = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+)`)
	// phpBinRe is a system PHP binary: php[version] or php-fpm[version] in
	// a folder root owns. Root runs it to test a configuration, so nothing
	// the SSH user's PATH could plant (~/bin) is ever accepted.
	phpBinRe = regexp.MustCompile(`^/usr/(?:local/)?s?bin/php(-fpm)?[0-9.]*$`)
)

// phpBinary is the one rule for a PHP binary Michel runs: Validate, Render
// and Lint all apply it.
func phpBinary(p, sapi string) bool {
	m := phpBinRe.FindStringSubmatch(p)
	if m == nil || path.Clean(p) != p || strings.HasSuffix(p, ".") {
		return false
	}
	return (sapi == SAPIFPM) == (m[1] != "")
}

// fpmService is the service of a PHP-FPM binary: php8.2-fpm for Debian's
// php-fpm8.2, the binary's name elsewhere (php-fpm, php-fpm83).
func fpmService(binary string) string {
	b := path.Base(binary)
	if m := debFPM.FindStringSubmatch(b); m != nil {
		return "php" + m[1] + "-fpm"
	}
	return b
}

// serviceManager is the service manager of the system.
func serviceManager(inv target.Inventory) string {
	if inv.OS.ID == "alpine" {
		return "rc-service"
	}
	return "systemctl"
}

// packageManager is the package manager of a system whose versions Michel
// can compare (vulnmatch.Ecosystem), or "".
func packageManager(inv target.Inventory) string {
	if _, ok := vulnmatch.Ecosystem(inv.OS); !ok {
		return ""
	}
	switch inv.OS.ID {
	case "debian", "ubuntu":
		return "apt"
	case "rocky", "almalinux":
		return "dnf"
	case "alpine":
		return "apk"
	}
	return ""
}

// services lists the services Michel may reload: the system PHP-FPM seen.
func services(inv target.Inventory) map[string]bool {
	out := map[string]bool{}
	for _, rt := range inv.PHP {
		if rt.SAPI == SAPIFPM && phpBinary(rt.Binary, SAPIFPM) {
			out[fpmService(rt.Binary)] = true
		}
	}
	return out
}

// branch is "8.2" for 8.2.7-1~deb12u1 or 1:8.2.7, or "".
func branch(v string) string {
	if m := branchRe.FindStringSubmatch(v); m != nil {
		return m[1] + "." + m[2]
	}
	return ""
}

func major(v string) string {
	if m := majorRe.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return ""
}

// isPHPPackage tells a package of PHP itself.
func isPHPPackage(inv target.Inventory, name string) bool {
	if strings.HasPrefix(name, "php") {
		return true
	}
	for _, rt := range inv.PHP {
		if rt.FromPackage == name {
			return true
		}
	}
	return false
}

// newer says whether v is strictly newer than cur in the system's ecosystem.
func newer(inv target.Inventory, cur, v string) (bool, error) {
	eco, ok := vulnmatch.Ecosystem(inv.OS)
	if !ok {
		return false, fmt.Errorf("%w: versions of %q cannot be compared", ErrUnknownPackage, inv.OS.ID)
	}
	pv, err := semantic.Parse(v, eco)
	if err != nil {
		return false, fmt.Errorf("%w: version %q", ErrUnknownPackage, v)
	}
	c, err := pv.CompareStr(cur)
	if err != nil {
		return false, fmt.Errorf("%w: installed version %q", ErrUnknownPackage, cur)
	}
	return c > 0, nil
}

// checkPackage validates one package_upgrade: an installed package, a
// strictly newer version, no change of PHP branch and no change of major
// version of any package (spec § 8.4: a major upgrade of PHP or of a
// service is a proposal only; Michel does not tell a service's package
// from a library's, so the rule holds for every package).
func checkPackage(inv target.Inventory, a Action) (Action, error) {
	if !pkgRe.MatchString(a.Package) || len(a.Package) > 128 {
		return a, fmt.Errorf("%w: %q", ErrUnknownPackage, a.Package)
	}
	if !versionRe.MatchString(a.Version) || len(a.Version) > 128 {
		return a, fmt.Errorf("%w: version %q", ErrUnknownPackage, a.Version)
	}
	var cur *target.Package
	for i := range inv.Packages {
		if inv.Packages[i].Name == a.Package {
			cur = &inv.Packages[i]
			break
		}
	}
	if cur == nil {
		return a, fmt.Errorf("%w: %q is not installed", ErrUnknownPackage, a.Package)
	}
	m := packageManager(inv)
	if m == "" {
		return a, fmt.Errorf("%w: unknown package manager for %q", ErrUnknownPackage, inv.OS.ID)
	}
	ok, err := newer(inv, cur.Version, a.Version)
	if err != nil {
		return a, err
	}
	if !ok {
		return a, fmt.Errorf("%w: %s %s is not newer than %s", ErrDowngrade, a.Package, a.Version, cur.Version)
	}
	if isPHPPackage(inv, a.Package) && branch(cur.Version) != branch(a.Version) {
		return a, ErrMajorUpgrade
	}
	if major(cur.Version) != major(a.Version) {
		return a, ErrMajorUpgrade
	}
	return Action{Op: OpPackageUpgrade, Package: a.Package, Version: a.Version, Manager: m}, nil
}

// userRe is a plain Unix user name.
var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// isUserIni tells a .user.ini: a file its site's owner may write, so every
// step on it runs as the SSH user, never as root.
func isUserIni(p string) bool { return path.Base(p) == ".user.ini" }

// checkOwner refuses a .user.ini fix when the SSH user, who runs it, is
// unknown, malformed or root.
func checkOwner(t target.Target) error {
	if !userRe.MatchString(t.User) || t.User == "root" {
		return fmt.Errorf("%w: a .user.ini is changed only as its owner, the SSH user %q cannot be", ErrPathNotAllowed, t.User)
	}
	return nil
}

// checkMix refuses a fix that writes a .user.ini (run as the SSH user, never
// root) together with a root file or a package.
func checkMix(files []string, pkg bool) error {
	user, other := 0, 0
	for _, f := range files {
		if isUserIni(f) {
			user++
		} else {
			other++
		}
	}
	if user > 0 && (other > 0 || pkg) {
		return fmt.Errorf("%w: a .user.ini is fixed on its own, without root files or packages", ErrBadAction)
	}
	return nil
}

// sealOf is the digest Validate stores in a plan and Render checks.
func sealOf(p Plan, t target.Target) string {
	p.seal = ""
	j, _ := json.Marshal(p)
	h := sha256.New()
	fmt.Fprintf(h, "michel-serverfix-plan\n%s\n%s\n%s\n", strconv.Quote(t.ID), strconv.Quote(t.User), strconv.Quote(t.SiteURL))
	h.Write(j)
	return hex.EncodeToString(h.Sum(nil))
}

// Validate checks a proposed plan against the server and its inventory
// and returns it normalized: a backup_file before the first write of each
// file, the writes in the proposed order, a test_config per tested
// configuration, a reload_service per PHP-FPM touched (and those proposed),
// at most one package_upgrade, and a check_site when the server has a site.
// The agent's own backup_file, test_config and check_site are checked then
// replaced by Michel's. Only the returned plan, unchanged, can be rendered.
func Validate(p Plan, t target.Target, inv target.Inventory) (Plan, error) {
	if t.ID == "" || (p.TargetID != "" && p.TargetID != t.ID) || (inv.TargetID != "" && inv.TargetID != t.ID) {
		return Plan{}, fmt.Errorf("%w: plan for another server", ErrBadAction)
	}
	var (
		writes  []Action
		files   []string
		tests   []Action
		reloads []Action
		pkgs    []Action
		svcs    = services(inv)
	)
	addTest := func(a Action) {
		for _, x := range tests {
			if x.Binary == a.Binary && x.Path == a.Path {
				return
			}
		}
		tests = append(tests, a)
	}
	addReload := func(svc string) {
		for _, x := range reloads {
			if x.Service == svc {
				return
			}
		}
		reloads = append(reloads, Action{Op: OpReload, Service: svc, Manager: serviceManager(inv)})
	}
	for _, a := range p.Actions {
		switch a.Op {
		case OpBackup:
			if err := allowedFile(t, inv, a.Path); err != nil {
				return Plan{}, err
			}
		case OpTestConfig, OpCheckSite:
			// Michel derives its own.
		case OpReload:
			if !serviceRe.MatchString(a.Service) || !svcs[a.Service] {
				return Plan{}, fmt.Errorf("%w: %q", ErrUnknownService, a.Service)
			}
			addReload(a.Service)
		case OpPackageUpgrade:
			if len(pkgs) > 0 {
				return Plan{}, fmt.Errorf("%w: one package per fix", ErrBadAction)
			}
			n, err := checkPackage(inv, a)
			if err != nil {
				return Plan{}, err
			}
			pkgs = append(pkgs, n)
		case OpSetDirective:
			value := strings.Trim(a.Value, " ")
			if a.Path != "" {
				if err := pathRefusal(t, a.Path); err != nil {
					return Plan{}, err
				}
			}
			if err := checkValue(a.Directive, value); err != nil {
				return Plan{}, err
			}
			r, err := rule(a.Directive)
			if err != nil {
				return Plan{}, err
			}
			if err := checkAdvised(r, value); err != nil {
				return Plan{}, err
			}
			loc, err := locate(inv, a.SAPI, a.Directive, a.Path)
			if err != nil {
				return Plan{}, err
			}
			if err := allowedFile(t, inv, loc.path); err != nil {
				return Plan{}, err
			}
			if loc.rt != nil {
				// The file has the role the write needs, in this runtime.
				pool := poolKeyRe.MatchString(loc.key)
				switch {
				case pool && !(loc.rt.SAPI == SAPIFPM && contains(loc.rt.PoolFiles, loc.path) && strings.HasSuffix(loc.path, ".conf")):
					return Plan{}, fmt.Errorf("%w: %q is not a pool of this PHP-FPM", ErrPathNotAllowed, loc.path)
				case !pool && !((loc.path == loc.rt.LoadedIni || contains(loc.rt.ScannedFiles, loc.path)) && strings.HasSuffix(loc.path, ".ini")):
					return Plan{}, fmt.Errorf("%w: %q is not an ini file of this PHP", ErrPathNotAllowed, loc.path)
				}
			}
			if debianConfD.MatchString(loc.path) {
				return Plan{}, fmt.Errorf("%w: %s", ErrLinkedFile, loc.path)
			}
			if !checkKey(loc.key) {
				return Plan{}, fmt.Errorf("%w: %q", ErrUnknownDirective, loc.key)
			}
			for _, w := range writes {
				if w.Path == loc.path && w.Key == loc.key {
					return Plan{}, fmt.Errorf("%w: %s set twice in one file", ErrBadAction, loc.key)
				}
			}
			switch {
			case loc.rt != nil:
				// A root file is tested by a system PHP binary, never by one
				// the collection found elsewhere (the SSH user's PATH).
				if !phpBinary(loc.rt.Binary, loc.rt.SAPI) {
					return Plan{}, fmt.Errorf("%w: %q", ErrUntestableBinary, loc.rt.Binary)
				}
				if loc.rt.SAPI == SAPIFPM {
					addTest(Action{Op: OpTestConfig, SAPI: SAPIFPM, Binary: loc.rt.Binary})
					addReload(fpmService(loc.rt.Binary))
				} else {
					addTest(Action{Op: OpTestConfig, SAPI: SAPICLI, Binary: loc.rt.Binary, Path: loc.path})
				}
			default:
				// A .user.ini is read again by PHP on its own. It is never
				// handed to `php -c`: parsed as a php.ini it could load an
				// extension its owner chose, and it is never touched as root.
				if err := checkOwner(t); err != nil {
					return Plan{}, err
				}
			}
			writes = append(writes, Action{Op: OpSetDirective, Path: loc.path, Directive: a.Directive, Value: value,
				SAPI: a.SAPI, Key: loc.key, Line: loc.line, Append: loc.append, SHA256: collectedHash(inv, loc.path)})
			if !contains(files, loc.path) {
				files = append(files, loc.path)
			}
		default:
			return Plan{}, fmt.Errorf("%w: op %q", ErrBadAction, a.Op)
		}
	}
	if len(writes) == 0 && len(pkgs) == 0 {
		return Plan{}, fmt.Errorf("%w: nothing to change", ErrBadAction)
	}
	if err := checkMix(files, len(pkgs) > 0); err != nil {
		return Plan{}, err
	}
	out := Plan{TargetID: t.ID, FindingID: p.FindingID, Mitigation: p.Mitigation, NeedsSnapshot: len(pkgs) > 0}
	for _, f := range files {
		out.Actions = append(out.Actions, Action{Op: OpBackup, Path: f})
	}
	out.Actions = append(out.Actions, writes...)
	out.Actions = append(out.Actions, tests...)
	out.Actions = append(out.Actions, reloads...)
	out.Actions = append(out.Actions, pkgs...)
	if t.SiteURL != "" {
		out.Actions = append(out.Actions, Action{Op: OpCheckSite})
	}
	out.seal = sealOf(out, t)
	return out, nil
}
