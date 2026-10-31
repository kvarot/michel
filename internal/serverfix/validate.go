package serverfix

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/target"
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

// pathRefusal checks a path on its own: absolute, clean, no "..", plain
// characters, a configuration file, no key file, no system folder, and not
// in /root or another user's /home.
func pathRefusal(t target.Target, p string) error {
	switch {
	case !pathRe.MatchString(p) || path.Clean(p) != p || strings.Contains(p, ".."):
		return fmt.Errorf("%w: %q", ErrPathNotAllowed, p)
	case !configFile.MatchString(path.Base(p)) || secretFile.MatchString(path.Base(p)):
		return fmt.Errorf("%w: not a configuration file", ErrPathNotAllowed)
	case strings.HasPrefix(p, "/root/") && t.User != "root":
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

// allowedFile checks a file a plan writes or backs up.
func allowedFile(t target.Target, inv target.Inventory, p string) error {
	if err := pathRefusal(t, p); err != nil {
		return err
	}
	ok := contains(userInis(inv), p)
	for _, rt := range inv.PHP {
		if p == rt.LoadedIni || contains(rt.ScannedFiles, p) || contains(rt.PoolFiles, p) {
			ok = true
		}
	}
	if !ok || !readByCollect(inv, p) {
		return fmt.Errorf("%w: %q was not read as PHP configuration", ErrPathNotAllowed, p)
	}
	return nil
}

var (
	binaryRe  = regexp.MustCompile(`^/[A-Za-z0-9._/+-]+$`)
	serviceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)
	pkgRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]*$`)
	versionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:_-]*$`)
	debFPM    = regexp.MustCompile(`^php-fpm([0-9]+\.[0-9]+)$`)
	branchRe  = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+)\.([0-9]+)`)
)

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

// packageManager is the package manager of the system, or "".
func packageManager(inv target.Inventory) string {
	switch inv.OS.ID {
	case "debian", "ubuntu", "raspbian", "linuxmint":
		return "apt"
	case "rhel", "centos", "rocky", "almalinux", "fedora", "ol", "amzn":
		return "dnf"
	case "alpine":
		return "apk"
	}
	return ""
}

// services lists the services Michel may reload: the PHP-FPM seen.
func services(inv target.Inventory) map[string]bool {
	out := map[string]bool{}
	for _, rt := range inv.PHP {
		if rt.SAPI == SAPIFPM && binaryRe.MatchString(rt.Binary) {
			out[fpmService(rt.Binary)] = true
		}
	}
	return out
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

// branch is "8.2" for 8.2.7-1~deb12u1 or 1:8.2.7, or "".
func branch(v string) string {
	if m := branchRe.FindStringSubmatch(v); m != nil {
		return m[1] + "." + m[2]
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

// checkPackage validates one package_upgrade.
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
	if cur.Version == a.Version {
		return a, fmt.Errorf("%w: %q is already at %s", ErrBadAction, a.Package, a.Version)
	}
	if isPHPPackage(inv, a.Package) && branch(cur.Version) != branch(a.Version) {
		return a, ErrMajorUpgrade
	}
	m := packageManager(inv)
	if m == "" {
		return a, fmt.Errorf("%w: unknown package manager for %q", ErrUnknownPackage, inv.OS.ID)
	}
	return Action{Op: OpPackageUpgrade, Package: a.Package, Version: a.Version, Manager: m}, nil
}

// Validate checks a proposed plan against the server and its inventory
// and returns it normalized: a backup_file before the first write of each
// file, the writes in the proposed order, a test_config per tested
// configuration, a reload_service per PHP-FPM touched (and those proposed),
// at most one package_upgrade, and a check_site when the server has a site.
// The agent's own backup_file, test_config and check_site are checked then
// replaced by Michel's.
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
			if _, err := rule(a.Directive); err != nil {
				return Plan{}, err
			}
			loc, err := locate(inv, a.SAPI, a.Directive, a.Path)
			if err != nil {
				return Plan{}, err
			}
			if err := allowedFile(t, inv, loc.path); err != nil {
				return Plan{}, err
			}
			if !checkKey(loc.key) {
				return Plan{}, fmt.Errorf("%w: %q", ErrUnknownDirective, loc.key)
			}
			for _, w := range writes {
				if w.Path == loc.path && w.Key == loc.key {
					return Plan{}, fmt.Errorf("%w: %s set twice in one file", ErrBadAction, loc.key)
				}
			}
			writes = append(writes, Action{Op: OpSetDirective, Path: loc.path, Directive: a.Directive, Value: value,
				SAPI: a.SAPI, Key: loc.key, Line: loc.line, Append: loc.append})
			if !contains(files, loc.path) {
				files = append(files, loc.path)
			}
			switch {
			case loc.rt != nil && loc.rt.SAPI == SAPIFPM:
				if !binaryRe.MatchString(loc.rt.Binary) {
					return Plan{}, fmt.Errorf("%w: FPM binary %q", ErrUnknownService, loc.rt.Binary)
				}
				addTest(Action{Op: OpTestConfig, SAPI: SAPIFPM, Binary: loc.rt.Binary})
				addReload(fpmService(loc.rt.Binary))
			case loc.rt != nil:
				if !binaryRe.MatchString(loc.rt.Binary) {
					return Plan{}, fmt.Errorf("%w: PHP binary %q", ErrBadAction, loc.rt.Binary)
				}
				addTest(Action{Op: OpTestConfig, SAPI: SAPICLI, Binary: loc.rt.Binary, Path: loc.path})
			default:
				// A .user.ini is read again by PHP on its own. It is never
				// handed to `php -c`: parsed as a php.ini it could load an
				// extension its owner chose, and it is never touched as root.
				if err := checkOwner(t); err != nil {
					return Plan{}, err
				}
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
	return out, nil
}
