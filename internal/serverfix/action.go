// Package serverfix turns a proposed server fix into typed, checked actions
// and renders them as two POSIX sh scripts: one that applies the fix and
// rolls itself back when a step fails, and one that undoes it. Nothing here
// runs anything: the scripts are text, checked against a closed grammar
// (Lint) and fingerprinted (Bundle.Hash) before anyone may run them.
//
// Safety rules, all enforced here:
//   - the only actions are those of the Op list; none deletes anything;
//   - a written file is a configuration file the collection read (php.ini,
//     a scanned ini file, a PHP-FPM pool or a .user.ini), backed up first;
//   - every value, path, service and package is checked against a strict
//     character set before it reaches a script, then single-quoted;
//   - shell redirections only ever write into the backup folder
//     $HOME/.michel/backups/<correction>, never into a configuration file;
//   - backups on the server are never deleted by any script.
package serverfix

import (
	"errors"
	"strings"
)

// Op is one kind of safe action. The list is closed.
type Op string

const (
	OpBackup         Op = "backup_file"
	OpSetDirective   Op = "set_directive"
	OpTestConfig     Op = "test_config"
	OpReload         Op = "reload_service"
	OpPackageUpgrade Op = "package_upgrade"
	OpCheckSite      Op = "check_site"
)

// Action is one typed step. The agent fills Op and the fields of its
// proposal (Directive, Value, SAPI and optionally Path for set_directive;
// Package and Version for package_upgrade; Service for reload_service);
// Validate fills the rest from the inventory.
type Action struct {
	Op        Op     `json:"op"`
	Path      string `json:"path,omitempty"`
	Directive string `json:"directive,omitempty"`
	Value     string `json:"value,omitempty"`
	Service   string `json:"service,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	SAPI      string `json:"sapi,omitempty"`

	// Set by Validate.
	//
	// Key is the name as written in the file (the directive, or a pool's
	// php_admin_value[directive]); Line is the line to change, 0 with
	// Append to add a line at the end of the file.
	Key    string `json:"key,omitempty"`
	Line   int    `json:"line,omitempty"`
	Append bool   `json:"append,omitempty"`
	// Binary is the PHP binary a test_config runs.
	Binary string `json:"binary,omitempty"`
	// Manager is the service manager of a reload_service (systemctl,
	// rc-service) or the package manager of a package_upgrade (apt, dnf,
	// apk).
	Manager string `json:"manager,omitempty"`
}

// Plan is a fix for one finding on one server.
type Plan struct {
	TargetID  string   `json:"target_id"`
	FindingID string   `json:"finding_id"`
	Actions   []Action `json:"actions"`
	// Mitigation marks a fix that only holds a flaw back.
	Mitigation bool `json:"mitigation,omitempty"`
	// NeedsSnapshot is set by Validate when the fix upgrades a package:
	// there is no automatic way back, the user's snapshot is the way back.
	NeedsSnapshot bool `json:"needs_snapshot,omitempty"`
}

// Bundle is what the user validates: both scripts, a plain explanation and
// the checks Michel makes from the workstation afterwards. Hash covers
// Apply, Undo and Checks.
type Bundle struct {
	Apply   string
	Undo    string
	Explain string
	Checks  []Action
	Hash    string
}

// SimResult is what a package manager's simulation would do.
type SimResult struct {
	Upgrades []string
	Removes  []string
	Installs []string
}

var (
	// ErrPathNotAllowed: the file is not one the collection read as a
	// php.ini, a scanned ini file, a PHP-FPM pool or a .user.ini, or the
	// path is refused (.., odd characters, another user's home, a key file),
	// or the directive would have no effect there.
	ErrPathNotAllowed = errors.New("serverfix: Michel may not write this file")
	// ErrBadValue: the value holds characters a configuration value must
	// not hold (control characters, new lines, an ini comment, quotes,
	// shell or sed specials), or is a value Michel never proposes.
	ErrBadValue = errors.New("serverfix: this value is refused")
	// ErrUnknownDirective: the directive is not one of Michel's rules.
	ErrUnknownDirective = errors.New("serverfix: unknown directive")
	// ErrUnknownService: the service is not a PHP-FPM seen on the server.
	ErrUnknownService = errors.New("serverfix: unknown service")
	// ErrUnknownPackage: the package is not installed on the server, its
	// version is malformed, or the system's package manager is unknown.
	ErrUnknownPackage = errors.New("serverfix: unknown package")
	// ErrMajorUpgrade: the upgrade changes the PHP branch; it is only ever
	// a proposal, never a script.
	ErrMajorUpgrade = errors.New("serverfix: this upgrade changes the PHP branch, it can only be proposed")
	// ErrBadAction: an unknown op, a missing field, an empty plan or a plan
	// for another server.
	ErrBadAction = errors.New("serverfix: malformed action")
	// ErrGrammar: a rendered script holds a line outside the grammar.
	ErrGrammar = errors.New("serverfix: script line outside the grammar")
)

// ErrWouldRemove means a package manager's simulation would remove or
// replace packages: the upgrade is refused.
type ErrWouldRemove struct {
	Packages []string
}

func (e ErrWouldRemove) Error() string {
	return "serverfix: the upgrade would remove " + strings.Join(e.Packages, ", ")
}
