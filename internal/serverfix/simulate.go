package serverfix

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

var (
	// apt-get -s: "Inst name [old] (new ...)", "Remv name [old]", "Purg ...".
	aptLine = regexp.MustCompile(`^(Inst|Remv|Purg) (\S+)(?: \[([^\]]*)\])?(?: \((\S+))?`)
	// apk --simulate: "(1/2) Upgrading name (old -> new)".
	apkLine = regexp.MustCompile(`^\(\d+/\d+\) (\S+) (\S+)(?: \((\S+)(?: -> (\S+))?\))?`)
	// dnf: a package line of the transaction table, or "replacing  name".
	dnfPkg     = regexp.MustCompile(`^\s+(\S+)\s+(\S+)\s+(\S+)`)
	dnfReplace = regexp.MustCompile(`^\s+replacing\s+(\S+)`)
)

// simEco is the version ecosystem of a manager, for comparisons.
var simEco = map[string]string{"apt": "Debian", "dnf": "Red Hat", "apk": "Alpine"}

// ParseSimulation reads what a package manager's dry run would do: manager
// is "apt" (apt-get -s), "dnf" (dnf --assumeno) or "apk" (apk --simulate);
// pkg and version are the upgrade the fix asks for. It fails closed:
//   - a removal, a replacement or a downgrade (an apt "Inst" to a lower
//     version included) is returned in Removes and as ErrWouldRemove;
//   - an output that does not show pkg upgraded to version (apk: to at
//     least version, as `apk add --upgrade 'pkg>=version'` asks) is
//     ErrSimulation: empty output, an error line, a lock, another version.
//
// The caller still checks the manager's exit status (dnf --assumeno always
// exits 1).
func ParseSimulation(manager, out, pkg, version string) (SimResult, error) {
	var r SimResult
	eco, ok := simEco[manager]
	if !ok {
		return SimResult{}, fmt.Errorf("%w: package manager %q", ErrUnknownPackage, manager)
	}
	lower := func(a, b string) bool { // a < b
		v, err := semantic.Parse(a, eco)
		if err != nil {
			return false
		}
		c, err := v.CompareStr(b)
		return err == nil && c < 0
	}
	got := "" // the new version of pkg
	switch manager {
	case "apt":
		for _, l := range lines(out) {
			if strings.HasPrefix(l, "E:") {
				return SimResult{}, fmt.Errorf("%w: %s", ErrSimulation, strings.TrimSpace(l))
			}
			m := aptLine.FindStringSubmatch(l)
			switch {
			case m == nil:
			case m[1] != "Inst":
				r.Removes = append(r.Removes, m[2])
			case m[3] != "" && m[4] != "" && lower(m[4], m[3]):
				r.Removes = append(r.Removes, m[2]) // a downgrade
			case m[3] != "":
				r.Upgrades = append(r.Upgrades, m[2])
				if m[2] == pkg {
					got = m[4]
				}
			default:
				r.Installs = append(r.Installs, m[2])
			}
		}
	case "apk":
		for _, l := range lines(out) {
			if strings.HasPrefix(l, "ERROR:") {
				return SimResult{}, fmt.Errorf("%w: %s", ErrSimulation, strings.TrimSpace(l))
			}
			m := apkLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			switch m[1] {
			case "Upgrading":
				r.Upgrades = append(r.Upgrades, m[2])
				if m[2] == pkg {
					got = m[4]
				}
			case "Installing":
				r.Installs = append(r.Installs, m[2])
			case "Purging", "Deleting", "Removing", "Replacing", "Downgrading":
				r.Removes = append(r.Removes, m[2])
			}
		}
	case "dnf":
		section := ""
		for _, l := range lines(out) {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "Error:") {
				return SimResult{}, fmt.Errorf("%w: %s", ErrSimulation, t)
			}
			if strings.HasPrefix(t, "Transaction Summary") || strings.HasPrefix(t, "Transaction summary") {
				break
			}
			if !strings.HasPrefix(l, " ") && strings.HasSuffix(t, ":") {
				section = strings.ToLower(t)
				continue
			}
			if m := dnfReplace.FindStringSubmatch(l); m != nil {
				r.Removes = append(r.Removes, m[1])
				continue
			}
			m := dnfPkg.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			switch {
			case strings.HasPrefix(section, "upgrading"):
				r.Upgrades = append(r.Upgrades, m[1])
				if m[1] == pkg {
					got = m[3]
				}
			case strings.HasPrefix(section, "installing"):
				r.Installs = append(r.Installs, m[1])
			case strings.HasPrefix(section, "removing"), strings.HasPrefix(section, "obsoleting"),
				strings.HasPrefix(section, "downgrading"), strings.HasPrefix(section, "replacing"),
				strings.HasPrefix(section, "erasing"):
				r.Removes = append(r.Removes, m[1])
			}
		}
	}
	if len(r.Removes) > 0 {
		return r, ErrWouldRemove{Packages: slices.Compact(slices.Sorted(slices.Values(r.Removes)))}
	}
	want := version
	if _, rest, ok := strings.Cut(version, ":"); ok && manager == "dnf" && !strings.Contains(got, ":") {
		want = rest // dnf prints no epoch
	}
	switch {
	case got == "":
		return r, fmt.Errorf("%w: %s is not upgraded", ErrSimulation, pkg)
	case manager == "apk" && !lower(got, version):
	case got != want:
		return r, fmt.Errorf("%w: %s goes to %s, not %s", ErrSimulation, pkg, got, version)
	}
	return r, nil
}

func lines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
