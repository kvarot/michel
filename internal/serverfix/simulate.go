package serverfix

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var (
	// apt-get -s: "Inst name [old] (new ...)", "Remv name [old]", "Purg ...".
	aptLine = regexp.MustCompile(`^(Inst|Remv|Purg) (\S+)( \[[^\]]*\])?`)
	// apk --simulate: "(1/2) Upgrading name (old -> new)".
	apkLine = regexp.MustCompile(`^\(\d+/\d+\) (\S+) (\S+)`)
	// dnf: a package line of the transaction table, or "replacing  name".
	dnfPkg     = regexp.MustCompile(`^\s+(\S+)\s+\S+\s+\S+`)
	dnfReplace = regexp.MustCompile(`^\s+replacing\s+(\S+)`)
)

// ParseSimulation reads what a package manager's dry run would do: manager
// is "apt" (apt-get -s), "dnf" (dnf --assumeno) or "apk" (apk --simulate).
// A removal, a replacement or a downgrade is returned in Removes and as
// ErrWouldRemove: the upgrade must not run.
func ParseSimulation(manager, out string) (SimResult, error) {
	var r SimResult
	switch manager {
	case "apt":
		for _, l := range lines(out) {
			m := aptLine.FindStringSubmatch(l)
			switch {
			case m == nil:
			case m[1] != "Inst":
				r.Removes = append(r.Removes, m[2])
			case m[3] != "":
				r.Upgrades = append(r.Upgrades, m[2])
			default:
				r.Installs = append(r.Installs, m[2])
			}
		}
	case "apk":
		for _, l := range lines(out) {
			m := apkLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			switch m[1] {
			case "Upgrading":
				r.Upgrades = append(r.Upgrades, m[2])
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
			case strings.HasPrefix(section, "installing"):
				r.Installs = append(r.Installs, m[1])
			case strings.HasPrefix(section, "removing"), strings.HasPrefix(section, "obsoleting"),
				strings.HasPrefix(section, "downgrading"), strings.HasPrefix(section, "replacing"),
				strings.HasPrefix(section, "erasing"):
				r.Removes = append(r.Removes, m[1])
			}
		}
	default:
		return SimResult{}, fmt.Errorf("%w: package manager %q", ErrUnknownPackage, manager)
	}
	if len(r.Removes) > 0 {
		return r, ErrWouldRemove{Packages: slices.Compact(slices.Sorted(slices.Values(r.Removes)))}
	}
	return r, nil
}

func lines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
