package serverrules

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

const (
	ecoUpstream = "php-upstream"
	ecoConfig   = "php-config"
)

// parseVersion reads the numeric X.Y.Z head of a PHP version, ignoring any
// suffix ("8.3.36-1", "8.4.0RC1"). X.Y is enough; a missing patch is 0.
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.SplitN(strings.TrimSpace(v), ".", 3)
	if len(parts) < 2 {
		return out, false
	}
	for i, p := range parts {
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		if end == 0 {
			return out, false
		}
		n, err := strconv.Atoi(p[:end])
		if err != nil {
			return out, false
		}
		out[i] = n
		if end < len(p) {
			break // a suffix ends the numeric part
		}
	}
	return out, true
}

func compare(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func branchOf(v string) string {
	n, ok := parseVersion(v)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d.%d", n[0], n[1])
}

func isOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes":
		return true
	}
	return false
}

// judge says whether a version is affected by an advisory: on a listed
// branch below its fix, or on a branch older than every fixed one (no fix
// exists there, so the lowest supported fix is advised).
func judge(a UpstreamAdvisory, version [3]int) (fixed string, vulnerable bool) {
	branch := fmt.Sprintf("%d.%d", version[0], version[1])
	var lowest [3]int
	lowestFix := ""
	for _, b := range a.Branches {
		fv, _ := parseVersion(b.Fixed)
		if lowestFix == "" || compare(fv, lowest) < 0 {
			lowest, lowestFix = fv, b.Fixed
		}
		if b.Branch == branch {
			return b.Fixed, compare(version, fv) < 0
		}
	}
	if compare([3]int{version[0], version[1], 0}, [3]int{lowest[0], lowest[1], 0}) < 0 {
		return lowestFix, true
	}
	return "", false
}

// Evaluate turns the inventory of a server into findings: one per runtime
// and per rule. A runtime installed from a distribution package is not judged
// on its upstream version (distributions fix without changing it; the
// vulnerability matcher handles those), only on its settings, and a
// mitigation setting is reported only for a runtime known to be vulnerable.
func Evaluate(t target.Target, inv target.Inventory, s Set) []scan.Finding {
	var out []scan.Finding
	for _, rt := range inv.PHP {
		key := rt.SAPI + ":" + rt.Binary
		ver, okVer := parseVersion(rt.Version)
		var open []UpstreamAdvisory
		if rt.FromPackage == "" && okVer {
			for _, a := range s.Upstream {
				if fixed, bad := judge(a, ver); bad {
					open = append(open, a)
					out = append(out, upstreamFinding(t, rt, key, a, fixed))
				}
			}
			for _, b := range s.EOL {
				if b.Branch == branchOf(rt.Version) {
					out = append(out, eolFinding(t, rt, key, b))
				}
			}
		}
		for _, r := range s.Config {
			if f, ok := configFinding(t, inv, rt, key, ver, okVer, open, r); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

func upstreamFinding(t target.Target, rt target.PHPRuntime, key string, a UpstreamAdvisory, fixed string) scan.Finding {
	return scan.Finding{
		ID:               scan.FindingID(t.ID, key, ecoUpstream, "php", a.ID),
		ProjectID:        t.ID,
		ManifestRelPath:  key,
		Ecosystem:        ecoUpstream,
		Package:          "php",
		OSVID:            a.ID,
		Aliases:          slices.Clone(a.Aliases),
		SeverityLabel:    a.Severity,
		CVSS:             a.CVSS,
		InstalledVersion: rt.Version,
		FixedVersions:    []string{fixed},
		Summary:          "PHP " + rt.Version + " is affected by " + a.ID + "; fixed in " + fixed,
		Kind:             scan.KindServerPackage,
		SAPI:             rt.SAPI,
	}
}

func eolFinding(t target.Target, rt target.PHPRuntime, key string, b Branch) scan.Finding {
	id := "EOL-" + b.Branch
	return scan.Finding{
		ID:               scan.FindingID(t.ID, key, ecoUpstream, "php", id),
		ProjectID:        t.ID,
		ManifestRelPath:  key,
		Ecosystem:        ecoUpstream,
		Package:          "php",
		OSVID:            id,
		SeverityLabel:    "high",
		InstalledVersion: rt.Version,
		Summary:          "branch no longer supported",
		Kind:             scan.KindServerPackage,
		SAPI:             rt.SAPI,
	}
}

// directiveValue finds the value of a directive for a runtime. Directives
// match by binary and SAPI; a .user.ini directive applies to the FPM runtime
// (an empty binary meaning the only FPM) and wins over the ini files. Masked
// (secret) values are never read.
func directiveValue(inv target.Inventory, rt target.PHPRuntime, name string) (d target.Directive, found bool) {
	for _, x := range inv.Directives {
		if x.Name != name || x.Secret {
			continue
		}
		switch {
		case x.SAPI == "user_ini" && rt.SAPI == "fpm" && (x.Binary == "" || x.Binary == rt.Binary):
		case x.SAPI == rt.SAPI && x.Binary == rt.Binary:
			if found && d.SAPI == "user_ini" {
				continue
			}
		default:
			continue
		}
		d, found = x, true
	}
	return d, found
}

func contextHolds(t target.Target, rt target.PHPRuntime, ctx []string) bool {
	for _, c := range ctx {
		switch {
		case c == "prod":
			if t.Env != target.EnvProd {
				return false
			}
		case c == "shared":
			if t.Kind != target.KindShared {
				return false
			}
		case c == "https":
			if !strings.HasPrefix(strings.ToLower(t.SiteURL), "https") {
				return false
			}
		case strings.HasPrefix(c, "sapi:"):
			if rt.SAPI != strings.TrimPrefix(c, "sapi:") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func configFinding(t target.Target, inv target.Inventory, rt target.PHPRuntime, key string, ver [3]int, okVer bool,
	open []UpstreamAdvisory, r ConfigRule) (scan.Finding, bool) {
	if !contextHolds(t, rt, r.Context) {
		return scan.Finding{}, false
	}
	if len(r.Branches) > 0 && !(okVer && slices.Contains(r.Branches, fmt.Sprintf("%d.%d", ver[0], ver[1]))) {
		return scan.Finding{}, false
	}
	if r.Mitigation && !mitigatesOpen(r, open) {
		return scan.Finding{}, false
	}
	d, found := directiveValue(inv, rt, r.Directive)
	value := d.Value
	if !found {
		if !r.MissingIsRisky {
			return scan.Finding{}, false
		}
		if r.Risky == "on" {
			value = "1" // PHP's own default is the risky one
		}
	}
	var risky bool
	switch r.Risky {
	case "on":
		risky = isOn(value)
	case "off":
		risky = !isOn(value)
	case "empty":
		risky = strings.TrimSpace(value) == ""
	}
	if !risky {
		return scan.Finding{}, false
	}
	f := scan.Finding{
		ID:               scan.FindingID(t.ID, key, ecoConfig, r.Directive, r.ID),
		ProjectID:        t.ID,
		ManifestRelPath:  key,
		Ecosystem:        ecoConfig,
		Package:          r.Directive,
		OSVID:            r.ID,
		SeverityLabel:    r.Severity,
		InstalledVersion: rt.Version,
		Summary:          r.Directive + " is risky; advised: " + advisedText(r),
		Kind:             scan.KindServerConfig,
		Mitigation:       r.Mitigation,
		SAPI:             rt.SAPI,
	}
	if found && d.File != "" {
		f.Location = d.File
		if d.Line > 0 {
			f.Location += ":" + strconv.Itoa(d.Line)
		}
	}
	return f, true
}

func advisedText(r ConfigRule) string {
	if r.Advised == "" {
		return "set it to the site directory"
	}
	return r.Advised
}

// mitigatesOpen tells whether the rule holds back one of the open advisories.
func mitigatesOpen(r ConfigRule, open []UpstreamAdvisory) bool {
	for _, a := range open {
		for _, m := range r.Mitigates {
			if m == a.ID || slices.Contains(a.Aliases, m) {
				return true
			}
		}
	}
	return false
}
