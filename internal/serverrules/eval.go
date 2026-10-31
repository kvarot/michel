package serverrules

import (
	"fmt"
	"regexp"
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

// isOn reads a PHP boolean: on/true/yes, or any integer other than 0.
// iniValue is a raw ini value as PHP reads it: a quoted value is what is
// between its quotes, anything after them ignored; otherwise an inline `;`
// comment is cut (collect keeps it) and spaces are trimmed.
func iniValue(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && (v[0] == '"' || v[0] == '\'') {
		if j := strings.IndexByte(v[1:], v[0]); j >= 0 {
			return v[1 : 1+j]
		}
	}
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

func isOn(v string) bool {
	v = strings.ToLower(strings.TrimSpace(iniValue(v)))
	switch v {
	case "on", "true", "yes":
		return true
	}
	// PHP's zend_ini_parse_bool falls back to atoi: an optional sign, then
	// the leading digits; the rest is ignored ("1x", "1.0" are On).
	if v != "" && (v[0] == '+' || v[0] == '-') {
		v = v[1:]
	}
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	return strings.TrimLeft(v[:i], "0") != ""
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
// mitigation setting is reported only for a runtime known (or unable to be
// ruled out) to be vulnerable. A compiled runtime whose version cannot be
// read gets a visible finding instead of being skipped.
func Evaluate(t target.Target, inv target.Inventory, s Set) []scan.Finding {
	return EvaluateWith(t, inv, s, Options{})
}

// Options carries what Evaluate cannot read in the inventory.
type Options struct {
	// DistroOpen maps an installed package name to the ids and aliases of
	// the distribution advisories still open on it (the vulnerability
	// matcher's hits). A runtime installed from that package counts the
	// upstream advisories they name as open, so the mitigation settings
	// that hold those back are judged for it too.
	DistroOpen map[string][]string
}

// EvaluateWith is Evaluate with the distribution advisories of o.
func EvaluateWith(t target.Target, inv target.Inventory, s Set, o Options) []scan.Finding {
	var out []scan.Finding
	for _, rt := range inv.PHP {
		key := rt.SAPI + ":" + rt.Binary
		ver, okVer := parseVersion(rt.Version)
		var open []UpstreamAdvisory
		switch {
		case rt.FromPackage != "":
			open = namedIn(s.Upstream, o.DistroOpen[rt.FromPackage])
		case !okVer:
			open = s.Upstream
			out = append(out, unknownVersionFinding(t, rt, key, s))
		default:
			for _, a := range s.Upstream {
				if fixed, bad := judge(a, ver); bad {
					open = append(open, a)
					out = append(out, upstreamFinding(t, rt, key, a, fixed))
				}
			}
			for _, b := range s.EOL {
				if b.Branch == branchOf(rt.Version) {
					out = append(out, eolFinding(t, rt, key, b.Branch))
				}
			}
			if lim, ok := parseVersion(s.EOLBefore); ok && compare([3]int{ver[0], ver[1], 0}, [3]int{lim[0], lim[1], 0}) < 0 &&
				!slices.ContainsFunc(s.EOL, func(b Branch) bool { return b.Branch == branchOf(rt.Version) }) {
				out = append(out, eolFinding(t, rt, key, branchOf(rt.Version)))
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

func unknownVersionFinding(t target.Target, rt target.PHPRuntime, key string, s Set) scan.Finding {
	var aliases []string
	for _, a := range s.Upstream {
		aliases = append(aliases, a.Aliases...)
	}
	return scan.Finding{
		ID:              scan.FindingID(t.ID, key, ecoUpstream, "php", "PHP-VERSION-UNKNOWN"),
		ProjectID:       t.ID,
		ManifestRelPath: key,
		Ecosystem:       ecoUpstream,
		Package:         "php",
		OSVID:           "PHP-VERSION-UNKNOWN",
		Aliases:         aliases,
		SeverityLabel:   "high",
		Summary:         "PHP version could not be read; PHP2Shell cannot be ruled out",
		Kind:            scan.KindServerPackage,
		SAPI:            rt.SAPI,
	}
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

func eolFinding(t target.Target, rt target.PHPRuntime, key, branch string) scan.Finding {
	id := "EOL-" + branch
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

// RiskyValue says whether value is the risky one for the rule, judged as
// the evaluation does (on, off or empty).
func RiskyValue(r ConfigRule, value string) bool { return riskyValue(r, value) }

var poolRe = regexp.MustCompile(`^php_(admin_)?(value|flag)\[(.+)\]$`)

// riskyValue says whether a value of the rule's directive is the risky one.
func riskyValue(r ConfigRule, value string) bool {
	switch r.Risky {
	case "on":
		return isOn(value)
	case "off":
		return !isOn(value)
	default:
		// Empty, or a path list holding "/" (which restricts nothing).
		v := iniValue(value)
		if v == "" {
			return true
		}
		for _, part := range strings.Split(v, ":") {
			if strings.TrimSpace(part) == "/" {
				return true
			}
		}
		return false
	}
}

// riskySource looks for a risky effective value of the rule's directive for
// a runtime. Each PHP-FPM pool is judged on its own: the ini value, then the
// pool's php_value/php_flag (not for a system directive), then its
// php_admin_value/php_admin_flag, which is final. A .user.ini line can only
// add risk: it never clears a finding (Michel does not know which folders
// of the server a runtime serves, so one safe .user.ini proves nothing), it
// is ignored for a system directive or one fixed by php_admin_*, and a line
// without a binary counts for every FPM. Masked values are never read.
func riskySource(inv target.Inventory, rt target.PHPRuntime, r ConfigRule) (src target.Directive, found, risky bool) {
	scopes := rt.PoolFiles
	if len(scopes) == 0 || rt.SAPI != "fpm" {
		scopes = []string{""}
	}
	for _, scope := range scopes {
		var cur, admin target.Directive
		var have, haveAdmin bool
		for _, x := range inv.Directives {
			if x.Secret || x.SAPI != rt.SAPI || x.Binary != rt.Binary {
				continue
			}
			if x.Name == r.Directive {
				cur, have = x, true
				continue
			}
			if scope == "" || x.File != scope {
				continue
			}
			m := poolRe.FindStringSubmatch(x.Name)
			if m == nil || m[3] != r.Directive {
				continue
			}
			switch {
			case m[1] != "":
				admin, haveAdmin = x, true
			case r.Changeable != "system":
				cur, have = x, true
			}
		}
		if haveAdmin {
			cur, have = admin, true
		}
		if have && riskyValue(r, cur.Value) {
			return cur, true, true
		}
		if !have && r.MissingIsRisky {
			return target.Directive{}, false, true
		}
		if haveAdmin || r.Changeable == "system" {
			continue
		}
		for _, x := range inv.Directives {
			if x.Secret || x.SAPI != "user_ini" || x.Name != r.Directive || (x.Binary != "" && x.Binary != rt.Binary) {
				continue
			}
			if riskyValue(r, x.Value) {
				return x, true, true
			}
		}
	}
	return target.Directive{}, false, false
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
	d, found, risky := riskySource(inv, rt, r)
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

// namedIn returns the advisories whose id or one alias is in ids.
func namedIn(all []UpstreamAdvisory, ids []string) []UpstreamAdvisory {
	if len(ids) == 0 {
		return nil
	}
	var out []UpstreamAdvisory
	for _, a := range all {
		if slices.Contains(ids, a.ID) || slices.ContainsFunc(a.Aliases, func(x string) bool { return slices.Contains(ids, x) }) {
			out = append(out, a)
		}
	}
	return out
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
