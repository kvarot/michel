package analyze

import (
	"regexp"
	"strconv"
	"strings"

	"deps.dev/util/semver"
)

// Jump is the size of the version change needed to reach the fixed version.
type Jump string

const (
	JumpNone    Jump = "none"
	JumpPatch   Jump = "patch"
	JumpMinor   Jump = "minor"
	JumpMajor   Jump = "major"
	JumpUnknown Jump = "unknown"
)

// Upgrade describes how to reach a fixed version.
type Upgrade struct {
	// Target is the smallest fixed version strictly greater than the installed
	// one, "" when there is none.
	Target string
	Jump   Jump
	// ConstraintAllows is nil when the constraint is empty, unparsable, or
	// there is no target.
	ConstraintAllows *bool
}

// systemFor maps an OSV ecosystem name to its semver rules. Packagist uses the
// library's Composer rules (so ~1.2 means >=1.2 <2.0, unlike npm).
func systemFor(ecosystem string) (semver.System, bool) {
	switch ecosystem {
	case "npm":
		return semver.NPM, true
	case "Packagist":
		return semver.Composer, true
	}
	return semver.DefaultSystem, false
}

// NormalizeVersion strips a leading v/V and surrounding spaces and returns the
// canonical version, or "" when the ecosystem parser rejects it.
func NormalizeVersion(ecosystem, v string) string {
	sys, ok := systemFor(ecosystem)
	if !ok {
		return ""
	}
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "vV")
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	parsed, err := sys.Parse(v)
	if err != nil {
		return ""
	}
	return parsed.Canon(false)
}

// PlanUpgrade picks the target among fixed, classifies the jump from installed
// and checks it against the project's constraint.
func PlanUpgrade(ecosystem, installed string, fixed []string, constraint string) Upgrade {
	up := Upgrade{Jump: JumpNone}
	sys, ok := systemFor(ecosystem)
	if !ok {
		return up
	}
	inst, instErr := sys.Parse(strings.TrimLeft(strings.TrimSpace(installed), "vV"))

	var best *semver.Version
	bestStr := ""
	for _, f := range fixed {
		raw := strings.TrimSpace(f)
		fv, err := sys.Parse(strings.TrimLeft(raw, "vV"))
		if err != nil {
			continue
		}
		if instErr == nil && fv.Compare(inst) <= 0 {
			continue
		}
		if best == nil || fv.Compare(best) < 0 {
			best, bestStr = fv, strings.TrimLeft(raw, "vV")
		}
	}
	if best == nil {
		return up
	}
	up.Target = bestStr

	// An unparsable installed version (e.g. dev-master) gives an unknown jump
	// and leaves the constraint unevaluated.
	if instErr != nil {
		up.Jump = JumpUnknown
		return up
	}
	up.Jump = jumpBetween(inst, best)
	if allowed, ok := constraintAllows(sys, constraint, best); ok {
		up.ConstraintAllows = &allowed
	}
	return up
}

// jumpBetween compares major/minor/patch only; pre-release and build are ignored.
func jumpBetween(from, to *semver.Version) Jump {
	a, b := numbers(from), numbers(to)
	switch {
	case a[0] != b[0]:
		return JumpMajor
	case a[1] != b[1]:
		return JumpMinor
	}
	return JumpPatch
}

// numbers returns the first three numeric components of the canonical form.
func numbers(v *semver.Version) [3]uint64 {
	s := v.Canon(false)
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	var out [3]uint64
	for i, p := range strings.Split(s, ".") {
		if i == 3 {
			break
		}
		n, _ := strconv.ParseUint(p, 10, 64)
		out[i] = n
	}
	return out
}

// constraintAllows reports whether v satisfies the constraint; ok is false when
// the constraint is empty or cannot be understood.
func constraintAllows(sys semver.System, constraint string, v *semver.Version) (allowed, ok bool) {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return false, false
	}
	if sys == semver.Composer {
		return composerAllows(constraint, v)
	}
	defer func() {
		// The library can panic on malformed input; treat it as unknown.
		if recover() != nil {
			allowed, ok = false, false
		}
	}()
	c, err := sys.ParseConstraint(constraint)
	if err != nil {
		return false, false
	}
	return c.MatchVersion(v), true
}

// Composer constraints are not supported by deps.dev/util/semver (its
// ParseConstraint panics for Composer), so the common syntax is evaluated here:
// || and | (or), space and comma (and), ^ ~ >= <= > < = != <>, X.* wildcards
// and "A - B" ranges. Anything else (@dev flags, dev- branches...) is unknown.
var (
	composerOpGap = regexp.MustCompile(`(>=|<=|!=|<>|[<>=~^])\s+`)
	composerRange = regexp.MustCompile(`(\S+)\s+-\s+(\S+)`)
	composerOr    = regexp.MustCompile(`\s*\|\|?\s*`)
	composerAnd   = regexp.MustCompile(`[\s,]+`)
)

func composerAllows(constraint string, v *semver.Version) (allowed, ok bool) {
	for _, group := range composerOr.Split(constraint, -1) {
		group = composerRange.ReplaceAllStringFunc(group, hyphenRange)
		group = composerOpGap.ReplaceAllString(strings.TrimSpace(group), "$1")
		if group == "" {
			return false, false
		}
		groupOK := true
		for _, atom := range composerAnd.Split(group, -1) {
			m, valid := composerAtom(atom, v)
			if !valid {
				return false, false
			}
			groupOK = groupOK && m
		}
		allowed = allowed || groupOK
	}
	return allowed, true
}

// composerAtom evaluates one comparator against v.
func composerAtom(atom string, v *semver.Version) (match, valid bool) {
	if atom == "*" || atom == "x" || atom == "X" {
		return true, true
	}
	op := ""
	for _, o := range []string{">=", "<=", "!=", "<>", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(atom, o) {
			op, atom = o, atom[len(o):]
			break
		}
	}
	atom = strings.TrimLeft(atom, "vV")
	if strings.HasSuffix(atom, ".*") || strings.HasSuffix(atom, ".x") {
		if op != "" {
			return false, false
		}
		prefix := strings.Split(strings.TrimSuffix(strings.TrimSuffix(atom, ".*"), ".x"), ".")
		got := numbers(v)
		for i, p := range prefix {
			n, err := strconv.ParseUint(p, 10, 64)
			if err != nil || i > 2 {
				return false, false
			}
			if got[i] != n {
				return false, true
			}
		}
		return true, true
	}
	base, err := semver.Composer.Parse(atom)
	if err != nil {
		return false, false
	}
	cmp := v.Compare(base)
	parts := len(strings.Split(atom, "."))
	b := numbers(base)
	switch op {
	case "", "=":
		return cmp == 0, true
	case "!=", "<>":
		return cmp != 0, true
	case ">":
		return cmp > 0, true
	case ">=":
		return cmp >= 0, true
	case "<":
		return cmp < 0, true
	case "<=":
		return cmp <= 0, true
	case "~":
		// ~1.2 = >=1.2 <2.0 ; ~1.2.3 = >=1.2.3 <1.3.0 ; ~1 = >=1 <2.
		// ~1.2.3.4 = >=1.2.3.4 <1.2.4.
		upper := [3]uint64{b[0] + 1, 0, 0}
		if parts >= 4 {
			upper = [3]uint64{b[0], b[1], b[2] + 1}
		} else if parts == 3 {
			upper = [3]uint64{b[0], b[1] + 1, 0}
		}
		return cmp >= 0 && less(numbers(v), upper), true
	case "^":
		// Next breaking version: bump the first non-zero component.
		upper := [3]uint64{b[0] + 1, 0, 0}
		switch {
		case b[0] > 0 || parts == 1:
		case b[1] > 0 || parts == 2:
			upper = [3]uint64{0, b[1] + 1, 0}
		default:
			upper = [3]uint64{0, 0, b[2] + 1}
		}
		return cmp >= 0 && less(numbers(v), upper), true
	}
	return false, false
}

func less(a, b [3]uint64) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// hyphenRange rewrites "A - B" as ">=A <=B", or ">=A <B'" when B has fewer than
// three parts (Composer: 1.0 - 2.0 = >=1.0.0 <2.1.0), B' being B with its last
// given component incremented.
func hyphenRange(m string) string {
	sub := composerRange.FindStringSubmatch(m)
	lo, hi := sub[1], sub[2]
	parts := strings.Split(strings.TrimLeft(hi, "vV"), ".")
	if len(parts) < 3 {
		if n, err := strconv.ParseUint(parts[len(parts)-1], 10, 64); err == nil {
			parts[len(parts)-1] = strconv.FormatUint(n+1, 10)
			return ">=" + lo + " <" + strings.Join(parts, ".")
		}
	}
	return ">=" + lo + " <=" + hi
}
