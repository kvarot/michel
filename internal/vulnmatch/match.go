package vulnmatch

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/semantic"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/kvarot/michel/internal/osvdb"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// maxAdvisory caps the size of one advisory file read from an archive.
const maxAdvisory = 4 << 20

// ErrSourceDisabled says the database of an ecosystem is not on this
// computer: its source is off or not downloaded yet. Key is the catalog key
// the server sheet offers to turn on.
type ErrSourceDisabled struct{ Key string }

func (e ErrSourceDisabled) Error() string {
	return "osv source " + e.Key + " is disabled or not downloaded"
}

// Hit is one source package (or package, outside Debian-family
// distributions) affected by one distribution advisory. Package stands for the
// installed package that carries the finding (the binary named like the
// source, else the first by name); Binaries lists every affected installed
// package name. Aliases carry the CVE ids so callers can reconcile with other
// findings. Uncertain means a version could not be compared, so the package is
// reported as affected to stay on the safe side.
type Hit struct {
	Package   target.Package
	Source    string
	Binaries  []string
	OSVID     string
	Aliases   []string
	Severity  string
	CVSS      float64
	Fixed     string
	Uncertain bool
}

// Unjudged is a package an advisory names but whose affected state could not
// be decided (a version or a range bound does not parse).
type Unjudged struct {
	Package target.Package
	OSVID   string
	Reason  string
}

// Result is what Match found. ReleaseKnown is false when no advisory of the
// archive names the exact ecosystem (a release too new for the database): zero
// hits then does not mean clean. Skipped counts advisory files that could not
// be read and were ignored.
type Result struct {
	Hits         []Hit
	Unjudged     []Unjudged
	ReleaseKnown bool
	Skipped      int
}

type event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type osvRange struct {
	Type   string  `json:"type"`
	Events []event `json:"events"`
}

type advisory struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges   []osvRange `json:"ranges"`
		Versions []string   `json:"versions"`
	} `json:"affected"`
}

// debianFamily says whether OSV names source packages for the ecosystem
// (Debian, Ubuntu). Elsewhere (Alpine origin, RPM) a package is looked up by
// both its source and its own name, because the records may use either.
func debianFamily(eco string) bool {
	b := base(eco)
	return b == "Debian" || b == "Ubuntu"
}

type rawHit struct {
	group     string
	pkg       target.Package
	osvID     string
	aliases   []string
	severity  string
	cvss      float64
	fixed     string
	uncertain bool
}

// Match reads the ecosystem's archive under osvRoot and returns the packages
// it affects. In Debian-family ecosystems the advisories name source packages,
// so a package's Source is used when it has one; elsewhere both the source and
// the package name are tried. Hits are collapsed per advisory and source. A
// missing archive is ErrSourceDisabled. A version or range bound that cannot
// be parsed counts as affected (Uncertain) and is also listed in Unjudged. An
// unreadable advisory file is skipped and counted.
func Match(ctx context.Context, osvRoot, eco string, pkgs []target.Package) (Result, error) {
	var res Result
	zr, err := zip.OpenReader(osvdb.ZipPath(osvRoot, base(eco)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return res, ErrSourceDisabled{Key: CatalogKey(eco)}
		}
		return res, err
	}
	defer zr.Close()

	byName := map[string][]int{}
	add := func(n string, i int) {
		if n != "" && !slices.Contains(byName[n], i) {
			byName[n] = append(byName[n], i)
		}
	}
	for i, p := range pkgs {
		if debianFamily(eco) && p.Source != "" {
			add(p.Source, i)
			continue
		}
		add(p.Source, i)
		add(p.Name, i)
	}

	var raw []rawHit
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		adv, err := readAdvisory(f)
		if err != nil {
			res.Skipped++
			continue
		}
		if adv.Withdrawn != "" {
			continue
		}
		for _, a := range adv.Affected {
			if a.Package.Ecosystem != eco {
				continue
			}
			res.ReleaseKnown = true
			for _, i := range byName[a.Package.Name] {
				p := pkgs[i]
				st := isAffected(eco, p.Version, a.Ranges, a.Versions)
				if !st.affected {
					continue
				}
				label, score := severity(adv)
				raw = append(raw, rawHit{group: a.Package.Name, pkg: p, osvID: adv.ID, aliases: adv.Aliases, severity: label, cvss: score, fixed: st.fixed, uncertain: st.uncertain})
				if st.uncertain {
					res.Unjudged = append(res.Unjudged, Unjudged{Package: p, OSVID: adv.ID, Reason: st.reason})
				}
			}
		}
	}
	res.Hits = collapse(raw)
	slices.SortStableFunc(res.Unjudged, func(a, b Unjudged) int {
		if c := strings.Compare(a.Package.Name, b.Package.Name); c != 0 {
			return c
		}
		if c := strings.Compare(a.OSVID, b.OSVID); c != 0 {
			return c
		}
		return strings.Compare(a.Package.Arch, b.Package.Arch)
	})
	res.Unjudged = slices.CompactFunc(res.Unjudged, func(a, b Unjudged) bool {
		return a.Package == b.Package && a.OSVID == b.OSVID
	})
	return res, nil
}

// collapse merges raw hits into one Hit per (source, advisory). The carrier
// package is the binary named like the source, else the first by name and
// architecture. A hit with a fixed version wins over one without, and a
// certain one over an uncertain one, so the outcome does not depend on order.
func collapse(raw []rawHit) []Hit {
	slices.SortStableFunc(raw, func(a, b rawHit) int {
		if c := strings.Compare(a.group, b.group); c != 0 {
			return c
		}
		if c := strings.Compare(a.osvID, b.osvID); c != 0 {
			return c
		}
		if c := strings.Compare(a.pkg.Name, b.pkg.Name); c != 0 {
			return c
		}
		if c := strings.Compare(a.pkg.Arch, b.pkg.Arch); c != 0 {
			return c
		}
		return strings.Compare(a.fixed, b.fixed)
	})
	var out []Hit
	for _, r := range raw {
		if n := len(out); n > 0 && out[n-1].Source == r.group && out[n-1].OSVID == r.osvID {
			h := &out[n-1]
			if !slices.Contains(h.Binaries, r.pkg.Name) {
				h.Binaries = append(h.Binaries, r.pkg.Name)
			}
			if r.pkg.Name == r.group && h.Package.Name != r.group {
				h.Package = r.pkg
			}
			if r.fixed != "" && (h.Fixed == "" || h.Uncertain && !r.uncertain) {
				h.Fixed = r.fixed
			}
			h.Uncertain = h.Uncertain && r.uncertain
			continue
		}
		out = append(out, Hit{
			Package: r.pkg, Source: r.group, Binaries: []string{r.pkg.Name}, OSVID: r.osvID,
			Aliases: slices.Clone(r.aliases), Severity: r.severity, CVSS: r.cvss, Fixed: r.fixed, Uncertain: r.uncertain,
		})
	}
	return out
}

func readAdvisory(f *zip.File) (advisory, error) {
	var adv advisory
	rc, err := f.Open()
	if err != nil {
		return adv, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxAdvisory+1))
	if err != nil {
		return adv, err
	}
	if len(data) > maxAdvisory {
		return adv, errors.New("advisory too large")
	}
	return adv, json.Unmarshal(data, &adv)
}

// severity scores the CVSS vectors (or numeric scores) of an advisory, keeps
// the highest, and labels it; without a score it falls back to a severity
// label of the database.
func severity(a advisory) (string, float64) {
	best := 0.0
	for _, s := range a.Severity {
		if sc := cvssScore(s.Score); sc > best {
			best = sc
		}
	}
	if l, sc := scan.SeverityLabel(strconv.FormatFloat(best, 'g', -1, 64)); l != "unknown" {
		return l, sc
	}
	switch l := strings.ToLower(strings.TrimSpace(a.DatabaseSpecific.Severity)); l {
	case "critical", "high", "medium", "low":
		return l, 0
	case "moderate":
		return "medium", 0
	}
	return "unknown", 0
}

// cvssScore returns the base score of a CVSS vector or a plain number; 0 when
// it cannot be read.
func cvssScore(s string) float64 {
	s = strings.TrimSpace(s)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	switch {
	case strings.HasPrefix(s, "CVSS:3.1/"):
		if v, err := gocvss31.ParseVector(s); err == nil {
			return v.BaseScore()
		}
	case strings.HasPrefix(s, "CVSS:3.0/"):
		if v, err := gocvss30.ParseVector(s); err == nil {
			return v.BaseScore()
		}
	case strings.HasPrefix(s, "CVSS:4.0/"):
		if v, err := gocvss40.ParseVector(s); err == nil {
			return v.Score()
		}
	case strings.HasPrefix(s, "CVSS:"):
	default:
		if v, err := gocvss20.ParseVector(s); err == nil {
			return v.BaseScore()
		}
	}
	return 0
}

type state struct {
	affected, uncertain bool
	fixed, reason       string
}

// isAffected says whether version falls in an ECOSYSTEM range (or in the
// explicit version list), with the fixed version closing the range. A version
// or bound that does not parse makes the answer affected and uncertain.
func isAffected(eco, version string, ranges []osvRange, versions []string) state {
	if slices.Contains(versions, version) {
		return state{affected: true}
	}
	v, err := semantic.Parse(version, eco)
	if err != nil {
		if hasRange(ranges) {
			return state{affected: true, uncertain: true, reason: "installed version does not parse"}
		}
		return state{}
	}
	cmp := func(other string) (int, bool) {
		w, err := semantic.Parse(other, eco)
		if err != nil {
			return 0, false
		}
		c, err := v.Compare(w)
		return c, err == nil
	}
	bad := state{affected: true, uncertain: true, reason: "range bound does not parse"}
	for _, r := range ranges {
		if r.Type != "ECOSYSTEM" {
			continue
		}
		started := false
		for _, e := range r.Events {
			switch {
			case e.Introduced != "":
				if e.Introduced == "0" {
					started = true
					continue
				}
				c, ok := cmp(e.Introduced)
				if !ok {
					return bad
				}
				started = c >= 0
			case e.Fixed != "":
				c, ok := cmp(e.Fixed)
				if !ok && started {
					return bad
				}
				if started && c < 0 {
					return state{affected: true, fixed: e.Fixed}
				}
				started = false
			case e.LastAffected != "":
				c, ok := cmp(e.LastAffected)
				if !ok && started {
					return bad
				}
				if started && c <= 0 {
					return state{affected: true}
				}
				started = false
			}
		}
		if started {
			return state{affected: true}
		}
	}
	return state{}
}

func hasRange(ranges []osvRange) bool {
	return slices.ContainsFunc(ranges, func(r osvRange) bool { return r.Type == "ECOSYSTEM" })
}

// Findings turns the hits of a result into server_package findings of a
// server: one per advisory and source package, the affected installed
// packages named in the summary.
func Findings(t target.Target, res Result) []scan.Finding {
	const key, eco = "os-packages", "os"
	out := make([]scan.Finding, 0, len(res.Hits))
	for _, h := range res.Hits {
		f := scan.Finding{
			ID:               scan.FindingID(t.ID, key, eco, h.Source, h.OSVID),
			ProjectID:        t.ID,
			ManifestRelPath:  key,
			Ecosystem:        eco,
			Package:          h.Source,
			OSVID:            h.OSVID,
			Aliases:          slices.Clone(h.Aliases),
			SeverityLabel:    h.Severity,
			CVSS:             h.CVSS,
			InstalledVersion: h.Package.Version,
			Summary:          h.Source + " " + h.Package.Version + " is affected by " + h.OSVID + " (installed: " + strings.Join(h.Binaries, ", ") + ")",
			Kind:             scan.KindServerPackage,
		}
		if h.Fixed != "" {
			f.FixedVersions = []string{h.Fixed}
			f.Summary += "; fixed in " + h.Fixed
		}
		if h.Uncertain {
			f.Summary += "; a version could not be compared"
		}
		out = append(out, f)
	}
	return out
}
