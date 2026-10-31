package vulnmatch

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/semantic"

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

// Hit is one installed package affected by one distribution advisory.
// Aliases carry the CVE ids so callers can reconcile with other findings.
type Hit struct {
	Package  target.Package
	OSVID    string
	Aliases  []string
	Severity string
	CVSS     float64
	Fixed    string
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

// Match reads the ecosystem's archive under osvRoot and returns the packages
// it affects. Advisories name source packages, so a package's Source is used
// when it has one. A missing archive is ErrSourceDisabled. A version the
// ecosystem cannot parse is never reported.
func Match(ctx context.Context, osvRoot, eco string, pkgs []target.Package) ([]Hit, error) {
	zr, err := zip.OpenReader(osvdb.ZipPath(osvRoot, base(eco)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrSourceDisabled{Key: CatalogKey(eco)}
		}
		return nil, err
	}
	defer zr.Close()

	byName := map[string][]int{}
	for i, p := range pkgs {
		n := p.Source
		if n == "" {
			n = p.Name
		}
		byName[n] = append(byName[n], i)
	}

	var hits []Hit
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		adv, err := readAdvisory(f)
		if err != nil {
			return nil, fmt.Errorf("advisory %s: %w", f.Name, err)
		}
		if adv.Withdrawn != "" {
			continue
		}
		for _, a := range adv.Affected {
			if a.Package.Ecosystem != eco {
				continue
			}
			for _, i := range byName[a.Package.Name] {
				p := pkgs[i]
				affected, fixed := isAffected(eco, p.Version, a.Ranges, a.Versions)
				if !affected {
					continue
				}
				label, score := severity(adv)
				hits = append(hits, Hit{Package: p, OSVID: adv.ID, Aliases: slices.Clone(adv.Aliases), Severity: label, CVSS: score, Fixed: fixed})
			}
		}
	}
	slices.SortFunc(hits, func(a, b Hit) int {
		if c := strings.Compare(a.Package.Name, b.Package.Name); c != 0 {
			return c
		}
		return strings.Compare(a.OSVID, b.OSVID)
	})
	return slices.CompactFunc(hits, func(a, b Hit) bool {
		return a.Package == b.Package && a.OSVID == b.OSVID
	}), nil
}

func readAdvisory(f *zip.File) (advisory, error) {
	var adv advisory
	rc, err := f.Open()
	if err != nil {
		return adv, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxAdvisory))
	if err != nil {
		return adv, err
	}
	return adv, json.Unmarshal(data, &adv)
}

// severity reads a numeric CVSS score or a severity label; a CVSS vector
// alone gives "unknown" (no score is computed from it).
func severity(a advisory) (string, float64) {
	for _, s := range a.Severity {
		if _, err := strconv.ParseFloat(strings.TrimSpace(s.Score), 64); err != nil {
			continue
		}
		if l, sc := scan.SeverityLabel(s.Score); l != "unknown" {
			return l, sc
		}
	}
	switch l := strings.ToLower(strings.TrimSpace(a.DatabaseSpecific.Severity)); l {
	case "critical", "high", "medium", "low":
		return l, 0
	case "moderate":
		return "medium", 0
	}
	return "unknown", 0
}

// isAffected says whether version falls in an ECOSYSTEM range (or in the
// explicit version list), and gives the fixed version closing the range.
func isAffected(eco, version string, ranges []osvRange, versions []string) (bool, string) {
	if slices.Contains(versions, version) {
		return true, ""
	}
	v, err := semantic.Parse(version, eco)
	if err != nil {
		return false, ""
	}
	cmp := func(other string) (int, bool) {
		w, err := semantic.Parse(other, eco)
		if err != nil {
			return 0, false
		}
		c, err := v.Compare(w)
		return c, err == nil
	}
	for _, r := range ranges {
		if r.Type != "ECOSYSTEM" {
			continue
		}
		started := false
		for _, e := range r.Events {
			switch {
			case e.Introduced != "":
				c, ok := cmp(e.Introduced)
				started = e.Introduced == "0" || (ok && c >= 0)
			case e.Fixed != "":
				if c, ok := cmp(e.Fixed); started && ok && c < 0 {
					return true, e.Fixed
				}
				started = false
			case e.LastAffected != "":
				if c, ok := cmp(e.LastAffected); started && ok && c <= 0 {
					return true, ""
				}
				started = false
			}
		}
		if started {
			return true, ""
		}
	}
	return false, ""
}

// Findings turns hits into server_package findings of a server.
func Findings(t target.Target, hits []Hit) []scan.Finding {
	const key, eco = "os-packages", "os"
	out := make([]scan.Finding, 0, len(hits))
	for _, h := range hits {
		f := scan.Finding{
			ID:               scan.FindingID(t.ID, key, eco, h.Package.Name, h.OSVID),
			ProjectID:        t.ID,
			ManifestRelPath:  key,
			Ecosystem:        eco,
			Package:          h.Package.Name,
			OSVID:            h.OSVID,
			Aliases:          slices.Clone(h.Aliases),
			SeverityLabel:    h.Severity,
			CVSS:             h.CVSS,
			InstalledVersion: h.Package.Version,
			Summary:          h.Package.Name + " " + h.Package.Version + " is affected by " + h.OSVID,
			Kind:             scan.KindServerPackage,
		}
		if h.Fixed != "" {
			f.FixedVersions = []string{h.Fixed}
			f.Summary += "; fixed in " + h.Fixed
		}
		out = append(out, f)
	}
	return out
}
