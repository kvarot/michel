// Package project is the registry of local projects Michel watches.
package project

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/policy"
)

// SourceLocalPath is the only project source supported in v1.
const SourceLocalPath = "local_path"

// Project is a folder on this machine that Michel scans.
type Project struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	SourceType     string                `json:"source_type"`
	Path           string                `json:"path"`
	Classification policy.Classification `json:"classification"`
	// FixLevel is how far Michel may go on the dependency files (0 to 3).
	FixLevel int `json:"fix_level"`
	// AutoFixMinor lets Michel start a fix alone for minor and patch updates
	// when FixLevel is 2.
	AutoFixMinor bool `json:"auto_fix_minor"`
	// GateThreshold is how strict the guards are for this project: soft,
	// normal (the default) or strict.
	GateThreshold Threshold `json:"gate_threshold"`
	TestCmd       string    `json:"test_cmd"`
	InstallCmd    string    `json:"install_cmd"`
	Active        bool      `json:"active"`
	// AutoScan lets the daily watch of michel serve check the project (true
	// on creation).
	AutoScan bool `json:"auto_scan"`
	// CorePackages are the packages whose upgrade is riskier for this project
	// (stored as typed; matching is done per ecosystem).
	CorePackages []string `json:"core_packages"`
	// RiskOverrides replaces risk-score values for this project; keys are the
	// policy.RiskKeys names.
	RiskOverrides map[string]int `json:"risk_overrides"`
	// Exclude lists folder names (not paths) that scans and analyses skip,
	// on top of the defaults; sorted and unique.
	Exclude []string `json:"exclude"`
	// Tech lists the technologies the user declares for this project
	// (nginx, postgresql...); TechAuto those Michel infers from the
	// manifests at each scan. Both sorted and unique.
	Tech      []string  `json:"tech"`
	TechAuto  []string  `json:"tech_auto"`
	CreatedAt time.Time `json:"created_at"`

	// FixLevelSet marks FixLevel as explicit, so that 0 (no automatic fix) is
	// not replaced by the default of 1. It is not stored.
	FixLevelSet bool `json:"-"`
}

// Threshold is how strict the guards of a project are.
type Threshold string

const (
	ThresholdSoft   Threshold = "soft"
	ThresholdNormal Threshold = "normal"
	ThresholdStrict Threshold = "strict"
)

// Valid reports whether t is one of the three thresholds.
func (t Threshold) Valid() bool {
	return t == ThresholdSoft || t == ThresholdNormal || t == ThresholdStrict
}

var (
	ErrInvalidThreshold      = errors.New("gate threshold must be soft, normal or strict")
	ErrNotADirectory         = errors.New("path is not an existing directory")
	ErrDuplicateName         = errors.New("a project with this name already exists")
	ErrEmptyName             = errors.New("project name is empty")
	ErrInvalidFixLevel       = errors.New("fix level must be between 0 and 3")
	ErrInvalidClassification = errors.New("unknown classification")
	ErrInvalidSourceType     = errors.New("unsupported source type")
	ErrNotFound              = errors.New("project not found")
	ErrInvalidRiskOverride   = errors.New("invalid risk override")
	ErrInvalidExclude        = errors.New("invalid excluded folder")
	ErrInvalidTech           = errors.New("invalid technology tag")
)

// techTag is the shape of a technology tag: lowercase letters, digits and
// . + -, 1 to 32 characters, starting with a letter or a digit.
var techTag = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,31}$`)

// ValidTech reports whether tag is a valid technology tag.
func ValidTech(tag string) bool { return techTag.MatchString(tag) }

// NormalizeTech checks every tag and returns them sorted and unique, never nil.
func NormalizeTech(tags []string) ([]string, error) {
	for _, t := range tags {
		if !ValidTech(t) {
			return nil, fmt.Errorf("%w %q: use lowercase letters, digits, dots, plus or hyphens, 32 characters at most (for example nginx or postgresql)", ErrInvalidTech, t)
		}
	}
	out := append([]string{}, tags...)
	slices.Sort(out)
	return slices.Compact(out), nil
}

// normalizeExtras validates RiskOverrides, Exclude and the technology tags,
// makes the extras non-nil, and sorts and deduplicates the lists.
func normalizeExtras(p *Project) error {
	if p.CorePackages == nil {
		p.CorePackages = []string{}
	}
	if p.RiskOverrides == nil {
		p.RiskOverrides = map[string]int{}
	}
	for _, name := range p.Exclude {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			return fmt.Errorf("%w %q: give a folder name such as build or dist, not a path", ErrInvalidExclude, name)
		}
	}
	p.Exclude = append([]string{}, p.Exclude...) // never nil, and never the caller's array
	slices.Sort(p.Exclude)
	p.Exclude = slices.Compact(p.Exclude)
	for k, v := range p.RiskOverrides {
		known := false
		for _, rk := range policy.RiskKeys {
			if rk == k {
				known = true
			}
		}
		if !known {
			return fmt.Errorf("%w: unknown key %q (use one of %s)", ErrInvalidRiskOverride, k, strings.Join(policy.RiskKeys, ", "))
		}
		if v < 0 || v > 100 || (k == "many_call_sites_threshold" && v < 1) {
			return fmt.Errorf("%w: %s=%d must be between 0 and 100", ErrInvalidRiskOverride, k, v)
		}
	}
	tech, err := NormalizeTech(p.Tech)
	if err != nil {
		return err
	}
	auto, err := NormalizeTech(p.TechAuto)
	if err != nil {
		return err
	}
	p.Tech, p.TechAuto = tech, auto
	return nil
}
