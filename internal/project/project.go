// Package project is the registry of local projects Michel watches.
package project

import (
	"errors"
	"fmt"
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
	FixLevel       int                   `json:"fix_level"`
	TestCmd        string                `json:"test_cmd"`
	InstallCmd     string                `json:"install_cmd"`
	Active         bool                  `json:"active"`
	// CorePackages are the packages whose upgrade is riskier for this project
	// (lowercased for Composer, as-is for npm).
	CorePackages []string `json:"core_packages"`
	// RiskOverrides replaces risk-score values for this project; keys are the
	// policy.RiskKeys names.
	RiskOverrides map[string]int `json:"risk_overrides"`
	CreatedAt     time.Time      `json:"created_at"`

	// FixLevelSet marks FixLevel as explicit, so that 0 (no automatic fix) is
	// not replaced by the default of 1. It is not stored.
	FixLevelSet bool `json:"-"`
}

var (
	ErrNotADirectory         = errors.New("path is not an existing directory")
	ErrDuplicateName         = errors.New("a project with this name already exists")
	ErrEmptyName             = errors.New("project name is empty")
	ErrInvalidFixLevel       = errors.New("fix level must be between 0 and 3")
	ErrInvalidClassification = errors.New("unknown classification")
	ErrInvalidSourceType     = errors.New("unsupported source type")
	ErrNotFound              = errors.New("project not found")
	ErrInvalidRiskOverride   = errors.New("invalid risk override")
)

// normalizeExtras validates RiskOverrides and makes both extras non-nil.
func normalizeExtras(p *Project) error {
	if p.CorePackages == nil {
		p.CorePackages = []string{}
	}
	if p.RiskOverrides == nil {
		p.RiskOverrides = map[string]int{}
	}
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
	return nil
}
