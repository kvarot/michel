package policy

import (
	"errors"
	"fmt"
	"strings"
)

// Validate checks that a policy is consistent. It returns the first problem found.
func Validate(p Policy) error {
	s := p.Sovereignty
	switch s.Mode {
	case ModeStrictLocal, ModeStandard:
	default:
		return fmt.Errorf("sovereignty.mode %q is unknown (use %q or %q)", s.Mode, ModeStrictLocal, ModeStandard)
	}
	if s.Mode == ModeStrictLocal {
		forbidden := []struct {
			key string
			on  bool
		}{
			{"ai.external_providers_enabled", s.AI.ExternalProvidersEnabled},
			{"ai.model_downloads_enabled", s.AI.ModelDownloadsEnabled},
			{"ai.automatic_model_updates", s.AI.AutomaticModelUpdates},
			{"network.telemetry_enabled", s.Network.TelemetryEnabled},
			{"network.remote_error_reporting", s.Network.RemoteErrorReporting},
		}
		for _, f := range forbidden {
			if f.on {
				return fmt.Errorf("strict_local forbids %s", f.key)
			}
		}
		if s.Network.DefaultEgress != "deny" {
			return errors.New("strict_local requires network.default_egress to be \"deny\"")
		}
	}
	if s.Remediation.ProductionDeploymentAllowed {
		return errors.New("remediation.production_deployment_allowed must be false: Michel never deploys to production")
	}
	switch p.Assistant.Lang {
	case "en", "fr":
	default:
		return fmt.Errorf("assistant.lang %q is unknown (use \"en\" or \"fr\")", p.Assistant.Lang)
	}
	if err := ValidateRisk(p.Risk); err != nil {
		return err
	}
	for i, r := range s.Network.Allow {
		if strings.TrimSpace(r.Host) == "" || strings.TrimSpace(r.Purpose) == "" {
			return fmt.Errorf("network.allow[%d] needs both a host and a purpose", i)
		}
		if err := checkHost(r.Host); err != nil {
			return fmt.Errorf("network.allow[%d]: %w", i, err)
		}
	}
	return nil
}

// checkHost accepts a bare host name, optionally with a "*." prefix.
func checkHost(h string) error {
	if strings.ContainsAny(h, "/:?#@ ") {
		return fmt.Errorf("host %q must be a bare host name, without scheme, path or port", h)
	}
	name := strings.TrimPrefix(h, "*.")
	if name == "" || strings.Contains(name, "*") {
		return fmt.Errorf("host %q is invalid: use an exact host or \"*.suffix\"", h)
	}
	return nil
}

// ValidateRisk checks term ranges, the call-site threshold and the
// auto_fix_below < handoff_up_to invariant.
func ValidateRisk(r RiskConfig) error {
	for _, t := range []struct {
		key string
		v   int
	}{
		{"major_jump", r.MajorJump}, {"breaking", r.Breaking}, {"direct", r.Direct},
		{"many_call_sites", r.ManyCallSites}, {"no_tests", r.NoTests}, {"core_package", r.CorePackage},
	} {
		if t.v < 0 || t.v > 100 {
			return fmt.Errorf("risk.%s is %d: use a value between 0 and 100", t.key, t.v)
		}
	}
	if r.ManyCallSitesThreshold < 1 {
		return fmt.Errorf("risk.many_call_sites_threshold is %d: use 1 or more", r.ManyCallSitesThreshold)
	}
	if r.AutoFixBelow < 0 || r.AutoFixBelow >= r.HandoffUpTo {
		return fmt.Errorf("risk.auto_fix_below is %d: use a value from 0 up to (not including) risk.handoff_up_to (%d)", r.AutoFixBelow, r.HandoffUpTo)
	}
	if r.HandoffUpTo > 100 {
		return fmt.Errorf("risk.handoff_up_to is %d: use at most 100", r.HandoffUpTo)
	}
	return nil
}
