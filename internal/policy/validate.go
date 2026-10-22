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
