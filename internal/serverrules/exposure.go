package serverrules

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/target"
)

// Verdicts on a service that listens.
const (
	VerdictNormal  = "normal"
	VerdictClose   = "close"
	VerdictUnknown = "unknown"
)

// Services that listen, as the rules name them.
const (
	ServiceWeb      = "web"
	ServiceAdmin    = "admin"
	ServiceDatabase = "database"
	ServiceCache    = "cache"
	ServiceOther    = "other"
)

// ExposurePrefix starts the manifest key of every exposure finding, followed
// by the port.
const ExposurePrefix = "exposure:"

const ecoExposure = "server-exposure"

// ListenRule says what the services on some ports are. A rule with the verdict
// close opens a finding (Rule, Severity, Key) when the service listens on all
// addresses. Key is the i18n prefix of its title and explanation.
type ListenRule struct {
	Ports    []int  `yaml:"ports"`
	Service  string `yaml:"service"`
	Verdict  string `yaml:"verdict"`
	Rule     string `yaml:"rule"`
	Severity string `yaml:"severity"`
	Key      string `yaml:"key"`
}

// Judgement is what Michel makes of one port, by its number alone: nothing was
// asked of the service, and a firewall may stand in front of it.
type Judgement struct {
	Service, Verdict string
}

// JudgeListener judges the port of l on server t. The port Michel connects to
// is the administration one, whatever its number and the rules (R10); a port
// no rule names is not recognized.
func JudgeListener(s Set, t target.Target, l target.Listener) Judgement {
	if r, ok := listenRule(s, t, l.Port); ok {
		return Judgement{Service: r.Service, Verdict: r.Verdict}
	}
	return Judgement{Service: ServiceOther, Verdict: VerdictUnknown}
}

func listenRule(s Set, t target.Target, port int) (ListenRule, bool) {
	if port == t.Port {
		return ListenRule{Service: ServiceAdmin, Verdict: VerdictNormal}, true
	}
	for _, r := range s.Listen {
		if slices.Contains(r.Ports, port) {
			return r, true
		}
	}
	return ListenRule{}, false
}

// ListenersKnown tells that inv says what listens: a complete read, with at
// least one row. Michel has just come in through a service that listens, so a
// list with none means ss looked elsewhere or could not look.
func ListenersKnown(inv target.Inventory) bool {
	return inv.ListenersRead && len(inv.Listeners) > 0
}

// openPorts lists, in order, the ports that listen on all addresses in inv,
// each once however many addresses it has. It says nothing of a list that is
// not known.
func openPorts(inv target.Inventory) []int {
	if !ListenersKnown(inv) {
		return nil
	}
	var out []int
	for _, l := range inv.Listeners {
		if l.Scope == target.ScopeOpen && !slices.Contains(out, l.Port) {
			out = append(out, l.Port)
		}
	}
	slices.Sort(out)
	return out
}

// OpenPortKeys gives the manifest keys of the ports inv shows open: a finding
// under one of them cannot be closed by this read, even when it would not be
// opened today (R8, R10).
func OpenPortKeys(inv target.Inventory) []string {
	var out []string
	for _, p := range openPorts(inv) {
		out = append(out, ExposurePrefix+strconv.Itoa(p))
	}
	return out
}

// exposureFindings turns what listens on all addresses into findings, one per
// port. On a shared server the services may be the host's or another client's,
// so no finding comes out of them (R8).
func exposureFindings(t target.Target, inv target.Inventory, s Set) []scan.Finding {
	if t.Kind == target.KindShared {
		return nil
	}
	var out []scan.Finding
	for _, port := range openPorts(inv) {
		r, ok := listenRule(s, t, port)
		if !ok || r.Verdict != VerdictClose {
			continue
		}
		p := strconv.Itoa(port)
		manifest := ExposurePrefix + p
		out = append(out, scan.Finding{
			ID:              scan.FindingID(t.ID, manifest, ecoExposure, p, r.Rule),
			ProjectID:       t.ID,
			ManifestRelPath: manifest,
			Ecosystem:       ecoExposure,
			Package:         p,
			OSVID:           r.Rule,
			SeverityLabel:   r.Severity,
			Summary:         "seen from inside the server: a " + r.Service + " service listens on all addresses, a firewall may still block it",
			Kind:            scan.KindServerExposure,
		})
	}
	return out
}

// checkListen validates the listen section. taken holds the ids of the other
// rules: a rule id names one rule, for its title. A service to close never
// goes above medium: Michel does not know it can be reached, so no alert (R9).
func checkListen(rules []ListenRule, taken map[string]bool) error {
	ports := map[int]bool{}
	for _, r := range rules {
		if len(r.Ports) == 0 {
			return fmt.Errorf("a listen rule of service %q has no port", r.Service)
		}
		for _, p := range r.Ports {
			if p < 1 || p > 65535 || ports[p] {
				return fmt.Errorf("listen rule of service %q: port %d is out of range or named twice", r.Service, p)
			}
			ports[p] = true
		}
		if !slices.Contains([]string{ServiceWeb, ServiceAdmin, ServiceDatabase, ServiceCache, ServiceOther}, r.Service) {
			return fmt.Errorf("a listen rule has an unknown service %q", r.Service)
		}
		switch r.Verdict {
		case VerdictClose:
			if r.Rule == "" || r.Key == "" || r.Severity != "medium" || taken[r.Rule] {
				return fmt.Errorf("listen rule %q needs a free id, a key and the severity medium", r.Rule)
			}
			taken[r.Rule] = true
		case VerdictNormal, VerdictUnknown:
			if r.Rule != "" || r.Severity != "" || r.Key != "" {
				return fmt.Errorf("a listen rule of service %q opens no finding: it has no id, severity or key", r.Service)
			}
		default:
			return fmt.Errorf("a listen rule has an unknown verdict %q", r.Verdict)
		}
	}
	return nil
}
