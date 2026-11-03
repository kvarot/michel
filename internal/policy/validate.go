package policy

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/kvarot/michel/internal/secret"
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
	case "auto", "en", "fr":
	default:
		return fmt.Errorf("assistant.lang %q is unknown (use \"auto\", \"en\" or \"fr\")", p.Assistant.Lang)
	}
	if err := ValidateRisk(p.Risk); err != nil {
		return err
	}
	if a := p.SSH.AgentPipe; len(a) > 512 || strings.IndexFunc(a, unicode.IsControl) >= 0 {
		return errors.New("ssh.agent_pipe must be a pipe or socket path of at most 512 characters, without control characters")
	}
	for i, r := range s.Network.Allow {
		if strings.TrimSpace(r.Host) == "" || strings.TrimSpace(r.Purpose) == "" {
			return fmt.Errorf("network.allow[%d] needs both a host and a purpose", i)
		}
		if err := checkHost(r.Host); err != nil {
			return fmt.Errorf("network.allow[%d]: %w", i, err)
		}
	}
	return ValidateNotify(p.Notify, s.Network.Allow)
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

// secretName is the pattern of a secret name (internal/secret).
var secretName = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// ValidateNotify checks the notify section: unique names, known types, the
// fields each type needs, and, for an enabled email or webhook channel, a
// network.allow rule for its host and purpose. A disabled channel is checked
// for shape only. Errors name the channel and say what to write.
func ValidateNotify(n NotifyConfig, rules []AllowRule) error {
	if n.SMSPerDay < 0 {
		return fmt.Errorf("notify.sms_per_day is %d: use 0 (default %d) or a positive number", n.SMSPerDay, DefaultSMSPerDay)
	}
	if n.DigestAt != "" && n.DigestAt != DigestOff {
		if _, _, ok := parseHourMinute(n.DigestAt); !ok {
			return fmt.Errorf("notify.digest_at %q must be a time of day as HH:MM (for example 08:00) or off", n.DigestAt)
		}
	}
	if n.PageURL != "" {
		u, err := url.Parse(n.PageURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("notify.page_url %q must be a plain http(s) link, without user, query or fragment (it never carries the access token)", n.PageURL)
		}
	}
	seen := map[string]bool{}
	for i, c := range n.Channels {
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("notify.channels[%d] needs a name", i)
		}
		if seen[c.Name] {
			return fmt.Errorf("notify channel name %q is used twice: give each channel its own name", c.Name)
		}
		seen[c.Name] = true
		for _, p := range c.Projects {
			if strings.TrimSpace(p) == "" {
				return fmt.Errorf("notify channel %q: projects lists an empty name", c.Name)
			}
		}
		host, purpose, err := ChannelTarget(c)
		if err != nil {
			return fmt.Errorf("notify channel %q: %w", c.Name, err)
		}
		if purpose != "" && c.IsEnabled() && !ruleAllows(rules, host, purpose) {
			return fmt.Errorf("notify channel %q needs a network rule: add under sovereignty.network.allow: {host: %s, purpose: %s}", c.Name, host, purpose)
		}
	}
	return nil
}

// ChannelTarget checks the fields of c for its type and returns the host it
// contacts and the egress purpose ("", "" for a toast).
func ChannelTarget(c ChannelConfig) (host, purpose string, err error) {
	switch c.Type {
	case ChannelEmail:
		return c.Host, PurposeEmail, checkEmail(c)
	case ChannelWebhook:
		h, err := checkWebhook(c)
		return h, PurposeWebhook, err
	case ChannelToast:
		return "", "", nil
	case ChannelSMS:
		h, err := checkSMS(c)
		return h, PurposeNotifySMS, err
	}
	return "", "", fmt.Errorf("type %q is unknown (use email, webhook, toast or sms)", c.Type)
}

// checkSMS returns the host an SMS channel contacts.
func checkSMS(c ChannelConfig) (string, error) {
	switch c.Provider {
	case SMSFreeMobile:
		if strings.TrimSpace(c.User) == "" {
			return "", errors.New("an sms channel with provider freemobile needs user (your Free Mobile login)")
		}
		if c.Secret == "" {
			return "", errors.New("secret is empty: name the secret holding the Free Mobile key (michel secret set <name>)")
		}
		w := c
		if w.URL == "" {
			w.URL = FreeMobileURL
		}
		w.Format = ""
		return checkWebhook(w)
	case SMSGeneric:
		if c.URL == "" {
			return "", errors.New("an sms channel with provider generic needs url")
		}
		w := c
		w.Format = ""
		return checkWebhook(w)
	}
	return "", fmt.Errorf("provider %q is unknown (use freemobile or generic)", c.Provider)
}

func checkEmail(c ChannelConfig) error {
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("an email channel needs a host (the SMTP server)")
	}
	if err := checkHost(c.Host); err != nil || strings.HasPrefix(c.Host, "*.") {
		return fmt.Errorf("host %q must be the bare name of the SMTP server, without scheme, port or wildcard", c.Host)
	}
	if c.Port != 587 && c.Port != 465 {
		return fmt.Errorf("port %d is not allowed: use 587 (STARTTLS) or 465 (implicit TLS); Michel never sends mail unencrypted", c.Port)
	}
	if !validAddress(c.From) {
		return fmt.Errorf("from %q is not a single email address", c.From)
	}
	if len(c.To) == 0 {
		return errors.New("to lists no recipient: add at least one email address")
	}
	for _, a := range c.To {
		if !validAddress(a) {
			return fmt.Errorf("to: %q is not a single email address", a)
		}
	}
	if c.Username != "" && c.PasswordSecret == "" {
		return errors.New("username is set but password_secret is empty: name the secret holding the password (michel secret set <name>)")
	}
	if c.PasswordSecret != "" && !secretName.MatchString(c.PasswordSecret) {
		return fmt.Errorf("password_secret %q is not a secret name: use 1 to 64 lowercase letters, digits or hyphens", c.PasswordSecret)
	}
	if c.PasswordSecret == secret.ReservedAPIToken {
		return fmt.Errorf("password_secret %q is reserved for the local page's token: store the password under another name (michel secret set <name>)", c.PasswordSecret)
	}
	return nil
}

// validAddress accepts one address, with or without a display name, and no
// line break (a line break would inject mail headers).
func validAddress(s string) bool {
	if strings.ContainsAny(s, "\r\n") {
		return false
	}
	_, err := mail.ParseAddress(s)
	return err == nil
}

// checkWebhook returns the host of the webhook url.
func checkWebhook(c ChannelConfig) (string, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("url %q is not a valid https link", c.URL)
	}
	host := u.Hostname()
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && IsLoopbackHost(host):
	default:
		return "", fmt.Errorf("url %q must start with https:// (plain http is only accepted on this machine: 127.0.0.1, ::1 or localhost)", c.URL)
	}
	switch c.Format {
	case "", FormatGeneric, FormatSlack, FormatDiscord:
	default:
		return "", fmt.Errorf("format %q is unknown (use generic, slack or discord)", c.Format)
	}
	if c.Secret == "" && !IsLoopbackHost(host) {
		return "", errors.New("secret is empty: name the secret holding the signing key (michel secret set <name>), so the receiver can check the message comes from Michel")
	}
	if c.Secret != "" && !secretName.MatchString(c.Secret) {
		return "", fmt.Errorf("secret %q is not a secret name: use 1 to 64 lowercase letters, digits or hyphens", c.Secret)
	}
	if c.Secret == secret.ReservedAPIToken {
		return "", fmt.Errorf("secret %q is reserved for the local page's token: store the signing key under another name (michel secret set <name>)", c.Secret)
	}
	return host, nil
}

// IsLoopbackHost reports whether host is localhost or a loopback address.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ruleAllows applies the gateway's matching: exact host, or "*.suffix".
func ruleAllows(rules []AllowRule, host, purpose string) bool {
	host = strings.ToLower(host)
	for _, r := range rules {
		if r.Purpose != purpose {
			continue
		}
		rh := strings.ToLower(r.Host)
		if suffix, ok := strings.CutPrefix(rh, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if rh == host {
			return true
		}
	}
	return false
}

// parseHourMinute reads HH:MM, two digits each, 00:00 to 23:59.
func parseHourMinute(s string) (hour, minute int, ok bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, false
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return 0, 0, false
		}
	}
	hour, minute = int(s[0]-'0')*10+int(s[1]-'0'), int(s[3]-'0')*10+int(s[4]-'0')
	return hour, minute, hour < 24 && minute < 60
}
