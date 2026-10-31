// Package policy loads and validates the sovereignty policy that governs
// what Michel may do with data, networks and AI.
package policy

// Mode is the sovereignty mode.
type Mode string

const (
	ModeStrictLocal Mode = "strict_local"
	ModeStandard    Mode = "standard"
)

// Classification is the sensitivity level of the data Michel handles.
type Classification string

const (
	ClassPublic       Classification = "public"
	ClassInternal     Classification = "internal"
	ClassConfidential Classification = "confidential"
	ClassSensitive    Classification = "sensitive"
	ClassHealth       Classification = "health"
)

// Source tells where a loaded policy comes from.
type Source string

const (
	SourceFile     Source = "file"
	SourceDefaults Source = "defaults"
)

// Policy is the full policy document.
type Policy struct {
	Sovereignty SovereigntyConfig `yaml:"sovereignty"`
	DB          DBConfig          `yaml:"db"`
	Assistant   AssistantConfig   `yaml:"assistant"`
	Risk        RiskConfig        `yaml:"risk"`
	Notify      NotifyConfig      `yaml:"notify"`
}

// SovereigntyConfig groups the sovereignty rules.
type SovereigntyConfig struct {
	Mode               Mode              `yaml:"mode"`
	DataClassification Classification    `yaml:"data_classification"`
	AI                 AIConfig          `yaml:"ai"`
	Network            NetworkConfig     `yaml:"network"`
	Audit              AuditConfig       `yaml:"audit"`
	Remediation        RemediationConfig `yaml:"remediation"`
}

// AIConfig controls AI providers and models.
type AIConfig struct {
	ProviderPolicy           string `yaml:"provider_policy"`
	ExternalProvidersEnabled bool   `yaml:"external_providers_enabled"`
	ModelDownloadsEnabled    bool   `yaml:"model_downloads_enabled"`
	AutomaticModelUpdates    bool   `yaml:"automatic_model_updates"`
}

// NetworkConfig controls outbound traffic.
type NetworkConfig struct {
	DefaultEgress        string      `yaml:"default_egress"`
	TelemetryEnabled     bool        `yaml:"telemetry_enabled"`
	RemoteErrorReporting bool        `yaml:"remote_error_reporting"`
	Allow                []AllowRule `yaml:"allow"`
}

// AllowRule allows outbound traffic to one host for one stated purpose.
// Host is exact, or "*.suffix".
type AllowRule struct {
	Host    string `yaml:"host"`
	Purpose string `yaml:"purpose"`
}

// AuditConfig controls the audit trail.
type AuditConfig struct {
	Enabled                bool   `yaml:"enabled"`
	IntegrityProtection    string `yaml:"integrity_protection"`
	PromptContentRetention string `yaml:"prompt_content_retention"`
}

// RemediationConfig controls automated fixes.
type RemediationConfig struct {
	IsolatedExecutionRequired     bool `yaml:"isolated_execution_required"`
	ProductionDeploymentAllowed   bool `yaml:"production_deployment_allowed"`
	HumanApprovalRequiredForMerge bool `yaml:"human_approval_required_for_merge"`
}

// DBConfig controls the local vulnerability database.
type DBConfig struct {
	AutoUpdate bool   `yaml:"auto_update"`
	OSVPath    string `yaml:"osv_path"`
}

// AssistantConfig controls the assistant persona.
type AssistantConfig struct {
	Name string `yaml:"name"`
	// Lang is the language of generated text: "en", "fr" or "auto" (the
	// system's language, English if it is not French).
	Lang string `yaml:"lang"`
}

// RiskConfig holds the public risk-score rule: the points each term adds,
// and the thresholds that turn a score into a recommendation. The AI model
// never changes these values.
type RiskConfig struct {
	MajorJump              int `yaml:"major_jump"`
	Breaking               int `yaml:"breaking"`
	Direct                 int `yaml:"direct"`
	ManyCallSites          int `yaml:"many_call_sites"`
	NoTests                int `yaml:"no_tests"`
	CorePackage            int `yaml:"core_package"`
	ManyCallSitesThreshold int `yaml:"many_call_sites_threshold"`
	// AutoFixBelow: a score strictly below it is auto_fix.
	AutoFixBelow int `yaml:"auto_fix_below"`
	// HandoffUpTo: a score up to it (inclusive) is a plain handoff; above it
	// the handoff carries a warning.
	HandoffUpTo int `yaml:"handoff_up_to"`
}

// RiskKeys lists the field names (snake_case) a per-project override may set.
var RiskKeys = []string{
	"major_jump", "breaking", "direct", "many_call_sites", "no_tests", "core_package",
	"many_call_sites_threshold", "auto_fix_below", "handoff_up_to",
}

// WithOverrides returns r with the known keys of m applied; unknown keys are
// ignored (project.Repo rejects them earlier).
func (r RiskConfig) WithOverrides(m map[string]int) RiskConfig {
	for k, v := range m {
		switch k {
		case "major_jump":
			r.MajorJump = v
		case "breaking":
			r.Breaking = v
		case "direct":
			r.Direct = v
		case "many_call_sites":
			r.ManyCallSites = v
		case "no_tests":
			r.NoTests = v
		case "core_package":
			r.CorePackage = v
		case "many_call_sites_threshold":
			r.ManyCallSitesThreshold = v
		case "auto_fix_below":
			r.AutoFixBelow = v
		case "handoff_up_to":
			r.HandoffUpTo = v
		}
	}
	return r
}

// Purposes of the notification channels in network.allow rules.
const (
	PurposeEmail   = "notify.email"
	PurposeWebhook = "notify.webhook"
)

// Purposes of the sources registry in network.allow rules. A plugin's
// purpose is "plugin.<key>" and is never allowed.
const (
	PurposeOSV      = "osv.db"
	PurposeEnrich   = "source.enrich"
	PurposeFeed     = "source.feed"
	PurposeRepo     = "source.repo"
	PurposeDiscover = "source.discover"
)

// Purposes of the fix agent in network.allow rules: the package registries
// the work copy installs from, and the AI provider the agent talks to.
const (
	PurposeFixInstall  = "fix.install"
	PurposeAgentClaude = "agent.claude"
)

// Purposes of the servers checked over SSH: the SSH session itself, the GET
// of the site, and the SMS gateway for urgent alerts.
const (
	PurposeTargetSSH  = "target.ssh"
	PurposeTargetHTTP = "target.http"
	PurposeNotifySMS  = "notify.sms"
)

// Channel types.
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
	ChannelToast   = "toast"
	ChannelSMS     = "sms"
)

// SMS providers.
const (
	// SMSFreeMobile is Free Mobile's "notification by SMS" API (GET).
	SMSFreeMobile = "freemobile"
	// SMSGeneric POSTs {"text"} as JSON, signed like a webhook.
	SMSGeneric = "generic"
)

// FreeMobileURL is the endpoint of the Free Mobile SMS API.
const FreeMobileURL = "https://smsapi.free-mobile.fr/sendmsg"

// DefaultSMSPerDay is the most SMS Michel sends in a day.
const DefaultSMSPerDay = 3

// Webhook body formats.
const (
	FormatGeneric = "generic"
	FormatSlack   = "slack"
	FormatDiscord = "discord"
)

// DefaultPageURL is the link to the "Today" page put in the digests.
const DefaultPageURL = "http://127.0.0.1:7331/"

// NotifyConfig lists where the digest is sent.
type NotifyConfig struct {
	// PageURL is the link put in the digests; it never carries the access
	// token.
	PageURL  string          `yaml:"page_url"`
	Channels []ChannelConfig `yaml:"channels"`
	// SMSPerDay caps the SMS sent in a day, all channels together; 0 means
	// DefaultSMSPerDay.
	SMSPerDay int `yaml:"sms_per_day"`
}

// EffectiveSMSPerDay is the daily SMS cap, with the default applied.
func (n NotifyConfig) EffectiveSMSPerDay() int {
	if n.SMSPerDay <= 0 {
		return DefaultSMSPerDay
	}
	return n.SMSPerDay
}

// ChannelConfig is one notification channel. Secrets are referred to by
// their name in the secret store, never by value.
type ChannelConfig struct {
	Name string `yaml:"name"`
	// Type is email, webhook, toast or sms.
	Type string `yaml:"type"`
	// Enabled nil means true.
	Enabled *bool `yaml:"enabled"`
	// Projects restricts the channel to these project names; empty = all.
	Projects []string `yaml:"projects"`

	// Email.
	Host           string   `yaml:"host"`
	Port           int      `yaml:"port"`
	From           string   `yaml:"from"`
	To             []string `yaml:"to"`
	Username       string   `yaml:"username"`
	PasswordSecret string   `yaml:"password_secret"`

	// Webhook.
	URL string `yaml:"url"`
	// Format is generic, slack or discord ("" = generic).
	Format string `yaml:"format"`
	// Secret names the secret holding the HMAC key.
	Secret string `yaml:"secret"`

	// SMS. Provider is freemobile or generic. For freemobile, User is the
	// account login and Secret names the secret holding the API key; URL is
	// optional (it replaces Free Mobile's address, for tests). For generic,
	// URL and Secret work as for a webhook. Urgent must be true for the
	// channel to send anything: an SMS only goes out for an urgent alert.
	Provider string `yaml:"provider"`
	User     string `yaml:"user"`
	Urgent   bool   `yaml:"urgent"`
}

// IsEnabled reports whether the channel is enabled (Enabled nil = true).
func (c ChannelConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }
