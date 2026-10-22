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
	// Lang is the language of generated text: "en" or "fr".
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
