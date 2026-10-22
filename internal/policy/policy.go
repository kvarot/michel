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
}
