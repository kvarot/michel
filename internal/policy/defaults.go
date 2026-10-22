package policy

// Defaults returns the built-in strict_local policy. OSVPath is left empty;
// Load fills it from the data directory.
func Defaults() Policy {
	return Policy{
		Sovereignty: SovereigntyConfig{
			Mode:               ModeStrictLocal,
			DataClassification: ClassInternal,
			AI:                 AIConfig{ProviderPolicy: "local_only"},
			Network:            NetworkConfig{DefaultEgress: "deny"},
			Audit: AuditConfig{
				Enabled:                true,
				IntegrityProtection:    "hash_chain",
				PromptContentRetention: "none",
			},
			Remediation: RemediationConfig{
				IsolatedExecutionRequired:     true,
				HumanApprovalRequiredForMerge: true,
			},
		},
		Assistant: AssistantConfig{Name: "Michel"},
	}
}
