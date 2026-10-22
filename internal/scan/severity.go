// Package scan runs an offline osv-scanner scan of a project and keeps its
// findings with stable identities and status transitions.
package scan

import (
	"strconv"
	"strings"
)

// SeverityLabel maps osv-scanner's MaxSeverity (a CVSS score such as "7.5")
// to a label. An empty or unreadable value is "unknown" with score 0.
func SeverityLabel(maxSeverity string) (label string, score float64) {
	s, err := strconv.ParseFloat(strings.TrimSpace(maxSeverity), 64)
	if err != nil || s <= 0 {
		return "unknown", 0
	}
	switch {
	case s >= 9:
		return "critical", s
	case s >= 7:
		return "high", s
	case s >= 4:
		return "medium", s
	default:
		return "low", s
	}
}

// severityRank orders labels from the most to the least severe.
func severityRank(label string) int {
	switch label {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// labelFromAdvisory reads a textual label such as "HIGH" or "MODERATE".
func labelFromAdvisory(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}
