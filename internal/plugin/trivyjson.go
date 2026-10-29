package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type trivyReport struct {
	Results []struct {
		Target            string `json:"Target"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			AVDID         string `json:"AVDID"`
			Title         string `json:"Title"`
			Message       string `json:"Message"`
			Severity      string `json:"Severity"`
			Status        string `json:"Status"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseTrivyJSON reads Trivy's JSON report. Every failed misconfiguration
// is a finding (KindMisconfig); a vulnerability is one (KindVulnerability)
// unless its id is in knownCVEs (upper case): the OSV scan already reports
// it, and skippedKnown counts those. A target that is not a path relative to
// the project is left out.
func ParseTrivyJSON(r io.Reader, knownCVEs map[string]bool) (findings []ExternalFinding, skippedKnown int, err error) {
	var rep trivyReport
	if err := json.NewDecoder(io.LimitReader(r, MaxReportSize)).Decode(&rep); err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrBadReport, err)
	}
	findings = []ExternalFinding{}
	for _, res := range rep.Results {
		target, ok := relLocation("", res.Target)
		if !ok {
			continue
		}
		for _, m := range res.Misconfigurations {
			if !strings.EqualFold(m.Status, "FAIL") {
				continue
			}
			if len(findings) >= MaxResults {
				return nil, 0, ErrReportTooBig
			}
			id := m.ID
			if id == "" {
				id = m.AVDID
			}
			loc := target
			if m.CauseMetadata.StartLine > 0 && loc != "" {
				loc += ":" + strconv.Itoa(m.CauseMetadata.StartLine)
			}
			msg := m.Title
			if m.Message != "" {
				msg += ": " + m.Message
			}
			findings = append(findings, ExternalFinding{RuleID: clip(id, maxRuleID), Message: clip(msg, maxMessage),
				Location: clip(loc, maxLocation), Severity: trivySeverity(m.Severity), Kind: KindMisconfig})
		}
		for _, v := range res.Vulnerabilities {
			id := strings.ToUpper(strings.TrimSpace(v.VulnerabilityID))
			if knownCVEs[id] {
				skippedKnown++
				continue
			}
			if id == "" {
				continue
			}
			if len(findings) >= MaxResults {
				return nil, 0, ErrReportTooBig
			}
			f := ExternalFinding{RuleID: clip(id, maxRuleID), Location: clip(target, maxLocation), Severity: trivySeverity(v.Severity),
				Kind: KindVulnerability, Aliases: []string{clip(id, maxRuleID)},
				Message: clip(fmt.Sprintf("%s %s: %s", v.PkgName, v.InstalledVersion, v.Title), maxMessage)}
			for _, c := range v.CVSS {
				if c.V3Score > f.CVSS && c.V3Score <= 10 {
					f.CVSS = c.V3Score
				}
			}
			findings = append(findings, f)
		}
	}
	return findings, skippedKnown, nil
}

func trivySeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return "unknown"
}
