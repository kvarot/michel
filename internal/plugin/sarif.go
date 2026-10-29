package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/kvarot/michel/internal/scan"
)

// Caps on the untrusted text of a report.
const (
	maxMessage  = 2000
	maxRuleID   = 200
	maxLocation = 500
)

type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	DefaultConfiguration struct{ Level string } `json:"defaultConfiguration"`
	Properties           map[string]any         `json:"properties"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Level     string `json:"level"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

// ParseSARIF reads a SARIF 2.1 report. The level gives the severity (error
// high, warning medium, note or none low; a result without level takes its
// rule's, else warning); a "security-severity" property (on the result or
// its rule) gives the CVSS score and the label from it. The location is made
// relative to projectRoot: a result whose file is outside it is left out.
// The fingerprint is partialFingerprints["primaryLocationLineHash"].
func ParseSARIF(r io.Reader, projectRoot string) ([]ExternalFinding, error) {
	var log sarifLog
	if err := json.NewDecoder(io.LimitReader(r, MaxReportSize)).Decode(&log); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadReport, err)
	}
	out := []ExternalFinding{}
	for _, run := range log.Runs {
		rules := map[string]sarifRule{}
		for _, rule := range run.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}
		for _, res := range run.Results {
			if len(out) >= MaxResults {
				return nil, ErrReportTooBig
			}
			rule, ok := rules[res.RuleID]
			if !ok && res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(run.Tool.Driver.Rules) {
				rule = run.Tool.Driver.Rules[*res.RuleIndex]
			}
			id := res.RuleID
			if id == "" {
				id = rule.ID
			}
			loc, ok := "", true
			if len(res.Locations) > 0 {
				pl := res.Locations[0].PhysicalLocation
				loc, ok = relLocation(projectRoot, pl.ArtifactLocation.URI)
				if ok && loc != "" && pl.Region.StartLine > 0 {
					loc += ":" + strconv.Itoa(pl.Region.StartLine)
				}
			}
			if !ok {
				continue
			}
			level := res.Level
			if level == "" {
				level = rule.DefaultConfiguration.Level
			}
			f := ExternalFinding{RuleID: clip(id, maxRuleID), Message: clip(res.Message.Text, maxMessage), Location: clip(loc, maxLocation),
				Fingerprint: clip(res.PartialFingerprints["primaryLocationLineHash"], maxRuleID), Severity: levelSeverity(level)}
			score, ok := securitySeverity(res.Properties)
			if !ok {
				score, ok = securitySeverity(rule.Properties)
			}
			if ok {
				f.Severity, f.CVSS = scan.SeverityLabel(strconv.FormatFloat(score, 'f', -1, 64))
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func levelSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "note", "none":
		return "low"
	default: // "warning", SARIF's default
		return "medium"
	}
}

// securitySeverity reads the "security-severity" property (a string or a
// number from 0.1 to 10).
func securitySeverity(props map[string]any) (float64, bool) {
	var s float64
	switch v := props["security-severity"].(type) {
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0, false
		}
		s = f
	case float64:
		s = v
	default:
		return 0, false
	}
	if s <= 0 || s > 10 {
		return 0, false
	}
	return s, true
}

// clip sanitizes untrusted text, flattens it to one line and caps it.
func clip(s string, max int) string {
	s = strings.Join(strings.Fields(scan.SanitizeText(s)), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

var drive = regexp.MustCompile(`^[A-Za-z]:/`)

// relLocation makes a report's file location (a relative path, an absolute
// path of either system, or a file: URI) a slash-separated path relative to
// root. ok is false for a path outside root. The comparison is lexical: the
// location is only shown, never opened. An empty location stays empty.
func relLocation(root, loc string) (rel string, ok bool) {
	if loc == "" {
		return "", true
	}
	if strings.HasPrefix(strings.ToLower(loc), "file:") {
		u, err := url.Parse(loc)
		if err != nil {
			return "", false
		}
		loc = u.Path
		if u.Host != "" && u.Host != "localhost" {
			loc = "//" + u.Host + loc
		}
		if len(loc) > 2 && loc[0] == '/' && drive.MatchString(loc[1:]) {
			loc = loc[1:]
		}
	} else if u, err := url.PathUnescape(loc); err == nil {
		loc = u
	}
	loc = strings.ReplaceAll(loc, `\`, "/")
	if isAbs(loc) {
		r := strings.TrimSuffix(path.Clean(strings.ReplaceAll(root, `\`, "/")), "/") + "/"
		loc = path.Clean(loc)
		windows := drive.MatchString(r) || strings.HasPrefix(r, "//")
		if root == "" || len(loc) < len(r) || !(loc[:len(r)] == r || windows && strings.EqualFold(loc[:len(r)], r)) {
			return "", false
		}
		loc = loc[len(r):]
	}
	loc = path.Clean(loc)
	if loc == "." || loc == ".." || strings.HasPrefix(loc, "../") || isAbs(loc) {
		return "", false
	}
	return loc, true
}

func isAbs(p string) bool { return strings.HasPrefix(p, "/") || drive.MatchString(p) }
