package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

var vulnrichmentBase = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"

type vulnrichment struct{}

// Vulnrichment reads CISA's Vulnrichment repository: CVSS and SSVC added to
// CVE records, one file per CVE.
func Vulnrichment() OnDemand { return vulnrichment{} }

func (vulnrichment) Key() string { return "enrich.vulnrichment" }

// vulnrichmentPath is /<year>/<block>/<CVE>.json, the block being the number
// divided by 1000 followed by "xxx" (CVE-2024-12345 is in 12xxx).
func vulnrichmentPath(cve string) string {
	parts := strings.Split(cve, "-")
	n, _ := strconv.ParseInt(parts[2], 10, 64)
	return fmt.Sprintf("/%s/%dxxx/%s.json", parts[1], n/1000, cve)
}

func (vulnrichment) Fetch(ctx context.Context, client *http.Client, cve string) (CVERecord, error) {
	cve, err := checkCVE(cve)
	if err != nil {
		return CVERecord{}, err
	}
	body, err := getJSON(ctx, client, vulnrichmentBase+vulnrichmentPath(cve), nil)
	if err != nil {
		return CVERecord{}, err
	}
	return parseCVE5(cve, body)
}

// cve5 is the part of a CVE JSON 5 record the readers use.
type cve5 struct {
	Containers struct {
		CNA cve5Container   `json:"cna"`
		ADP []cve5Container `json:"adp"`
	} `json:"containers"`
	CVSS json.Number `json:"cvss"` // CIRCL's older flat shape
}

type cve5Container struct {
	Metrics []struct {
		V31   *cve5CVSS `json:"cvssV3_1"`
		V40   *cve5CVSS `json:"cvssV4_0"`
		Other *struct {
			Type    string `json:"type"`
			Content struct {
				Options []map[string]string `json:"options"`
			} `json:"content"`
		} `json:"other"`
	} `json:"metrics"`
	ProblemTypes []struct {
		Descriptions []struct {
			CWEID string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
}

type cve5CVSS struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

// parseCVE5 reads a CVE JSON 5 record: the CVSS 3.1 score (else 4.0) of the
// first container giving one, the SSVC options and the CWE ids.
func parseCVE5(cve string, body []byte) (CVERecord, error) {
	var doc cve5
	if err := json.Unmarshal(body, &doc); err != nil {
		return CVERecord{}, fmt.Errorf("the answer is not a CVE record: %w", err)
	}
	rec := CVERecord{CVE: cve}
	boxes := append([]cve5Container{doc.Containers.CNA}, doc.Containers.ADP...)
	// Version 3.1 first, in any container, then 4.0.
	for _, want := range []string{"3.1", "4.0"} {
		for _, b := range boxes {
			for _, m := range b.Metrics {
				c := m.V31
				if want == "4.0" {
					c = m.V40
				}
				if c != nil && c.BaseScore > 0 && rec.CVSSScore == 0 {
					rec.CVSSScore, rec.CVSSVector = c.BaseScore, c.VectorString
				}
			}
		}
	}
	if rec.CVSSScore == 0 {
		if f, err := doc.CVSS.Float64(); err == nil {
			rec.CVSSScore = f
		}
	}
	for _, b := range boxes {
		for _, m := range b.Metrics {
			if m.Other == nil || !strings.EqualFold(m.Other.Type, "ssvc") {
				continue
			}
			for _, o := range m.Other.Content.Options {
				for k, v := range o {
					switch strings.ToLower(k) {
					case "exploitation":
						rec.SSVCExploitation = v
					case "automatable":
						rec.SSVCAutomatable = v
					case "technical impact":
						rec.SSVCTechnicalImpact = v
					}
				}
			}
		}
		for _, p := range b.ProblemTypes {
			for _, d := range p.Descriptions {
				if d.CWEID != "" {
					rec.CWE = append(rec.CWE, d.CWEID)
				}
			}
		}
	}
	return rec.clean(), nil
}
