package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

var nvdBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVD request spacing: 5 requests per 30 s without a key, 50 with one.
const (
	nvdIntervalAnonymous = 6 * time.Second
	nvdIntervalWithKey   = 600 * time.Millisecond
)

type nvd struct{ apiKey string }

// NVD reads the NVD API 2.0. apiKey is optional; when set it travels in the
// apiKey header only and never appears in an error.
func NVD(apiKey string) OnDemand { return nvd{apiKey: apiKey} }

func (nvd) Key() string { return "enrich.nvd" }

// Interval is the pause RunOnDemand leaves between two requests.
func (n nvd) Interval() time.Duration {
	if n.apiKey != "" {
		return nvdIntervalWithKey
	}
	return nvdIntervalAnonymous
}

func (n nvd) Fetch(ctx context.Context, client *http.Client, cve string) (CVERecord, error) {
	cve, err := checkCVE(cve)
	if err != nil {
		return CVERecord{}, err
	}
	var h map[string]string
	if n.apiKey != "" {
		h = map[string]string{"apiKey": n.apiKey}
	}
	body, err := getJSON(ctx, client, nvdBase+"?cveId="+url.QueryEscape(cve), h)
	if err != nil {
		return CVERecord{}, err
	}
	return parseNVD(cve, body)
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// parseNVD reads an NVD 2.0 answer: the best CVSS metric (3.1, 4.0, 3.0
// then 2) and the CWE weaknesses.
func parseNVD(cve string, body []byte) (CVERecord, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVE struct {
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Metrics struct {
					V40 []nvdMetric `json:"cvssMetricV40"`
					V31 []nvdMetric `json:"cvssMetricV31"`
					V30 []nvdMetric `json:"cvssMetricV30"`
					V2  []nvdMetric `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return CVERecord{}, fmt.Errorf("the answer is not an NVD record: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return CVERecord{}, ErrNotFound
	}
	c := doc.Vulnerabilities[0].CVE
	rec := CVERecord{CVE: cve}
	for _, list := range [][]nvdMetric{c.Metrics.V31, c.Metrics.V40, c.Metrics.V30, c.Metrics.V2} {
		if len(list) > 0 && list[0].CVSSData.BaseScore > 0 {
			rec.CVSSScore, rec.CVSSVector = list[0].CVSSData.BaseScore, list[0].CVSSData.VectorString
			break
		}
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			rec.CWE = append(rec.CWE, d.Value)
		}
	}
	return rec.clean(), nil
}
