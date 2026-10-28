package enrich

import (
	"context"
	"net/http"
)

var circlBase = "https://vulnerability.circl.lu/api/vulnerability"

type circl struct{}

// CIRCL reads the Vulnerability-Lookup service of CIRCL.lu, a European
// alternative to NVD and Vulnrichment.
func CIRCL() OnDemand { return circl{} }

func (circl) Key() string { return "enrich.circl" }

func (circl) Fetch(ctx context.Context, client *http.Client, cve string) (CVERecord, error) {
	cve, err := checkCVE(cve)
	if err != nil {
		return CVERecord{}, err
	}
	body, err := getJSON(ctx, client, circlBase+"/"+cve, nil)
	if err != nil {
		return CVERecord{}, err
	}
	return parseCVE5(cve, body)
}
