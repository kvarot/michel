package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kvarot/michel/internal/scan"
)

// maxField caps every text field read from a source, in characters.
const maxField = 300

// cleanField strips control characters, trims and caps one text field.
func cleanField(s string) string {
	s = strings.TrimSpace(scan.SanitizeText(s))
	if utf8.RuneCountInString(s) > maxField {
		s = string([]rune(s)[:maxField])
	}
	return s
}

// cleanDay keeps a YYYY-MM-DD day, "" for anything else.
func cleanDay(s string) string {
	s = strings.TrimSpace(s)
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return ""
	}
	return s
}

// firstURL is the first http(s) link of a KEV "notes" field, which lists
// links separated by " ; ".
func firstURL(notes string) string {
	for _, part := range strings.Split(notes, ";") {
		u := cleanField(part)
		if (strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) && !strings.ContainsAny(u, " \t") {
			return u
		}
	}
	return ""
}

// fetch GETs url with If-None-Match etag and returns the body read up to
// limit bytes. A 304 is ErrNotModified; a body (or Content-Length) over
// limit is an error.
func fetch(ctx context.Context, client *http.Client, url, etag string, limit int64) ([]byte, string, error) {
	if client == nil {
		return nil, "", errors.New("no HTTP client: build it with the egress gateway")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, etag, ErrNotModified
	case resp.StatusCode != http.StatusOK:
		return nil, "", fmt.Errorf("the server answered %s", resp.Status)
	case resp.ContentLength > limit:
		return nil, "", fmt.Errorf("the answer is %d bytes, more than the %d bytes Michel accepts", resp.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > limit {
		return nil, "", fmt.Errorf("the answer is more than the %d bytes Michel accepts", limit)
	}
	return body, cleanField(resp.Header.Get("ETag")), nil
}

// kevRow is one row of the kev table.
type kevRow struct {
	cve, vendor, product, name, added, due, ransomware, notesURL string
}

// parseKEV reads CISA's KEV JSON. Entries without a valid CVE id are left
// out; a list without any valid entry is refused (it would empty the table).
func parseKEV(body []byte) ([]kevRow, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			DateAdded         string `json:"dateAdded"`
			DueDate           string `json:"dueDate"`
			Ransomware        string `json:"knownRansomwareCampaignUse"`
			Notes             string `json:"notes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the KEV list is not valid JSON: %w", err)
	}
	out := []kevRow{}
	for _, v := range doc.Vulnerabilities {
		if !scan.IsCVE(v.CVEID) {
			continue
		}
		out = append(out, kevRow{
			cve: strings.ToUpper(strings.TrimSpace(v.CVEID)), vendor: cleanField(v.VendorProject), product: cleanField(v.Product),
			name: cleanField(v.VulnerabilityName), added: cleanDay(v.DateAdded), due: cleanDay(v.DueDate),
			ransomware: cleanField(v.Ransomware), notesURL: firstURL(v.Notes),
		})
	}
	if len(out) == 0 {
		return nil, errors.New("the KEV list holds no valid entry")
	}
	return out, nil
}

// ReadKEV downloads CISA's KEV list and replaces the kev table with it, in
// one transaction. etag is the ETag of the last read: a 304 answer returns
// (0, etag, ErrNotModified) and leaves the table as it is. Any failure leaves
// the previous data in place.
func ReadKEV(ctx context.Context, deps Deps, etag string) (items int, newETag string, err error) {
	body, newETag, err := fetch(ctx, deps.Client, kevURL, etag, maxKEVBytes)
	if err != nil {
		if errors.Is(err, ErrNotModified) {
			return 0, newETag, err
		}
		return 0, "", fmt.Errorf("cannot read the KEV list: %w", err)
	}
	rows, err := parseKEV(body)
	if err != nil {
		return 0, "", err
	}
	if err := replaceKEV(ctx, deps.Store.DB(), rows); err != nil {
		return 0, "", err
	}
	return len(rows), newETag, nil
}
