package enrich

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/kvarot/michel/internal/scan"
)

// epssRow is one row of the epss table.
type epssRow struct {
	cve               string
	score, percentile float64
}

// parseEPSS reads FIRST's gzipped CSV: comment lines start with "#" (the
// first one carries "score_date:<RFC 3339>", whose day is the model date),
// then a "cve,epss,percentile" header and one row per CVE. Rows that do not
// read as a CVE and two scores in [0, 1] are left out. The decompressed text
// is capped at limit bytes.
func parseEPSS(body []byte, limit int64) (rows []epssRow, modelDate string, err error) {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("the EPSS file is not gzip: %w", err)
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: limit + 1}
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			for _, part := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(part), "score_date:"); ok && len(v) >= 10 {
					modelDate = cleanDay(v[:10])
				}
			}
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 3 || !scan.IsCVE(f[0]) {
			continue // the header, or a row Michel cannot read
		}
		score, e1 := strconv.ParseFloat(strings.TrimSpace(f[1]), 64)
		pct, e2 := strconv.ParseFloat(strings.TrimSpace(f[2]), 64)
		if e1 != nil || e2 != nil || score < 0 || score > 1 || pct < 0 || pct > 1 {
			continue
		}
		rows = append(rows, epssRow{cve: strings.ToUpper(strings.TrimSpace(f[0])), score: score, percentile: pct})
	}
	if limited.N <= 0 {
		return nil, "", fmt.Errorf("the EPSS file is more than the %d bytes Michel accepts once decompressed", limit)
	}
	if err := sc.Err(); err != nil {
		return nil, "", fmt.Errorf("cannot read the EPSS file: %w", err)
	}
	if len(rows) == 0 {
		return nil, "", errors.New("the EPSS file holds no valid row")
	}
	return rows, modelDate, nil
}

// ReadEPSS downloads FIRST's EPSS scores of the day and replaces the epss
// table with them, in one transaction. etag works as in ReadKEV. The
// compressed download is capped like the decompressed text, at MaxEPSSBytes.
func ReadEPSS(ctx context.Context, deps Deps, etag string) (items int, newETag string, err error) {
	body, newETag, err := fetch(ctx, deps.Client, epssURL, etag, maxEPSSBytes)
	if err != nil {
		if errors.Is(err, ErrNotModified) {
			return 0, newETag, err
		}
		return 0, "", fmt.Errorf("cannot read the EPSS scores: %w", err)
	}
	rows, modelDate, err := parseEPSS(body, maxEPSSBytes)
	if err != nil {
		return 0, "", err
	}
	if err := replaceEPSS(ctx, deps.Store.DB(), rows, modelDate); err != nil {
		return 0, "", err
	}
	return len(rows), newETag, nil
}
