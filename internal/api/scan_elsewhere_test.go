package api

import (
	"fmt"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
)

// A check refused because another process scans the project says so, not
// "the check failed".
func TestScanRunningElsewhereHasItsSentence(t *testing.T) {
	code := codeOfScan(fmt.Errorf("%w: demo", scan.ErrScanRunning))
	if code != "api.project.scan_elsewhere" || !i18n.Has(code+"_hint") {
		t.Errorf("code = %q", code)
	}
}
