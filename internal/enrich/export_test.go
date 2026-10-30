package enrich

import (
	"context"
	"time"
)

// SetBaseURLsForTest points the on-demand readers at test servers and
// removes the pauses between requests; it returns the function that restores
// the real values.
func SetBaseURLsForTest(vulnrichment, nvd, circl string) (restore func()) {
	ov, on, oc, op := vulnrichmentBase, nvdBase, circlBase, pause
	vulnrichmentBase, nvdBase, circlBase = vulnrichment, nvd, circl
	pause = func(context.Context, time.Duration) error { return nil }
	return func() { vulnrichmentBase, nvdBase, circlBase, pause = ov, on, oc, op }
}

// SetMaxOnDemandBytesForTest lowers the body cap.
func SetMaxOnDemandBytesForTest(n int64) (restore func()) {
	old := maxOnDemandBytes
	maxOnDemandBytes = n
	return func() { maxOnDemandBytes = old }
}
