package plugin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/scan"
)

// plugin_run statuses.
const (
	RunRunning = "running"
	RunOK      = "ok"
	RunFailed  = "failed"
)

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func insertRun(ctx context.Context, db *sql.DB, id, sourceID, projectID string, started time.Time) error {
	_, err := db.ExecContext(ctx, `INSERT INTO plugin_run (id, source_id, project_id, started_at, status) VALUES (?,?,?,?,?)`,
		id, sourceID, projectID, stamp(started), RunRunning)
	return err
}

// runRow is what a run stores when it ends.
type runRow struct {
	finished        time.Time
	version, report string
	status, errText string
	findings        int
	log             string
}

func finishRun(ctx context.Context, ex interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, id string, r runRow) error {
	_, err := ex.ExecContext(ctx, `UPDATE plugin_run SET finished_at=?, tool_version=?, report_path=?, status=?, error=?, findings=?, log=?
		WHERE id=?`, stamp(r.finished), r.version, r.report, r.status, r.errText, r.findings, r.log, id)
	return err
}

// knownCVEs are the ids (upper case) of the OSV findings of the project
// still present, with their aliases: a plugin does not report them again.
func knownCVEs(ctx context.Context, db *sql.DB, projectID string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT osv_id, aliases FROM finding WHERE project_id = ? AND source_key = '' AND status <> ?`,
		projectID, scan.StatusGone)
	if err != nil {
		return nil, fmt.Errorf("cannot read the findings: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id, aliases string
		if err := rows.Scan(&id, &aliases); err != nil {
			return nil, err
		}
		var list []string
		_ = json.Unmarshal([]byte(aliases), &list)
		for _, x := range append(list, id) {
			if x = strings.ToUpper(strings.TrimSpace(x)); x != "" {
				out[x] = true
			}
		}
	}
	return out, rows.Err()
}
