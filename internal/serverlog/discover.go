package serverlog

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/target"
)

// Candidate is a log source Michel proposes. Nothing is created: the user
// ticks. Why is a stable key for the reason, which the interface words.
type Candidate struct {
	Path   string
	Format Format
	Why    string
}

// Reasons of a proposal.
const (
	WhyPHPCLI     = "php_error_log_cli"
	WhyPHPFPM     = "php_error_log_fpm"
	WhyPHPPool    = "php_error_log_pool"
	WhyPostgres   = "postgresql_default_folder"
	WhyAppStorage = "project_storage_logs"
	WhyAppVarLog  = "project_var_log"
)

// The usual places, under a linked project folder or on the server.
const (
	postgresGlob   = "/var/log/postgresql/postgresql-*.log"
	projectStorage = "/storage/logs/*.log"
	projectVarLog  = "/var/log/*.log"
)

// errorLogRe matches the directive that names the PHP log: error_log in
// php.ini, or set by a FPM pool.
var errorLogRe = regexp.MustCompile(`^(error_log|php_(?:admin_)?value\[error_log\])$`)

// Discover proposes log sources for a server from what the last collection
// saw (PHP error_log, CLI and FPM, pools included) and from usual places: the
// PostgreSQL folder and the storage/logs and var/log folders of the linked
// projects. It reads the database only: nothing is read on the server and no
// source is created.
func Discover(ctx context.Context, repo *target.Repo, t target.Target) ([]Candidate, error) {
	var out []Candidate
	seen := map[string]bool{}
	add := func(path string, f Format, why string) {
		if seen[path] || ValidatePath(path) != nil {
			return
		}
		seen[path] = true
		out = append(out, Candidate{Path: path, Format: f, Why: why})
	}

	inv, ok, err := repo.LatestInventory(ctx, t.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot propose log sources: %w", err)
	}
	if ok {
		for _, why := range []struct {
			test func(target.Directive) bool
			key  string
		}{
			{func(d target.Directive) bool { return d.SAPI == "cli" && d.Name == "error_log" }, WhyPHPCLI},
			{func(d target.Directive) bool { return d.SAPI == "fpm" && d.Name == "error_log" }, WhyPHPFPM},
			{func(d target.Directive) bool { return d.SAPI == "fpm" && d.Name != "error_log" }, WhyPHPPool},
		} {
			for _, d := range inv.Directives {
				if d.Secret || !errorLogRe.MatchString(d.Name) || !why.test(d) {
					continue
				}
				// "syslog", a relative path or an empty value name no file.
				if v := strings.TrimSpace(d.Value); strings.HasPrefix(v, "/") {
					add(v, FormatPHP, why.key)
				}
			}
		}
	}

	add(postgresGlob, FormatPostgres, WhyPostgres)

	links, err := repo.Links(ctx, t.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot propose log sources: %w", err)
	}
	for _, l := range links {
		dir := strings.TrimRight(l.RemoteDir, "/")
		if dir == "" {
			continue
		}
		add(dir+projectStorage, FormatMonolog, WhyAppStorage)
		add(dir+projectVarLog, FormatMonolog, WhyAppVarLog)
	}
	return out, nil
}
