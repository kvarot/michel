package serverlog

import (
	"context"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/target"
)

func TestDiscoverProposes(t *testing.T) {
	e := setup(t, target.EnvProd)
	ctx := context.Background()
	repo := target.NewRepo(e.s)
	if err := repo.Link(ctx, target.Link{TargetID: e.tgt.ID, ProjectID: "P1", RemoteDir: "/var/www/demo/"}); err != nil {
		t.Fatal(err)
	}
	inv := target.Inventory{TargetID: e.tgt.ID, At: t0, Directives: []target.Directive{
		{SAPI: "cli", Name: "error_log", Value: "/var/log/php-cli.log", File: "/etc/php/8.2/cli/php.ini", Line: 3},
		{SAPI: "fpm", Name: "error_log", Value: "/var/log/php-fpm.log", File: "/etc/php/8.2/fpm/php.ini", Line: 4},
		{SAPI: "fpm", Name: "php_admin_value[error_log]", Value: "/var/log/php/demo-pool.log", File: "/etc/php/8.2/fpm/pool.d/demo.conf", Line: 9},
		{SAPI: "fpm", Name: "php_value[error_log]", Value: "/var/log/php-fpm.log", File: "/etc/php/8.2/fpm/pool.d/www.conf", Line: 9}, // same file twice
		{SAPI: "fpm", Name: "php_admin_value[error_log]", Value: "syslog"},                                                            // not a file
		{SAPI: "cli", Name: "error_log", Value: "relative/php.log"},
		{SAPI: "cli", Name: "error_log", Value: "/var/log/../etc/php.log"},
		{SAPI: "fpm", Name: "error_log", Value: "/var/log/$(x).log"},
		{SAPI: "cli", Name: "error_log", Value: "/var/log/secret.log", Secret: true},
		{SAPI: "cli", Name: "display_errors", Value: "/var/log/not-a-log.log"},
	}}
	if err := repo.SaveInventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	got, err := Discover(ctx, repo, e.tgt)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Format{
		"/var/log/php-cli.log":                 FormatPHP,
		"/var/log/php-fpm.log":                 FormatPHP,
		"/var/log/php/demo-pool.log":           FormatPHP,
		"/var/log/postgresql/postgresql-*.log": FormatPostgres,
		"/var/www/demo/storage/logs/*.log":     FormatMonolog,
		"/var/www/demo/var/log/*.log":          FormatMonolog,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, c := range got {
		f, ok := want[c.Path]
		if !ok || f != c.Format {
			t.Errorf("unexpected candidate %+v", c)
		}
		if seen[c.Path] {
			t.Errorf("%s proposed twice", c.Path)
		}
		seen[c.Path] = true
		if c.Why == "" {
			t.Errorf("%s has no reason", c.Path)
		}
		if err := ValidatePath(c.Path); err != nil {
			t.Errorf("%s is proposed but refused: %v", c.Path, err)
		}
	}
	// Proposing creates nothing.
	if srcs, err := e.r.Sources(ctx, e.tgt.ID); err != nil || len(srcs) != 1 {
		t.Errorf("sources after Discover: %+v %v", srcs, err)
	}
	if n := count(t, e, `SELECT COUNT(*) FROM log_source`); n != 1 {
		t.Errorf("log_source = %d, want the one of setup", n)
	}
}

func TestDiscoverWithoutInventoryOrLinks(t *testing.T) {
	e := setup(t, target.EnvDev)
	got, err := Discover(context.Background(), target.NewRepo(e.s), e.tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0].Path, "/var/log/postgresql/") || got[0].Format != FormatPostgres {
		t.Fatalf("no inventory: %+v", got)
	}
}
