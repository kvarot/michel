package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/api"
	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/buildinfo"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/web"
	"github.com/spf13/cobra"
)

// shutdownGrace is how long serve waits for requests in flight when stopped.
const shutdownGrace = 5 * time.Second

// serveReady, when set (tests), receives the page URL once serve listens.
var serveReady func(url string)

// openBrowser opens url in the default browser with a fixed program per
// system, run directly (no shell). Replaced in tests.
var openBrowser = func(url string) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		c = exec.Command(filepath.Join(root, "System32", "rundll32.exe"), "url.dll,FileProtocolHandler", url)
	case "darwin":
		c = exec.Command("/usr/bin/open", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	if err := c.Start(); err != nil {
		return err
	}
	go func() { _ = c.Wait() }()
	return nil
}

// loopbackListen checks that addr is host:port with a loopback host
// (127.0.0.0/8, ::1 or localhost) and a numeric port.
func loopbackListen(deps *Deps, addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", deps.Errorf("cli.serve.bad_listen", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return "", deps.Errorf("cli.serve.bad_listen", addr)
	}
	if host == "" || !policy.IsLoopbackHost(host) {
		return "", deps.Errorf("cli.serve.loopback_only", addr)
	}
	return addr, nil
}

func newServeCmd(deps *Deps) *cobra.Command {
	var listen string
	var open bool
	c := &cobra.Command{
		Use:   "serve",
		Short: "Serve the Today page and its local API on this computer only",
		Long: "Serve starts the Today page and its JSON API on a loopback address (127.0.0.1 by default): no other computer " +
			"can reach it. The first start creates an access token, kept in the data folder like the other secrets; serve " +
			"prints the page link with the token once, and the page then keeps it. Decisions taken on the page are " +
			"recorded and audited like 'michel decide' (author web). The project folders are never touched. " +
			"Ctrl+C stops the server.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := loopbackListen(deps, listen)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			swept, err := scan.SweepStale(ctx, deps.Store.DB(), deps.Now().UTC(), scan.StaleScanAfter)
			if err != nil {
				return err
			}
			if swept > 0 {
				if _, err := deps.Audit.Record(ctx, audit.Event{Actor: "serve", Action: "scan.sweep", Target: "serve", Result: "ok",
					Evidence: map[string]any{"swept": swept, "max_age": scan.StaleScanAfter.String()}}); err != nil {
					return deps.Wrapf("cli.serve.audit_failed", err)
				}
			}
			secrets, err := openSecrets(cmd, deps)
			if err != nil {
				return err
			}
			token, err := api.LoadOrCreateToken(secrets)
			if err != nil {
				return deps.Wrapf("cli.serve.token_failed", err)
			}
			var lc net.ListenConfig
			ln, err := lc.Listen(ctx, "tcp", addr)
			if err != nil {
				return deps.Wrapf("cli.serve.listen_failed", err, addr)
			}
			defer ln.Close()
			bound := ln.Addr().String()
			port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
			// The Sources page gives its consents like michel source enable:
			// the rules go into the policy file of --config, and a reload
			// hands them to the gateway at once.
			sd := sourceDeps(cmd, deps)
			dataDir, _ := cmd.Flags().GetString("data-dir")
			d := api.Deps{Store: deps.Store, Audit: deps.Audit, Policy: deps.Policy, Secrets: secrets, Now: deps.Now,
				Version: buildinfo.Version, OSVRoot: dbRoot(cmd, deps), Lang: deps.Lang,
				AllowedHosts: []string{bound, net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("localhost", port), net.JoinHostPort("::1", port)},
				PolicyPath:   sd.PolicyPath, Reload: sd.Reload, Sources: api.Sources{Gateway: deps.Gateway, DataDir: dataDir}}
			if fsys, ok := web.Dist(); ok {
				d.Web = fsys
			}
			srv := &http.Server{Handler: api.New(d, token), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
				WriteTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
			if _, err := deps.Audit.Record(ctx, audit.Event{Actor: "serve", Action: "api.start", Target: bound, Result: "ok",
				Evidence: map[string]any{"listen": bound}}); err != nil {
				return deps.Wrapf("cli.serve.audit_failed", err)
			}
			url := "http://" + bound + "/?token=" + token
			fmt.Fprintln(deps.Stdout, deps.T("cli.serve.url", url))
			served := make(chan error, 1)
			go func() { served <- srv.Serve(ln) }()
			if open {
				if err := openBrowser(url); err != nil {
					fmt.Fprintln(deps.Stderr, deps.T("cli.serve.open_failed", err))
				}
			}
			if serveReady != nil {
				serveReady(url)
			}
			var serveErr error
			select {
			case <-ctx.Done():
			case serveErr = <-served:
			}
			shutdown, cancel := context.WithTimeout(context.Background(), shutdownGrace)
			defer cancel()
			_ = srv.Shutdown(shutdown)
			if _, err := deps.Audit.Record(context.Background(), audit.Event{Actor: "serve", Action: "api.stop", Target: bound, Result: "ok",
				Evidence: map[string]any{"listen": bound}}); err != nil {
				return deps.Wrapf("cli.serve.audit_failed", err)
			}
			fmt.Fprintln(deps.Stdout, deps.T("cli.serve.stopped"))
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				return serveErr
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&listen, "listen", "127.0.0.1:7331", "address and port to listen on; only 127.0.0.1, [::1] or localhost are accepted")
	f.BoolVar(&open, "open", false, "open the page in the default browser")
	f.String("osv-db", "", "directory of the offline databases, for their freshness (default: from the policy)")
	return c
}
