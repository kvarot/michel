// Command demo starts a test server for trying Michel's server pages by
// hand, never a real one: an sshtest SSH server on 127.0.0.1 (Debian 12, PHP
// 8.3.35 built from source, expose_php = On), its own SSH agent holding the
// only key the server accepts, and a local test site that can be cut. The
// scripts of a fix run in the sshtest shell, on the in-memory file system.
//
// It writes, in a folder of its own (a new temporary one by default): a
// policy file that points Michel at the demo agent, and a home folder whose
// .ssh/config names the server "demo", so "Trouver mes serveurs" finds it.
// It never reads or writes the real ~/.ssh, never reaches the real SSH
// agent, and listens on the loopback only.
//
//	go run ./internal/sshx/sshtest/cmd/demo
//
// Then type "cut" (or "coupe") to cut the site, "up" (or "remets") to bring
// it back, "status" to see the php.ini, and "quit" to stop.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/kvarot/michel/internal/sshx/sshtest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func run() error {
	dirFlag := flag.String("dir", "", "folder for the demo's policy file, home and Michel data (a new temporary folder when empty)")
	flag.Parse()
	dir := *dirFlag
	if dir == "" {
		d, err := os.MkdirTemp("", "michel-demo-")
		if err != nil {
			return err
		}
		dir = d
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	out := os.Stdout

	h := &host{log: out}
	root := &sshtest.Shell{UID: 0, Home: "/root"}
	user := &sshtest.Shell{UID: 1000, Home: userHome}
	srv, err := sshtest.Start(sshtest.Options{Files: files(), Commands: h.commands(), Sudo: true, Shell: user.Func(), RootShell: root.Func()})
	if err != nil {
		return err
	}
	defer srv.Close()
	h.srv = srv
	_, sshPort, _ := net.SplitHostPort(srv.Addr())

	// The test site, cut and brought back from the keyboard (or its
	// /__demo/cut and /__demo/up pages).
	var down atomic.Bool
	siteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	site := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__demo/cut":
			down.Store(true)
			fmt.Fprintln(out, "demo: site cut (from the browser)")
			io.WriteString(w, "demo site cut: Michel's site check now fails\n")
			return
		case "/__demo/up":
			down.Store(false)
			fmt.Fprintln(out, "demo: site back (from the browser)")
			io.WriteString(w, "demo site back\n")
			return
		}
		if down.Load() {
			http.Error(w, "demo site cut", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Server", "nginx/1.22.1")
		if h.ExposePHP() {
			w.Header().Set("X-Powered-By", "PHP/"+phpVersion)
		}
		io.WriteString(w, "<!doctype html><title>demo</title><p>demo site</p>\n")
	})}
	go site.Serve(siteLn)
	defer site.Close()
	siteURL := "http://" + siteLn.Addr().String() + "/"

	// The demo's own SSH agent: the only key the server accepts.
	keyring, err := srv.AddClientKey()
	if err != nil {
		return err
	}
	agentLn, agentPath, err := listenAgent(dir)
	if err != nil {
		return err
	}
	defer agentLn.Close()
	go serveAgent(agentLn, keyring)

	paths, err := writeFiles(dir, sshPort, agentPath)
	if err != nil {
		return err
	}
	printHelp(out, dir, srv, sshPort, siteURL, agentPath, paths)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			lines <- strings.ToLower(strings.TrimSpace(sc.Text()))
		}
		close(lines)
	}()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(out, "demo: stopped")
			return nil
		case l, ok := <-lines:
			if !ok {
				// No keyboard (stdin closed): keep serving until Ctrl+C.
				lines = nil
				continue
			}
			switch l {
			case "cut", "coupe":
				down.Store(true)
				fmt.Fprintln(out, "demo: site cut: it answers 503 until you type up")
			case "up", "remets":
				down.Store(false)
				fmt.Fprintln(out, "demo: site back")
			case "status", "etat":
				ini, _ := srv.File(phpIni)
				fmt.Fprintf(out, "demo: site down=%v, PHP-FPM reloads=%d\n%s\n", down.Load(), h.reloads, ini)
			case "quit", "exit", "q":
				fmt.Fprintln(out, "demo: stopped")
				return nil
			case "":
			default:
				fmt.Fprintln(out, "demo: type cut, up, status or quit")
			}
		}
	}
}

func serveAgent(ln net.Listener, kr agent.Agent) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			defer c.Close()
			_ = agent.ServeAgent(kr, c)
		}()
	}
}

type demoPaths struct {
	config, home, data string
}

// writeFiles writes the policy file (the demo agent) and the home folder
// with its .ssh/config, both in dir only.
func writeFiles(dir, port, agentPath string) (demoPaths, error) {
	p := demoPaths{config: filepath.Join(dir, "config.yaml"), home: filepath.Join(dir, "home"), data: filepath.Join(dir, "data")}
	if err := os.MkdirAll(filepath.Join(p.home, ".ssh"), 0o700); err != nil {
		return p, err
	}
	if err := os.MkdirAll(p.data, 0o700); err != nil {
		return p, err
	}
	sshConfig := fmt.Sprintf("# Written by Michel's demo server: a test server on this computer only.\nHost demo\n  HostName 127.0.0.1\n  Port %s\n  User %s\n", port, sshUser)
	if err := os.WriteFile(filepath.Join(p.home, ".ssh", "config"), []byte(sshConfig), 0o600); err != nil {
		return p, err
	}
	if _, err := os.Stat(p.config); errors.Is(err, os.ErrNotExist) {
		pol := fmt.Sprintf("# Michel's demo policy: the demo SSH agent, nothing else.\nassistant:\n  lang: fr\nssh:\n  agent_pipe: '%s'\nnotify:\n  page_url: http://127.0.0.1:7331/\n", agentPath)
		if err := os.WriteFile(p.config, []byte(pol), 0o600); err != nil {
			return p, err
		}
	} else if err == nil {
		// A folder used again: only the agent of this run changes.
		if err := setAgentPipe(p.config, agentPath); err != nil {
			return p, err
		}
	}
	return p, nil
}

// setAgentPipe writes the agent of this run into a policy file the demo
// wrote before.
func setAgentPipe(path, agentPath string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ls := strings.Split(string(b), "\n")
	for i, l := range ls {
		if strings.HasPrefix(strings.TrimSpace(l), "agent_pipe:") {
			ls[i] = "  agent_pipe: '" + agentPath + "'"
		}
	}
	return os.WriteFile(path, []byte(strings.Join(ls, "\n")), 0o600)
}

func printHelp(w io.Writer, dir string, srv *sshtest.Server, port, siteURL, agentPath string, p demoPaths) {
	fp := srv.HostKeyFingerprint()
	fmt.Fprintf(w, `Michel demo server (a test server on this computer, never a real one)

  SSH server   127.0.0.1:%s, user %s (Debian 12, PHP %s built from source, expose_php = On)
  host key     %s
  SSH agent    %s  (holds the only key this server accepts)
  test site    %s
  folder       %s

`, port, sshUser, phpVersion, fp, agentPath, siteURL, dir)
	bin := filepath.Join(dir, "michel")
	flags := fmt.Sprintf("--config '%s' --data-dir '%s'", p.config, p.data)
	if runtime.GOOS == "windows" {
		bin += ".exe"
		fmt.Fprintf(w, `1. Build Michel (in the repository, before changing any variable):
  go build -o '%s' ./cmd/michel
2. Start it on this demo in another PowerShell window (the two variables point
   discovery and known_hosts at the demo home only, for that window):
  $env:USERPROFILE = '%s'; $env:HOME = '%s'
  & '%s' %s serve --listen 127.0.0.1:7391
   Or by hand in that window:
  & '%s' %s target add demo --env prod --executor michel --sudo nopasswd --site-url %s
  & '%s' %s target trust demo --fingerprint %s
  & '%s' %s target check demo
`, bin, p.home, p.home, bin, flags, bin, flags, siteURL, bin, flags, fp, bin, flags)
	} else {
		fmt.Fprintf(w, `1. Build Michel (in the repository):
  go build -o '%s' ./cmd/michel
2. Start it on this demo (HOME points discovery and known_hosts at the demo home only):
  HOME='%s' '%s' %s serve --listen 127.0.0.1:7391
   Or by hand:
  HOME='%s' '%s' %s target add demo --env prod --executor michel --sudo nopasswd --site-url %s
  HOME='%s' '%s' %s target trust demo --fingerprint %s
  HOME='%s' '%s' %s target check demo
`, bin, p.home, bin, flags, p.home, bin, flags, siteURL, p.home, bin, flags, fp, p.home, bin, flags)
	}
	fmt.Fprintf(w, `
On the page: Serveurs > Trouver mes serveurs > "demo"; site address %s.
Here: type "cut" to cut the site, "up" to bring it back, "status", "quit".
(or open %s__demo/cut and %s__demo/up)
`, siteURL, siteURL, siteURL)
}
