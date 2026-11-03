package collect_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/collect"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/sshx/sshtest"
	"github.com/kvarot/michel/internal/target"
)

const ssHeader = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"

func listenerSet(ls []target.Listener) string {
	var out []string
	for _, l := range ls {
		out = append(out, fmt.Sprintf("%s %d %s", l.Address, l.Port, l.Scope))
	}
	return strings.Join(out, "\n")
}

func TestParseListeners(t *testing.T) {
	ls, rejected, saw := collect.ParseListeners(fixture(t, "ss-debian.txt"))
	if rejected != 0 || !saw {
		t.Fatalf("rejected %d, header %v", rejected, saw)
	}
	want := strings.Join([]string{
		"0.0.0.0 22 open",
		":: 22 open",
		"fe80::1 22 private",
		"127.0.0.53 53 server",
		"0.0.0.0 68 open",
		"* 80 open",
		"0.0.0.0 80 open",
		":: 80 open",
		"127.0.0.1 5432 server",
		"::1 5432 server",
		"::ffff:127.0.0.1 8080 server",
		"203.0.113.7 9200 open",
	}, "\n")
	if got := listenerSet(ls); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// Older iproute2, as printed by those of Debian 9 and Ubuntu 14.04: no
// brackets around IPv6, `*` for any IPv4 address, the zone right after an
// unbracketed address.
func TestParseListenersOldForms(t *testing.T) {
	ls, rejected, saw := collect.ParseListeners(fixture(t, "ss-rhel.txt"))
	if rejected != 0 || !saw {
		t.Fatalf("rejected %d, header %v", rejected, saw)
	}
	want := strings.Join([]string{
		"* 22 open",
		":: 22 open",
		"127.0.0.1 25 server",
		"::1 25 server",
		"fe80::1 2222 private",
		"192.0.2.10 3306 open",
		"::ffff:127.0.0.1 8080 server",
	}, "\n")
	if got := listenerSet(ls); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestParseListenersHeaderForms(t *testing.T) {
	for _, h := range []string{
		"State Recv-Q Send-Q Local Address:Port Peer Address:Port\n",
		"State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n",
		"State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n",
		"State      Recv-Q Send-Q        Local Address:Port          Peer Address:Port \n",
	} {
		ls, rejected, saw := collect.ParseListeners(h + "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
		if !saw || rejected != 0 || len(ls) != 1 {
			t.Errorf("%q: %+v rejected %d header %v", h, ls, rejected, saw)
		}
	}
}

func TestParseListenersFormsAreCanonical(t *testing.T) {
	out := ssHeader +
		"LISTEN 0 1 [::]:80 [::]:*\n" +
		"LISTEN 0 1 :::80 :::*\n" +
		"LISTEN 0 1 [0:0:0:0:0:0:0:0]:80 [::]:*\n" +
		"LISTEN 0 1 [2001:DB8::1]:443 [::]:*\n" +
		"LISTEN 0 1 *%eth0:81 *:*\n" +
		"LISTEN 0 1 [::]%eth0.100:82 [::]:*\n"
	ls, rejected, _ := collect.ParseListeners(out)
	want := ":: 80 open\n* 81 open\n:: 82 open\n2001:db8::1 443 open"
	if got := listenerSet(ls); got != want || rejected != 0 {
		t.Fatalf("rejected %d, got:\n%s", rejected, got)
	}
}

func TestParseListenersRefusesForged(t *testing.T) {
	for name, line := range map[string]string{
		"tab":           "LISTEN\t0\t128\t0.0.0.0:22\t0.0.0.0:*",
		"tab inside":    "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\t",
		"port 0":        "LISTEN 0 128 0.0.0.0:0 0.0.0.0:*",
		"port 70000":    "LISTEN 0 128 0.0.0.0:70000 0.0.0.0:*",
		"port negative": "LISTEN 0 128 0.0.0.0:-22 0.0.0.0:*",
		"port plus":     "LISTEN 0 128 0.0.0.0:+22 0.0.0.0:*",
		"port zeros":    "LISTEN 0 128 0.0.0.0:0022 0.0.0.0:*",
		"port name":     "LISTEN 0 128 0.0.0.0:ssh 0.0.0.0:*",
		"port star":     "LISTEN 0 128 0.0.0.0:* 0.0.0.0:*",
		"port huge":     "LISTEN 0 128 0.0.0.0:99999999999999999999 0.0.0.0:*",
		"no port":       "LISTEN 0 128 0.0.0.0 0.0.0.0:*",
		"no address":    "LISTEN 0 128 :22 0.0.0.0:*",
		"name":          "LISTEN 0 128 canary.example.test:22 0.0.0.0:*",
		"not ip":        "LISTEN 0 128 999.1.1.1:22 0.0.0.0:*",
		"leading zero":  "LISTEN 0 128 010.0.0.1:22 0.0.0.0:*",
		"shell":         "LISTEN 0 128 $(id):22 0.0.0.0:*",
		"backquote":     "LISTEN 0 128 `id`:22 0.0.0.0:*",
		"zone shell":    "LISTEN 0 128 0.0.0.0%$(id):22 0.0.0.0:*",
		"zone empty":    "LISTEN 0 128 0.0.0.0%:22 0.0.0.0:*",
		"zone long":     "LISTEN 0 128 0.0.0.0%" + strings.Repeat("a", 16) + ":22 0.0.0.0:*",
		"zone twice":    "LISTEN 0 128 0.0.0.0%a%b:22 0.0.0.0:*",
		"zone inside":   "LISTEN 0 128 [fe80::1%eth0]:22 [::]:*",
		"bracket v4":    "LISTEN 0 128 [192.0.2.1]:22 0.0.0.0:*",
		"bracket open":  "LISTEN 0 128 [::1:22 [::]:*",
		"bracket star":  "LISTEN 0 128 [*]:22 [::]:*",
		"not LISTEN":    "ESTAB 0 0 192.0.2.1:22 198.51.100.1:5555",
		"unconn":        "UNCONN 0 0 0.0.0.0:68 0.0.0.0:*",
		"lower case":    "listen 0 128 0.0.0.0:22 0.0.0.0:*",
		"spaced":        " LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
		"no state":      "0 128 0.0.0.0:22 0.0.0.0:*",
		"ansi":          "LISTEN 0 128 \x1b[31m0.0.0.0:22\x1b[0m 0.0.0.0:*",
		"ansi after":    "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* \x1b[2K",
		"nul":           "LISTEN 0 128 0.0.0.0:22\x00 0.0.0.0:*",
		"carriage":      "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\rLISTEN 0 1 192.0.2.1:1 *:*",
		"non ascii":     "LISTEN 0 128 ０.0.0.0:22 0.0.0.0:*",
		"bad utf8":      "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* \xff",
		"process":       `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`,
		"short":         "LISTEN 0 128 0.0.0.0:22",
		"queue word":    "LISTEN a 128 0.0.0.0:22 0.0.0.0:*",
		"send word":     "LISTEN 0 b 0.0.0.0:22 0.0.0.0:*",
		"peer set":      "LISTEN 0 128 0.0.0.0:22 198.51.100.1:5555",
		"long line":     "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*" + strings.Repeat(" ", 600),
		"second header": strings.TrimSpace(ssHeader),
		"banner":        "Welcome to srv-demo!",
	} {
		ls, rejected, saw := collect.ParseListeners(ssHeader + line + "\n")
		if rejected != 1 || len(ls) != 0 || !saw {
			t.Errorf("%s: kept %+v, rejected %d, header %v", name, ls, rejected, saw)
		}
	}
}

func TestParseListenersKeepsTheGoodLinesAndCountsTheBad(t *testing.T) {
	ls, rejected, _ := collect.ParseListeners(ssHeader + "LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\ngarbage\nLISTEN 0 1 0.0.0.0:70000 *:*\n\n   \nLISTEN 0 1 0.0.0.0:80 *:*\n")
	if rejected != 2 || listenerSet(ls) != "0.0.0.0 22 open\n0.0.0.0 80 open" {
		t.Fatalf("rejected %d: %+v", rejected, ls)
	}
}

func TestParseListenersLinesBeforeTheHeaderAreRejected(t *testing.T) {
	ls, rejected, saw := collect.ParseListeners("LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\nmotd\n" + ssHeader)
	if rejected != 3 || len(ls) != 0 || saw {
		t.Fatalf("%+v rejected %d header %v", ls, rejected, saw)
	}
}

func TestParseListenersAtMost4096Lines(t *testing.T) {
	var b strings.Builder
	b.WriteString(ssHeader)
	n := 5000
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "LISTEN 0 1 127.0.0.1:%d 0.0.0.0:*\n", 1+i)
	}
	ls, rejected, _ := collect.ParseListeners(b.String())
	if len(ls) != 4096 || rejected != n-4096 {
		t.Fatalf("kept %d, rejected %d", len(ls), rejected)
	}
	// Duplicates count as lines: the bound is on what is read, not kept.
	b.Reset()
	b.WriteString(ssHeader)
	for i := 0; i < n; i++ {
		b.WriteString("LISTEN 0 1 127.0.0.1:80 0.0.0.0:*\n")
	}
	ls, rejected, _ = collect.ParseListeners(b.String())
	if len(ls) != 1 || rejected != n-4096 {
		t.Fatalf("kept %d, rejected %d", len(ls), rejected)
	}
}

func TestParseListenersOversizeOutput(t *testing.T) {
	// One megabyte on one line, as much as sshx keeps.
	ls, rejected, saw := collect.ParseListeners(ssHeader + strings.Repeat("A", sshx.MaxOutput))
	if len(ls) != 0 || rejected != 1 || !saw {
		t.Fatalf("%d kept, rejected %d, header %v", len(ls), rejected, saw)
	}
}

func TestNoHeaderIsNotRead(t *testing.T) {
	for name, out := range map[string]string{
		"empty":        "",
		"blank":        "\n\n",
		"only rows":    "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n",
		"usage":        "Usage: ss [ OPTIONS ]\n",
		"not found":    "sh: ss: not found\n",
		"other header": "Recv-Q Send-Q Local Address:Port Peer Address:Port\n0 128 *:22 *:*\n",
		"netstat":      "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address State\n",
		"half header":  "State Recv-Q\n",
		"header plus":  "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process Extra\n",
	} {
		if _, _, saw := collect.ParseListeners(out); saw {
			t.Errorf("%s: header seen", name)
		}
	}
	// A header alone is an answer: nothing listens.
	ls, rejected, saw := collect.ParseListeners(ssHeader)
	if len(ls) != 0 || rejected != 0 || !saw {
		t.Fatalf("%+v rejected %d header %v", ls, rejected, saw)
	}
}

func ssEnv(t *testing.T, tune func(h *host)) *env {
	t.Helper()
	h := debian(t)
	if tune != nil {
		tune(h)
	}
	return start(t, h)
}

// ssServed is a host whose commands the test replaced.
func ssServed(t *testing.T, tune func(h *host, cmds map[string]sshtest.Handler)) *env {
	t.Helper()
	h := debian(t)
	cmds := h.commands()
	tune(h, cmds)
	return restart(t, start(t, h), sshtest.New(t, sshtest.Options{Commands: cmds}))
}

func assertNoOtherMeans(t *testing.T, e *env) {
	t.Helper()
	for _, l := range e.srv.Log() {
		for _, bad := range []string{"netstat", "sudo", "/proc", "lsof", "sockstat", "busybox", "'-p'", "tlnp"} {
			if strings.Contains(l, bad) {
				t.Errorf("other means tried: %s", l)
			}
		}
	}
}

func ssLog(e *env) []string {
	var out []string
	for _, l := range e.srv.Log() {
		if strings.Contains(l, "ss'") {
			out = append(out, l)
		}
	}
	return out
}

func assertUnseen(t *testing.T, name string, inv target.Inventory) {
	t.Helper()
	if inv.ListenersRead || len(inv.Listeners) != 0 {
		t.Errorf("%s: read %v, listeners %+v", name, inv.ListenersRead, inv.Listeners)
	}
	n := 0
	for _, u := range inv.Unseen {
		if u.What == "listeners" {
			n++
		}
	}
	if n != 1 || !hasUnseen(inv, "listeners", collect.ReasonListeners) {
		t.Errorf("%s: unseen %+v", name, inv.Unseen)
	}
}

func TestListenersRunAsTheClosedList(t *testing.T) {
	e := ssEnv(t, nil)
	inv := run(t, e, demoLinks)
	if !inv.ListenersRead || len(inv.Listeners) == 0 {
		t.Fatalf("read %v: %+v (unseen %+v)", inv.ListenersRead, inv.Listeners, inv.Unseen)
	}
	if got := ssLog(e); len(got) != 1 || got[0] != envC+`'ss' '-tln'` {
		t.Fatalf("got %q", got)
	}
	fixed := 0
	for _, argv := range collect.Commands(e.tgt) {
		q := sshx.Quote(argv)
		if q == envC+`'ss' '-tln'` || q == envC+`'/usr/sbin/ss' '-tln'` {
			fixed++
		}
	}
	if fixed != 2 {
		t.Fatalf("%d ss commands in Commands", fixed)
	}
}

func TestSsInSbinOnlyAfter127(t *testing.T) {
	// Only in /usr/sbin: asked after the 127.
	e := ssEnv(t, func(h *host) { h.ssSbin, h.ss = fixture(t, "ss-rhel.txt"), "" })
	inv := run(t, e, demoLinks)
	if !inv.ListenersRead || len(inv.Listeners) != 7 {
		t.Fatalf("read %v, %+v, unseen %+v", inv.ListenersRead, inv.Listeners, inv.Unseen)
	}
	if got := ssLog(e); len(got) != 2 || got[1] != envC+`'/usr/sbin/ss' '-tln'` {
		t.Fatalf("got %q", got)
	}
	// Another failure of the first is an answer: the other is not asked.
	for _, code := range []int{1, 2, 126, 255} {
		code := code
		e := ssServed(t, func(h *host, cmds map[string]sshtest.Handler) {
			cmds["ss"] = func(sshtest.Exec) int { return code }
			cmds["/usr/sbin/ss"] = func(e sshtest.Exec) int { io.WriteString(e.Stdout, ssHeader); return 0 }
		})
		assertUnseen(t, fmt.Sprintf("code %d", code), run(t, e, demoLinks))
		if got := ssLog(e); len(got) != 1 {
			t.Fatalf("code %d: got %q", code, got)
		}
	}
	// In /usr/sbin too, a failure is said, not retried.
	e = ssServed(t, func(h *host, cmds map[string]sshtest.Handler) {
		cmds["ss"] = notFound
		cmds["/usr/sbin/ss"] = func(sshtest.Exec) int { return 1 }
	})
	assertUnseen(t, "sbin fails", run(t, e, demoLinks))
	if got := ssLog(e); len(got) != 2 {
		t.Fatalf("got %q", got)
	}
}

func TestSsMissingIsUnseen(t *testing.T) {
	e := ssEnv(t, func(h *host) { h.ss = "" })
	assertUnseen(t, "missing", run(t, e, demoLinks))
	assertNoOtherMeans(t, e)
	if got := ssLog(e); len(got) != 2 {
		t.Fatalf("got %q", got)
	}
}

func TestSsFailureIsUnseen(t *testing.T) {
	serve := func(code int, stdout, stderr string) sshtest.Handler {
		return func(e sshtest.Exec) int {
			io.WriteString(e.Stdout, stdout)
			io.WriteString(e.Stderr, stderr)
			return code
		}
	}
	good := fixture(t, "ss-debian.txt")
	rows := func(n int) string { return ssHeader + strings.Repeat("LISTEN 0 1 127.0.0.1:80 0.0.0.0:*\n", n) }
	for name, h := range map[string]sshtest.Handler{
		"code 1":           serve(1, good, "ss: broken\n"),
		"code 1, empty":    serve(1, "", ""),
		"empty, code 0":    serve(0, "", ""),
		"no header":        serve(0, "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", ""),
		"garbage":          serve(0, strings.Repeat("x", 2000)+"\n", ""),
		"rejected line":    serve(0, good+"LISTEN 0 128 0.0.0.0:70000 0.0.0.0:*\n", ""),
		"banner first":     serve(0, "Welcome\n"+good, ""),
		"too many lines":   serve(0, rows(4097), ""),
		"output cut":       serve(0, rows(40000), ""),
		"stderr cut":       serve(0, good, strings.Repeat("e", sshx.MaxOutput+1)),
		"header and error": serve(0, ssHeader, "Cannot open netlink socket: Protocol not supported\n"),
	} {
		e := ssServed(t, func(_ *host, cmds map[string]sshtest.Handler) {
			cmds["ss"] = h
			cmds["/usr/sbin/ss"] = serve(0, good, "")
		})
		assertUnseen(t, name, run(t, e, demoLinks))
		if got := ssLog(e); len(got) != 1 {
			t.Errorf("%s: got %q", name, got)
		}
		assertNoOtherMeans(t, e)
	}
	// Past its time limit: the collection goes on, and nothing is claimed.
	e := ssEnv(t, func(h *host) { h.ssSbin = good })
	r := slowRunner{r: e.client, slow: func(argv []string) bool { return argv[len(argv)-2] == "ss" }}
	inv, err := collect.Run(context.Background(), e.deps, r, e.tgt, demoLinks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertUnseen(t, "timeout", inv)
	if got := ssLog(e); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
}

type failRunner struct {
	r    collect.Runner
	fail func(argv []string) bool
}

func (f failRunner) Run(ctx context.Context, argv []string, stdin io.Reader) (sshx.Result, error) {
	if f.fail(argv) {
		return sshx.Result{}, errors.New("connection lost")
	}
	return f.r.Run(ctx, argv, stdin)
}

// The connection lost during ss is a stopped collection, not a claim.
func TestSsConnectionLostStops(t *testing.T) {
	e := ssEnv(t, nil)
	r := failRunner{r: e.client, fail: func(argv []string) bool { return argv[len(argv)-2] == "ss" }}
	inv, err := collect.Run(context.Background(), e.deps, r, e.tgt, demoLinks)
	if err == nil || inv.ListenersRead || len(inv.Listeners) != 0 {
		t.Fatalf("err %v, %+v", err, inv.Listeners)
	}
}

// A list that holds nothing is an answer, and differs from a failed read.
func TestNothingListeningIsRead(t *testing.T) {
	e := ssEnv(t, func(h *host) { h.ss = ssHeader })
	inv := run(t, e, demoLinks)
	if !inv.ListenersRead || len(inv.Listeners) != 0 || hasUnseen(inv, "listeners", collect.ReasonListeners) {
		t.Fatalf("read %v, %+v, unseen %+v", inv.ListenersRead, inv.Listeners, inv.Unseen)
	}
	// A warning next to good lines (ss falling back to /proc) changes nothing.
	e = ssServed(t, func(_ *host, cmds map[string]sshtest.Handler) {
		cmds["ss"] = func(e sshtest.Exec) int {
			io.WriteString(e.Stdout, fixture(t, "ss-debian.txt"))
			io.WriteString(e.Stderr, "Cannot open netlink socket: Protocol not supported\n")
			return 0
		}
	})
	if inv := run(t, e, demoLinks); !inv.ListenersRead || len(inv.Listeners) == 0 {
		t.Fatalf("read %v, unseen %+v", inv.ListenersRead, inv.Unseen)
	}
}

func TestSsDoesNotAskProcessNames(t *testing.T) {
	e := ssEnv(t, nil)
	run(t, e, demoLinks)
	assertNoOtherMeans(t, e)
	for _, l := range ssLog(e) {
		if !strings.HasSuffix(l, `ss' '-tln'`) {
			t.Errorf("command: %s", l)
		}
	}
	for _, argv := range collect.Commands(e.tgt) {
		if strings.HasSuffix(argv[len(argv)-2], "ss") && argv[len(argv)-1] != "-tln" {
			t.Errorf("argv %q", argv)
		}
	}
	// A listener has room for its address, its port and its scope, no more.
	b, err := json.Marshal(target.Listener{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Fatalf("a listener holds %s", b)
	}
}

func TestAuditCountsListenersOnly(t *testing.T) {
	e := ssEnv(t, nil)
	inv := run(t, e, demoLinks)
	var ev string
	if err := e.st.DB().QueryRow(`SELECT evidence FROM audit_event WHERE action = 'target.collect'`).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(ev), &m); err != nil {
		t.Fatal(err)
	}
	if len(inv.Listeners) == 0 || m["listeners"] != float64(len(inv.Listeners)) {
		t.Fatalf("evidence %s", ev)
	}
	for _, bad := range []string{"0.0.0.0", "203.0.113.7", "127.0.0.53", "fe80", "9200", "5432"} {
		if strings.Contains(ev, bad) {
			t.Errorf("the evidence holds %q: %s", bad, ev)
		}
	}
}

func TestSameOnHdsAndShared(t *testing.T) {
	var want, wantCmd string
	for i, k := range []target.Kind{target.KindVPS, target.KindHDS, target.KindShared} {
		e := ssEnv(t, nil)
		e.tgt.Kind = k
		inv := run(t, e, demoLinks)
		got, cmd := listenerSet(inv.Listeners), strings.Join(ssLog(e), "|")
		if i == 0 {
			want, wantCmd = got, cmd
			if want == "" || !inv.ListenersRead {
				t.Fatalf("%+v", inv)
			}
			continue
		}
		if got != want || cmd != wantCmd || !inv.ListenersRead {
			t.Errorf("%s: %s\n%s", k, got, cmd)
		}
	}
}
