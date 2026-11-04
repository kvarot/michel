package collect

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kvarot/michel/internal/target"
)

const (
	// maxListenerLines bounds the lines of ss read for one server; a line past
	// it counts as rejected, so a list that long is never taken as complete.
	maxListenerLines = 4096
	// maxListenerLine bounds one line: column padding included, a real one is
	// far shorter.
	maxListenerLine = 512
)

var (
	// listenersHeaderRe is the header of `ss -tln`. iproute2 aligns it, and the
	// last column depends on its version (seen on Debian 9 and 13, Ubuntu 14.04).
	listenersHeaderRe = regexp.MustCompile(`^State +Recv-Q +Send-Q +Local Address:Port +Peer Address:Port( *Process)? *$`)
	// zoneRe is an interface name as Linux allows it (IFNAMSIZ is 16 with its
	// final zero).
	zoneRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)
	queueRe = regexp.MustCompile(`^[0-9]{1,20}$`)
	portRe  = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
)

// ParseListeners reads the output of `ss -tln`. It keeps the address and the
// port of each LISTEN line, without the zone, each pair once, sorted by port
// and address: the order of ss means nothing, and an unchanged server keeps
// the same inventory.
//
// rejected counts the lines that do not fit, whose values are not kept, and
// the lines past maxListenerLines. sawHeader tells that the header of ss came
// first. Only a header with no rejected line is a complete answer; with no
// header at all, nothing was read, whatever the rest says.
func ParseListeners(out string) (ls []target.Listener, rejected int, sawHeader bool) {
	seen := map[target.Listener]bool{}
	read := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if read == 0 && !sawHeader && len(line) <= maxListenerLine && listenersHeaderRe.MatchString(line) {
			sawHeader = true
			continue
		}
		if read++; read > maxListenerLines {
			rejected++
			continue
		}
		l, ok := parseListenerLine(line)
		if !ok || !sawHeader {
			rejected++
			continue
		}
		if !seen[l] {
			seen[l] = true
			ls = append(ls, l)
		}
	}
	sort.Slice(ls, func(i, j int) bool {
		if ls[i].Port != ls[j].Port {
			return ls[i].Port < ls[j].Port
		}
		return ls[i].Address < ls[j].Address
	})
	return ls, rejected, sawHeader
}

// wildcardPeer holds the only peer columns ss prints for a listening socket.
var wildcardPeer = map[string]bool{"*:*": true, "0.0.0.0:*": true, "[::]:*": true, ":::*": true}

// parseListenerLine reads one line: LISTEN, the two queues, the local address
// and a peer that is a wildcard, nothing else. No process name can pass.
func parseListenerLine(line string) (target.Listener, bool) {
	if len(line) > maxListenerLine {
		return target.Listener{}, false
	}
	for i := 0; i < len(line); i++ {
		if line[i] < 0x20 || line[i] > 0x7e {
			return target.Listener{}, false
		}
	}
	f := strings.Fields(line)
	if !strings.HasPrefix(line, "LISTEN ") || len(f) != 5 || !queueRe.MatchString(f[1]) || !queueRe.MatchString(f[2]) ||
		!wildcardPeer[f[4]] {
		return target.Listener{}, false
	}
	addr, port, ok := parseListenAddress(f[3])
	if !ok {
		return target.Listener{}, false
	}
	return target.Listener{Address: addr, Port: port, Scope: target.ClassifyListen(addr)}, true
}

// parseListenAddress reads the local column in the forms ss prints: `*:80`,
// `0.0.0.0:80`, `[::]:80` and, in older versions, `:::80` or `::1:25`. Any of
// them may carry a zone before the port (`127.0.0.53%lo:53`,
// `[fe80::1]%eth0:22`). The port is what follows the last colon. The address
// comes back canonical, without its zone, or "*".
func parseListenAddress(s string) (string, int, bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || !portRe.MatchString(s[i+1:]) {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port > 65535 {
		return "", 0, false
	}
	host, zone, zoned := strings.Cut(s[:i], "%")
	if zoned && !zoneRe.MatchString(zone) {
		return "", 0, false
	}
	if host == "*" {
		return host, port, true
	}
	bracketed := strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]")
	if bracketed {
		host = host[1 : len(host)-1]
	}
	a, err := netip.ParseAddr(host)
	if err != nil || (bracketed && !a.Is6()) {
		return "", 0, false
	}
	return a.String(), port, true
}

// listeners reads what listens over TCP (ss, R7). /usr/sbin/ss is the same
// program, placed elsewhere: it is asked only when the first answer is 127,
// command not found. Everything but a complete answer is an Unseen line, with
// no list and no other means. An empty list counts as not seen too.
func (c *collector) listeners() {
	res, _, broken := c.probe(cmdSS)
	if !broken && res.Exit == 127 {
		res, _, broken = c.probe(cmdSSSbin)
	}
	if c.err != nil {
		return
	}
	if !broken && res.Exit == 0 && !res.Truncated {
		ls, rejected, sawHeader := ParseListeners(string(res.Stdout))
		// An empty list is never a read: Michel has just come in through sshd,
		// so no listener at all means ss looked elsewhere or could not look,
		// and it can do so with a header, exit 0 and no error.
		if sawHeader && rejected == 0 && len(ls) > 0 {
			c.inv.Listeners, c.inv.ListenersRead = ls, true
			return
		}
	}
	c.unseen("listeners", ReasonListeners)
}
