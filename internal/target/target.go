// Package target is the registry of the servers Michel checks over SSH, their
// links to projects, and the stored inventory of what was read on them. It is
// a leaf: no network and no SSH here.
package target

import (
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/policy"
)

// Kind is the sort of server.
type Kind string

const (
	// KindHDS is a server hosting health data: its classification is always health.
	KindHDS    Kind = "hds"
	KindVPS    Kind = "vps"
	KindShared Kind = "shared"
)

// Env is the role of the server.
type Env string

const (
	EnvProd    Env = "prod"
	EnvPreprod Env = "preprod"
	EnvDev     Env = "dev"
)

// Executor is who runs a validated fix script on the server.
type Executor string

const (
	ExecUser   Executor = "user"
	ExecMichel Executor = "michel"
)

// SudoMode tells whether the SSH user may use sudo without a password.
type SudoMode string

const (
	SudoNone     SudoMode = "none"
	SudoNopasswd SudoMode = "nopasswd"
)

// DefaultCheckInterval is the time between two checks of a server unless the
// user chooses another one. Add keeps the interval it is given; Due counts a
// zero interval as this default.
const DefaultCheckInterval = 24 * time.Hour

// ManualOnly is the check interval of a server checked by hand only: Due
// never returns it. Add and Update store any negative interval as this.
const ManualOnly = -time.Second

// Target is one server.
type Target struct {
	ID             string
	Name           string
	Host           string
	Port           int
	User           string
	Alias          string
	HostKey        string
	Kind           Kind
	Env            Env
	Classification policy.Classification
	FixLevel       int
	// CheckInterval is the time between two automatic checks; 0 means
	// DefaultCheckInterval and ManualOnly (negative) by hand only.
	CheckInterval time.Duration
	PreprodID     string
	Executor      Executor
	Sudo          SudoMode
	SiteURL       string
	AutoConfig    bool
	Active        bool
	LastCheckAt   time.Time
	CreatedAt     time.Time
}

// Link ties a server to a project and says where the project lives on it.
type Link struct {
	TargetID  string
	ProjectID string
	RemoteDir string
}

// Inventory is what a check read on a server. It never holds a secret value.
type Inventory struct {
	TargetID   string
	At         time.Time
	OS         OSInfo
	PHP        []PHPRuntime
	Web        []WebServer
	Packages   []Package
	Directives []Directive
	Files      []FileSeen
	Unseen     []Unseen
	// Site holds the HTTP headers of the site (SiteURL), when they were read.
	Site SiteHeaders
	// Listeners are the TCP services that listen on the server, address and
	// port only. ListenersRead tells that the list is a complete answer: when
	// it is false, nothing is known, and an empty list does not mean that
	// nothing listens. An inventory stored before this reading has it false.
	Listeners     []Listener
	ListenersRead bool
}

// ListenScope is who an address listens for, by the address alone. It says
// nothing about a firewall.
type ListenScope string

const (
	// ScopeOpen is any other address: every network the server is on.
	ScopeOpen ListenScope = "open"
	// ScopeServer is the server itself (loopback).
	ScopeServer ListenScope = "server"
	// ScopePrivate is an address of a private network.
	ScopePrivate ListenScope = "private"
)

// Listener is one TCP address and port where a service listens. It never
// names the process.
type Listener struct {
	Address string
	Port    int
	Scope   ListenScope
}

// cgnat is 100.64.0.0/10; netip leaves it out of IsPrivate.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// ClassifyListen tells the scope of a listening address. An IPv4 address
// written in IPv6 is unfolded first. A zone changes nothing: an address bound
// to an interface keeps the scope of the address, since Michel does not know
// what that interface reaches. What cannot be read counts as open: never
// narrower than what is known.
func ClassifyListen(addr string) ListenScope {
	host, _, _ := strings.Cut(addr, "%")
	a, err := netip.ParseAddr(host)
	if err != nil {
		return ScopeOpen
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return ScopeServer
	case a.IsPrivate(), cgnat.Contains(a), a.Is6() && a.IsLinkLocalUnicast():
		return ScopePrivate
	}
	return ScopeOpen
}

// SiteHeaders are the headers of the site that name its software.
type SiteHeaders struct {
	Server    string
	PoweredBy string
}

// OSInfo identifies the operating system (from os-release) and its kernel
// (uname -r).
type OSInfo struct {
	ID        string
	VersionID string
	Pretty    string
	Kernel    string
}

// PHPRuntime is one PHP installation: the command line one or a FPM one.
type PHPRuntime struct {
	SAPI         string // "cli" or "fpm"
	Binary       string
	Version      string
	FromPackage  string
	Modules      []string
	LoadedIni    string
	ScannedDir   string
	ScannedFiles []string
	PoolFiles    []string
}

// WebServer is a web server found on the machine.
type WebServer struct {
	Name    string
	Version string
}

// Package is an installed system package.
type Package struct {
	Name    string
	Source  string
	Version string
	Arch    string
}

// Directive is one configuration directive read in a file. Secret marks a
// value that was masked before storage.
//
// Binary is the PHP binary the directive belongs to (the CLI one or one
// FPM), so several FPM versions on one server can be told apart; a
// .user.ini directive (SAPI user_ini) has the FPM binary when exactly one
// FPM was seen, else "".
type Directive struct {
	SAPI   string
	Binary string
	Name   string
	Value  string
	File   string
	Line   int
	Secret bool
}

// FileSeen is a file that was read, with its hash.
type FileSeen struct {
	Path   string
	SHA256 string
	Size   int
}

// Unseen is something the check could not read, and why.
type Unseen struct {
	What   string
	Reason string
}

var (
	ErrNotFound        = errors.New("server not found")
	ErrDuplicateName   = errors.New("a server with this name already exists")
	ErrEmptyName       = errors.New("server name is empty")
	ErrEmptyHost       = errors.New("server host is empty")
	ErrInvalidPort     = errors.New("server port must be between 1 and 65535")
	ErrInvalidKind     = errors.New("unknown server kind")
	ErrInvalidEnv      = errors.New("unknown server environment")
	ErrInvalidExecutor = errors.New("unknown executor")
	ErrInvalidSudo     = errors.New("unknown sudo mode")
	ErrInvalidFixLevel = errors.New("fix level must be between 0 and 3")
	ErrInvalidClass    = errors.New("unknown classification")
	ErrHDSIsHealth     = errors.New("a server of kind hds is always classified health")
)
