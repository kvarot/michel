// Package plugin runs the external tools of the plugin sources (Trivy,
// Semgrep) behind a deny-all proxy, or reads a report they or another tool
// produced (SARIF, Trivy JSON), and turns their results into findings of the
// same loop as the OSV ones. A tool's report is untrusted data: its text is
// sanitized, its locations made relative to the project (or refused), and
// nothing in it is ever executed.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/source"
)

// Kinds of the findings a plugin reports (scan.Finding.Kind).
const (
	// KindCode is a weakness in the project's own code (Semgrep, CodeQL).
	KindCode = "code"
	// KindMisconfig is a risky setting in a configuration file (Trivy).
	KindMisconfig = "misconfig"
	// KindWeb is a weakness seen on the running site (ZAP).
	KindWeb = "web"
	// KindVulnerability is a flaw of a package that the tool reports and the
	// OSV scan did not (Trivy JSON with vulnerabilities).
	KindVulnerability = "vulnerability"
)

// Report formats (config.format).
const (
	FormatSARIF     = "sarif"
	FormatTrivyJSON = "trivy_json"
)

var (
	// ErrNotRunnable: Michel does not run this tool itself; its report is
	// read with an input file.
	ErrNotRunnable = errors.New("Michel does not run this tool: pass its report as an input file")
	// ErrNotInstalled: the tool's program is not on the PATH.
	ErrNotInstalled = errors.New("the tool is not installed")
	// ErrNoRules: Semgrep has no local rules to run offline.
	ErrNoRules = errors.New("no Semgrep rules in Michel's data folder")
	// ErrUnknownTool and ErrUnknownFormat refuse a plugin setting.
	ErrUnknownTool   = errors.New("unknown plugin tool (use trivy, semgrep, codeql, zap or generic)")
	ErrUnknownFormat = errors.New("unknown report format (use sarif or trivy_json)")
	// ErrReportTooBig: the report is over MaxReportSize or MaxResults: the
	// run fails rather than close the findings past the cap.
	ErrReportTooBig = errors.New("the report is too big for Michel")
	// ErrBadReport: the report cannot be read as SARIF or Trivy JSON.
	ErrBadReport = errors.New("the report is not a SARIF or Trivy JSON file Michel can read")
)

// MaxReportSize is the most bytes Michel reads of a report (a variable for
// the tests).
var MaxReportSize int64 = 50 << 20

// MaxResults is the most results Michel reads from one report (a variable
// for the tests).
var MaxResults = 10000

// ExternalFinding is one result of a tool's report. Location is a
// slash-separated path relative to the project, with ":line" when known.
type ExternalFinding struct {
	RuleID, Message, Location, Fingerprint, Severity string
	CVSS                                             float64
	Kind                                             string
	Aliases                                          []string
}

// ExecFunc runs a program and returns what it wrote (each capped at
// maxOutput).
type ExecFunc func(ctx context.Context, name string, args, env []string, dir string) (stdout, stderr []byte, err error)

// Provider is one plugin tool.
type Provider interface {
	Key() string
	Tool() string
	// Kind is the kind of the findings it reports, unless a result says
	// otherwise (ExternalFinding.Kind).
	Kind() string
	// Detect tells whether the tool is installed and its version.
	Detect(ctx context.Context) (installed bool, version string)
	// Run runs the tool on the project, writing its report under outDir
	// (the tool's folder in the data folder, never in the project), and
	// returns the report path. ErrNotRunnable for codeql, zap and generic.
	Run(ctx context.Context, p project.Project, outDir string, env []string) (reportPath string, err error)
	// Ingest reads a report produced for p.
	Ingest(ctx context.Context, reportPath string, p project.Project) ([]ExternalFinding, error)
}

// tool is every Provider: what differs is its kind and how it runs.
type tool struct {
	key, name, kind, format string
	// args builds the command line, nil when Michel does not run the tool.
	args func(outDir, report string, p project.Project) ([]string, error)
	exec ExecFunc
	// detectEnv is the environment of "<tool> --version".
	detectEnv []string
	// dir is the tool's folder in the data folder, the working folder of
	// "<tool> --version" (never the project); "" for the current folder.
	dir string
	// argv is the command line of the last Run, for its hash in the audit;
	// output is what it wrote (stdout then stderr, capped), for the run log.
	argv   []string
	output []byte
}

func (t *tool) Key() string  { return t.key }
func (t *tool) Tool() string { return t.name }
func (t *tool) Kind() string { return t.kind }

var versionPattern = regexp.MustCompile(`\d+\.\d+[0-9A-Za-z.+\-]*`)

// Detect runs "<tool> --version" (10 s at most) through the PATH.
func (t *tool) Detect(ctx context.Context) (bool, string) {
	if t.args == nil {
		return false, ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, _, err := t.exec(ctx, t.name, []string{"--version"}, t.detectEnv, t.dir)
	if errors.Is(err, exec.ErrNotFound) {
		return false, ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	v := versionPattern.FindString(line)
	if v == "" {
		v = strings.TrimSpace(line)
	}
	if len(v) > 64 {
		v = v[:64]
	}
	return true, scan.SanitizeText(v)
}

// Run creates outDir/reports and runs the tool from outDir.
func (t *tool) Run(ctx context.Context, p project.Project, outDir string, env []string) (string, error) {
	if t.args == nil {
		return "", ErrNotRunnable
	}
	reports := filepath.Join(outDir, "reports")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		return "", fmt.Errorf("cannot prepare the tool's folder: %w", noPath(err))
	}
	report := filepath.Join(reports, time.Now().UTC().Format("20060102T150405.000000000")+".sarif")
	args, err := t.args(outDir, report, p)
	if err != nil {
		return "", err
	}
	t.argv = append([]string{t.name}, args...)
	stdout, stderr, err := t.exec(ctx, t.name, args, env, outDir)
	t.output = combined(stdout, stderr)
	if err != nil {
		return "", &RunError{Err: err}
	}
	return report, nil
}

// RunError is a tool that failed. Its message never carries what the tool
// wrote: that only goes to the local run log.
type RunError struct{ Err error }

func (e *RunError) Error() string {
	var ee *exec.ExitError
	if errors.As(e.Err, &ee) {
		return fmt.Sprintf("the tool stopped with exit code %d", ee.ExitCode())
	}
	if errors.Is(e.Err, context.DeadlineExceeded) {
		return "the tool took too long and was stopped"
	}
	return "the tool failed: " + noPath(e.Err).Error()
}

func (e *RunError) Unwrap() error { return e.Err }

// Ingest reads the report, at most MaxReportSize, as SARIF or Trivy JSON
// (from its content; a report of Michel's own run is SARIF).
func (t *tool) Ingest(ctx context.Context, reportPath string, p project.Project) ([]ExternalFinding, error) {
	f, err := os.Open(reportPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read the report: %w", noPath(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxReportSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the report: %w", noPath(err))
	}
	if int64(len(b)) > MaxReportSize {
		return nil, ErrReportTooBig
	}
	var out []ExternalFinding
	switch formatOf(b, t.format) {
	case FormatTrivyJSON:
		out, _, err = ParseTrivyJSON(bytes.NewReader(b), nil)
	default:
		out, err = ParseSARIF(bytes.NewReader(b), p.Path)
	}
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Kind == "" {
			out[i].Kind = t.kind
		}
	}
	return out, nil
}

// formatOf tells a SARIF report (top-level "runs") from a Trivy JSON one
// ("Results" or "SchemaVersion"); otherwise the configured format.
func formatOf(b []byte, configured string) string {
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) == nil {
		if _, ok := top["runs"]; ok {
			return FormatSARIF
		}
		_, results := top["Results"]
		_, schema := top["SchemaVersion"]
		if results || schema {
			return FormatTrivyJSON
		}
	}
	return configured
}

// ForEntry builds the provider of a plugin entry from its settings tool and
// format. A provider built here detects and runs the tool with no network:
// RunPlugin builds its own, fenced by the deny proxy.
func ForEntry(e source.Entry) (Provider, error) {
	t, err := forEntry(e, defaultExec, toolEnv("127.0.0.1:9", ""))
	if err != nil {
		return nil, err
	}
	return t, nil
}

func forEntry(e source.Entry, run ExecFunc, env []string) (*tool, error) {
	if e.Kind != source.KindPlugin {
		return nil, fmt.Errorf("%s is not a plugin source", e.Key)
	}
	format := e.Config.Str("format")
	if format == "" {
		format = FormatSARIF
	}
	if format != FormatSARIF && format != FormatTrivyJSON {
		return nil, fmt.Errorf("%s: %w", e.Key, ErrUnknownFormat)
	}
	t := &tool{key: e.Key, name: e.Config.Str("tool"), format: format, exec: run, detectEnv: env}
	switch t.name {
	case "trivy":
		t.kind, t.args = KindMisconfig, trivyRun
	case "semgrep":
		t.kind, t.args = KindCode, semgrepRun
	default:
		kind, ok := readOnlyTools[t.name]
		if !ok {
			return nil, fmt.Errorf("%s: %w", e.Key, ErrUnknownTool)
		}
		t.kind = kind
	}
	return t, nil
}

// maxOutput caps what Michel keeps of a tool's stdout and stderr.
const maxOutput = 64 << 10

// capped keeps the first max bytes written to it and drops the rest.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// defaultExec runs name with exactly env (never Michel's own environment),
// from dir, stdout and stderr capped at maxOutput.
func defaultExec(ctx context.Context, name string, args, env []string, dir string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{}, env...) // never nil: nil would pass Michel's environment
	cmd.Stdin = nil
	out, errOut := &capped{max: maxOutput}, &capped{max: maxOutput}
	cmd.Stdout, cmd.Stderr = out, errOut
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	return out.buf.Bytes(), errOut.buf.Bytes(), err
}

// toolEnv is the whole environment of a tool: the few variables a program
// needs to start (PATH, SystemRoot, TEMP/TMP), HOME and USERPROFILE set to
// home (the tool keeps its settings and logs there, in the data folder; left
// out when home is ""), the proxy at proxyAddr for every scheme, and the
// switches that keep Trivy and Semgrep offline. No secret, token or other
// variable of Michel's reaches it.
func toolEnv(proxyAddr, home string) []string {
	var env []string
	for _, k := range []string{"PATH", "SystemRoot", "TEMP", "TMP"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	if home != "" {
		env = append(env, "HOME="+home, "USERPROFILE="+home)
	}
	proxy := "http://" + proxyAddr
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env = append(env, k+"="+proxy)
	}
	return append(env, "NO_PROXY=", "no_proxy=", "TRIVY_SKIP_DB_UPDATE=true", "SEMGREP_SEND_METRICS=off")
}

// noPath drops the file path of a file system error: report and data paths
// never reach a message.
func noPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}

// combined is what a tool wrote, stdout then stderr, for the local run log:
// sanitized and capped at maxOutput bytes in all.
func combined(stdout, stderr []byte) []byte {
	var b bytes.Buffer
	if len(stdout) > 0 {
		b.WriteString("stdout:\n")
		b.Write(stdout)
		b.WriteString("\n")
	}
	if len(stderr) > 0 {
		b.WriteString("stderr:\n")
		b.Write(stderr)
		b.WriteString("\n")
	}
	s := scan.SanitizeText(strings.ToValidUTF8(b.String(), "�"))
	if len(s) > maxOutput {
		s = strings.ToValidUTF8(s[:maxOutput], "")
	}
	return []byte(s)
}
