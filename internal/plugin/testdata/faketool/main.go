// Command faketool stands for trivy or semgrep in the plugin tests. It prints
// a version, tries to reach ghcr.io through the proxy it is given (the deny
// proxy must refuse it), checks that no variable outside the allowlist
// reached it, and writes a SARIF report to --output. It never writes in the
// project it is pointed at.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const report = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake","rules":[
{"id":"fake.rule","defaultConfiguration":{"level":"error"}}]}},"results":[
{"ruleId":"fake.rule","message":{"text":"Fake problem."},
"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.php"},"region":{"startLine":3}}}],
"partialFingerprints":{"primaryLocationLineHash":"feedface:1"}}]}]}`

const cleanReport = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake","rules":[]}},"results":[]}]}`

func main() {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println("Version: 0.99.0-fake")
		return
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(strings.ToUpper(kv), "MICHEL_CANARY=") {
			fmt.Fprintln(os.Stderr, "a variable outside the allowlist reached the tool")
			os.Exit(7)
		}
	}
	out := ""
	for i, a := range args {
		if a == "--output" && i+1 < len(args) {
			out = args[i+1]
		}
	}
	if out == "" {
		fmt.Fprintln(os.Stderr, "no --output")
		os.Exit(2)
	}
	// Goes through HTTPS_PROXY (the default transport reads it).
	c := &http.Client{Timeout: 10 * time.Second}
	if resp, err := c.Get("https://ghcr.io/"); err == nil {
		resp.Body.Close()
		fmt.Fprintln(os.Stderr, "the network was reachable")
		os.Exit(3)
	}
	fmt.Println("home=" + os.Getenv("HOME"))
	result := report
	// Like a real tool, it reads the project it is pointed at: a test decides
	// what it sees through src/app.php.
	for _, a := range args {
		code, err := os.ReadFile(filepath.Join(a, "src", "app.php"))
		if err != nil {
			continue
		}
		if strings.Contains(string(code), "FAKE-TOOL-FAILS") {
			fmt.Fprintln(os.Stderr, "the tool failed")
			os.Exit(5)
		}
		if strings.Contains(string(code), "FAKE-FLAW-FIXED") {
			result = cleanReport
		}
	}
	if err := os.WriteFile(out, []byte(result), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
}
