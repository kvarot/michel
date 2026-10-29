package plugin

// readOnlyTools are the tools Michel never runs, with the kind of their
// findings: CodeQL needs a database build, ZAP a running site, and a generic
// plugin is any tool that writes SARIF. Their provider has no command line:
// Run returns ErrNotRunnable and Ingest reads the report the user produced.
var readOnlyTools = map[string]string{
	"codeql":  KindCode,
	"zap":     KindWeb,
	"generic": KindCode,
}
