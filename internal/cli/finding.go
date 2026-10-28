package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

const (
	maxCallSitesShown = 10
	maxChangelogLines = 20
	maxAmbiguousShown = 10
	maxBreakingShown  = 5
)

func explainLang(deps *Deps) explain.Lang {
	if deps.Lang == explain.FR {
		return explain.FR
	}
	return explain.EN
}

// resolveFinding finds one finding by exact id, then by unique id prefix,
// across all projects.
func resolveFinding(ctx context.Context, deps *Deps, idOrPrefix string) (scan.Finding, project.Project, error) {
	idOrPrefix = strings.TrimSpace(idOrPrefix)
	list, err := scan.NewRepo(deps.Store).FindByIDPrefix(ctx, idOrPrefix)
	if err != nil {
		return scan.Finding{}, project.Project{}, err
	}
	if len(list) == 0 {
		return scan.Finding{}, project.Project{}, deps.Errorf("cli.finding.not_found", idOrPrefix)
	}
	pick := list
	for _, f := range list {
		if f.ID == idOrPrefix {
			pick = []scan.Finding{f}
			break
		}
	}
	names := map[string]string{}
	projects, err := projectRepo(deps).List(ctx)
	if err != nil {
		return scan.Finding{}, project.Project{}, err
	}
	byID := map[string]project.Project{}
	for _, p := range projects {
		names[p.ID], byID[p.ID] = p.Name, p
	}
	if len(pick) > 1 {
		return scan.Finding{}, project.Project{}, errors.New(ambiguousPrefixMessageIn(deps.Lang, idOrPrefix, pick, names))
	}
	return pick[0], byID[pick[0].ProjectID], nil
}

// ambiguousPrefixMessage is ambiguousPrefixMessageIn in English.
func ambiguousPrefixMessage(prefix string, pick []scan.Finding, names map[string]string) string {
	return ambiguousPrefixMessageIn(i18n.EN, prefix, pick, names)
}

// ambiguousPrefixMessageIn lists the candidates of an id prefix in lang. The
// lookup stops at scan.MaxPrefixMatches, so a full result says "at least".
func ambiguousPrefixMessageIn(lang i18n.Lang, prefix string, pick []scan.Finding, names map[string]string) string {
	var sb strings.Builder
	capped := len(pick) >= scan.MaxPrefixMatches
	if capped {
		sb.WriteString(i18n.T(lang, "cli.finding.ambiguous_capped", prefix, scan.MaxPrefixMatches))
	} else {
		sb.WriteString(i18n.T(lang, "cli.finding.ambiguous", prefix, len(pick)))
	}
	for i, f := range pick {
		if i == maxAmbiguousShown {
			if capped {
				sb.WriteString("\n  " + i18n.T(lang, "cli.finding.ambiguous_more_capped"))
			} else {
				sb.WriteString("\n  " + i18n.T(lang, "cli.finding.ambiguous_more", len(pick)-maxAmbiguousShown))
			}
			break
		}
		sb.WriteString("\n  " + i18n.T(lang, "cli.finding.ambiguous_candidate", f.ID, safe(f.Package), safe(f.InstalledVersion), safe(f.OSVID), names[f.ProjectID]))
	}
	return sb.String()
}

// loadFacts reads the stored analysis of a finding and builds its facts, with
// the fix level of its project.
func loadFacts(ctx context.Context, deps *Deps, p project.Project, f scan.Finding) (analyze.Analysis, bool, explain.Facts, error) {
	a, ok, err := analyze.NewRepo(deps.Store).Get(ctx, f.ID)
	if err != nil {
		return analyze.Analysis{}, false, explain.Facts{}, err
	}
	facts := explain.FactsFrom(f, a, ok)
	facts.FixLevel = p.FixLevel
	return a, ok, facts, nil
}

// safe strips control characters from untrusted text before it is printed.
func safe(s string) string { return scan.SanitizeText(s) }

func newFindingCmd(deps *Deps) *cobra.Command {
	c := &cobra.Command{
		Use:   "finding <id-or-prefix>",
		Short: "Explain one finding in plain language, with the facts behind it",
		Long: "Finding shows one vulnerability: three plain sentences (what it is, how much it matters to you, what fixing it costs) " +
			"and the offline facts behind them. Pass the full id or a unique prefix; 'michel findings' lists them. " +
			"Use --lang fr for French. Run 'michel analyze' first for the complete view.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fi, p, err := resolveFinding(ctx, deps, args[0])
			if err != nil {
				return err
			}
			a, hasA, facts, err := loadFacts(ctx, deps, p, fi)
			if err != nil {
				return err
			}
			lang := explainLang(deps)
			ex, err := explain.Render(lang, facts)
			if err != nil {
				return err
			}
			if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
				doc := struct {
					Finding     scan.Finding        `json:"finding"`
					Analysis    *analyze.Analysis   `json:"analysis"`
					Explanation explain.Explanation `json:"explanation"`
				}{Finding: fi, Explanation: ex}
				if hasA {
					doc.Analysis = &a
				}
				return json.NewEncoder(deps.Stdout).Encode(doc)
			}
			printFinding(deps, lang, fi, p, a, hasA, facts, ex)
			return nil
		},
	}
	return c
}

func printFinding(deps *Deps, lang explain.Lang, fi scan.Finding, p project.Project, a analyze.Analysis, hasA bool, facts explain.Facts, ex explain.Explanation) {
	w := deps.Stdout
	L := func(k string) string { return explain.Label(lang, k) }
	colon := ":"
	if lang == explain.FR {
		colon = " :"
	}
	H := func(k string) string { return L(k) + colon }
	// Package names, versions, ids, paths and changelog text come from
	// outside: facts are already sanitized, the rest goes through safe.
	fmt.Fprintf(w, "%s %s — %s — %s — %s %s — %s\n\n", facts.Package, facts.Installed, safe(facts.SeverityLabel), facts.OSVID, L("project"), p.Name, facts.ManifestRelPath)
	fmt.Fprintf(w, "%s %s\n%s %s\n%s %s\n\n", H("what"), ex.What, H("impact"), ex.Impact, H("cost"), ex.Cost)

	fmt.Fprintf(w, "%s\n", L("facts"))
	fixed := L("none")
	if len(fi.FixedVersions) > 0 {
		fixed = safe(strings.Join(fi.FixedVersions, ", "))
	}
	versions := fmt.Sprintf("%s %s, %s %s", L("installed"), facts.Installed, H("fixed"), fixed)
	if facts.Target != "" {
		versions += fmt.Sprintf(", %s %s (%s)", L("target"), facts.Target, explain.Enum(lang, "jump", string(facts.Jump)))
	}
	fmt.Fprintf(w, "  %s %s\n", H("versions"), versions)
	if fi.KEV {
		// "kev: yes": exploited in the wild, on CISA's list.
		since := L("kev_yes")
		if facts.KEVAdded != "" {
			since = fmt.Sprintf(L("kev_since"), kevDay(lang, facts.KEVAdded))
		}
		fmt.Fprintf(w, "  %s %s\n", H("kev"), since)
	}
	if !hasA {
		fmt.Fprintf(w, "\n"+L("hint")+"\n", p.Name)
		printGlossary(w, lang, facts)
		return
	}
	switch a.Path.Directness {
	case analyze.Direct:
		fmt.Fprintf(w, "  %s %s\n", H("path"), L("direct"))
	case analyze.Transitive:
		fmt.Fprintf(w, "  %s %s %s\n", H("path"), L("transitive"), strings.Join(facts.Via, " > "))
	default:
		fmt.Fprintf(w, "  %s %s\n", H("path"), L("unknown"))
	}
	if facts.Constraint != "" {
		fmt.Fprintf(w, "  %s %s\n", H("constraint"), facts.Constraint)
	}
	fmt.Fprintf(w, "  %s %d (%s)\n", H("calls"), a.Calls.Count, explain.Enum(lang, "quality", a.Calls.Quality))
	for i, s := range a.Calls.Sites {
		if i == maxCallSitesShown {
			fmt.Fprintf(w, "    "+L("more")+"\n", a.Calls.Count-maxCallSitesShown)
			break
		}
		fmt.Fprintf(w, "    %s:%d\n", safe(s.File), s.Line)
	}
	testsLine := explain.TestsLine(lang, a.Coverage.Count)
	if a.Coverage.Count > 0 {
		testsLine += " (" + explain.Enum(lang, "method", a.Coverage.Method) + ")"
	}
	fmt.Fprintf(w, "  %s %s\n", H("tests"), testsLine)
	switch {
	case !a.Changelog.Available:
		fmt.Fprintf(w, "  %s %s\n", H("changelog"), L("nochangelog"))
	case a.Changelog.VersionsUnread():
		fmt.Fprintf(w, "  %s %s, %s\n", H("changelog"), safe(a.Changelog.Source), L("noversions"))
	case a.Changelog.Breaking:
		fmt.Fprintf(w, "  %s %s (%d %s)\n", H("changelog"), safe(a.Changelog.Source), max(len(a.Changelog.BreakingLines), 1), L("breaks"))
	default:
		fmt.Fprintf(w, "  %s %s, %s\n", H("changelog"), safe(a.Changelog.Source), L("nobreak"))
	}
	for i, l := range facts.BreakingLines {
		if i == maxBreakingShown {
			break
		}
		fmt.Fprintf(w, "    ! %s\n", l)
	}
	if a.Changelog.Excerpt != "" {
		lines := strings.Split(strings.TrimRight(a.Changelog.Excerpt, "\r\n"), "\n")
		for i, l := range lines {
			if i == maxChangelogLines {
				fmt.Fprintf(w, "    ...\n")
				break
			}
			fmt.Fprintf(w, "    | %s\n", safe(strings.TrimRight(l, "\r")))
		}
	}
	fmt.Fprintf(w, "  %s %s %d/100, %s %s\n", H("risk"), L("score"), a.Risk.Score, L("recommendation"), explain.Enum(lang, "rec", string(a.Risk.Recommendation)))
	fmt.Fprintf(w, "    %s\n", explain.RiskTerms(lang, a.Risk.Terms))
	if a.Risk.Warning {
		eff, _ := analyze.EffectiveRisk(deps.Policy.Risk, p.RiskOverrides)
		fmt.Fprintf(w, "  %s\n", explain.RiskWarning(lang, eff.HandoffUpTo))
	}
	printGlossary(w, lang, facts)
}

// printGlossary defines only the terms the output used.
func printGlossary(w io.Writer, lang explain.Lang, f explain.Facts) {
	var keys []string
	if f.Directness == analyze.Transitive {
		keys = append(keys, "transitive")
	}
	if f.Breaking || (f.HasAnalysis && f.Target != "" && f.ChangelogAvailable) {
		keys = append(keys, "breaking")
	}
	if len(keys) == 0 {
		return
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, explain.Label(lang, "term_"+k)+" = "+explain.Term(lang, k))
	}
	fmt.Fprintf(w, "\n%s: %s\n", explain.Label(lang, "glossary"), strings.Join(parts, ", "))
}

// kevDay writes a YYYY-MM-DD day in lang's date layout.
func kevDay(lang explain.Lang, day string) string {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return safe(day)
	}
	return t.Format(i18n.T(lang, "digest.date_layout"))
}
