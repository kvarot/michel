package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/explain"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/spf13/cobra"
)

const (
	maxCallSitesShown   = 10
	maxChangelogLines   = 20
	maxAmbiguousShown   = 10
	maxBreakingShown    = 5
	findingNotFoundHelp = "Run 'michel findings --project <name>' to see the ids."
)

func explainLang(deps *Deps) explain.Lang {
	if deps.Lang == "fr" {
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
		return scan.Finding{}, project.Project{}, fmt.Errorf("No finding has the id %q. %s", idOrPrefix, findingNotFoundHelp)
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
		var sb strings.Builder
		fmt.Fprintf(&sb, "The id prefix %q matches %d findings. Type more characters of the id. Candidates:", idOrPrefix, len(pick))
		for i, f := range pick {
			if i == maxAmbiguousShown {
				fmt.Fprintf(&sb, "\n  ... and %d more", len(pick)-maxAmbiguousShown)
				break
			}
			fmt.Fprintf(&sb, "\n  %s  %s %s (%s) in project %s", f.ID, f.Package, f.InstalledVersion, f.OSVID, names[f.ProjectID])
		}
		return scan.Finding{}, project.Project{}, errors.New(sb.String())
	}
	return pick[0], byID[pick[0].ProjectID], nil
}

// loadFacts reads the stored analysis of a finding and builds its facts.
func loadFacts(ctx context.Context, deps *Deps, f scan.Finding) (analyze.Analysis, bool, explain.Facts, error) {
	a, ok, err := analyze.NewRepo(deps.Store).Get(ctx, f.ID)
	if err != nil {
		return analyze.Analysis{}, false, explain.Facts{}, err
	}
	return a, ok, explain.FactsFrom(f, a, ok), nil
}

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
			a, hasA, facts, err := loadFacts(ctx, deps, fi)
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
	fmt.Fprintf(w, "%s %s — %s — %s — %s %s — %s\n\n", fi.Package, fi.InstalledVersion, fi.SeverityLabel, fi.OSVID, L("project"), p.Name, fi.ManifestRelPath)
	fmt.Fprintf(w, "%s: %s\n%s: %s\n%s: %s\n\n", L("what"), ex.What, L("impact"), ex.Impact, L("cost"), ex.Cost)

	fmt.Fprintf(w, "%s\n", L("facts"))
	fixed := L("none")
	if len(fi.FixedVersions) > 0 {
		fixed = strings.Join(fi.FixedVersions, ", ")
	}
	versions := fmt.Sprintf("%s %s, %s %s", L("installed"), fi.InstalledVersion, L("fixed"), fixed)
	if facts.Target != "" {
		versions += fmt.Sprintf(", %s %s (%s)", L("target"), facts.Target, facts.Jump)
	}
	fmt.Fprintf(w, "  %s: %s\n", L("versions"), versions)
	if !hasA {
		fmt.Fprintf(w, "\n"+L("hint")+"\n", p.Name)
		printGlossary(w, lang, facts)
		return
	}
	switch a.Path.Directness {
	case analyze.Direct:
		fmt.Fprintf(w, "  %s: %s\n", L("path"), L("direct"))
	case analyze.Transitive:
		fmt.Fprintf(w, "  %s: %s %s\n", L("path"), L("transitive"), strings.Join(a.Path.Via, " > "))
	default:
		fmt.Fprintf(w, "  %s: %s\n", L("path"), L("unknown"))
	}
	if a.Path.Constraint != "" {
		fmt.Fprintf(w, "  %s: %s\n", L("constraint"), a.Path.Constraint)
	}
	fmt.Fprintf(w, "  %s: %d (%s)\n", L("calls"), a.Calls.Count, orDash(a.Calls.Quality))
	for i, s := range a.Calls.Sites {
		if i == maxCallSitesShown {
			fmt.Fprintf(w, "    "+L("more")+"\n", a.Calls.Count-maxCallSitesShown)
			break
		}
		fmt.Fprintf(w, "    %s:%d\n", s.File, s.Line)
	}
	fmt.Fprintf(w, "  %s: %d %s (%s)\n", L("tests"), a.Coverage.Count, L("covering"), orDash(a.Coverage.Method))
	switch {
	case !a.Changelog.Available:
		fmt.Fprintf(w, "  %s: %s\n", L("changelog"), L("nochangelog"))
	case a.Changelog.Breaking:
		fmt.Fprintf(w, "  %s: %s (%d %s)\n", L("changelog"), a.Changelog.Source, max(len(a.Changelog.BreakingLines), 1), L("breaks"))
	default:
		fmt.Fprintf(w, "  %s: %s, %s\n", L("changelog"), a.Changelog.Source, L("nobreak"))
	}
	for i, l := range a.Changelog.BreakingLines {
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
			fmt.Fprintf(w, "    | %s\n", strings.TrimRight(l, "\r"))
		}
	}
	terms := make([]string, 0, len(a.Risk.Terms))
	for _, k := range slices.Sorted(maps.Keys(a.Risk.Terms)) {
		if a.Risk.Terms[k] != 0 {
			terms = append(terms, fmt.Sprintf("%s +%d", k, a.Risk.Terms[k]))
		}
	}
	fmt.Fprintf(w, "  %s: %s %d/100, %s %s", L("risk"), L("score"), a.Risk.Score, L("recommendation"), a.Risk.Recommendation)
	if len(terms) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(terms, ", "))
	}
	fmt.Fprintln(w)
	printGlossary(w, lang, facts)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// printGlossary defines only the terms the output used.
func printGlossary(w interface{ Write([]byte) (int, error) }, lang explain.Lang, f explain.Facts) {
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
