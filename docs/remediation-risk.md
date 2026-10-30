# Remediation risk score

Lire en français : [remediation-risk.fr.md](remediation-risk.fr.md)

Michel gives every finding a risk score from 0 to 100 and a recommendation. The rule is public, deterministic and the same on every run: the same evidence always gives the same score.

**The AI model can never change these values.** The model may explain a score, but the score, its terms and the thresholds come only from the policy file and the project settings.

## Terms

Each term adds points when its condition is true. The points are summed and capped at 100.

| Term | Points | Condition |
| --- | --- | --- |
| `major_jump` | +40 | The fix needs a major version jump. |
| `breaking` | +25 | The changelog announces breaking changes. A changelog without readable version headings is not assessed: it adds 0, and the explanation says so. |
| `direct` | +10 | The package is a direct dependency of the project. |
| `many_call_sites` | +15 | The code calls the package in more places than `many_call_sites_threshold` (10, strictly more). |
| `no_tests` | +20 | No test uses the package itself. Only a covering test that imports or calls the package (method `callsite`) cancels this term; a test that merely mentions the name of a file using the package (method `reference`) is weak evidence and does not. |
| `core_package` | +20 | The package is listed as a core package of the project. |

When the size of the jump cannot be determined (`unknown`), `major_jump` adds 0 and the analysis records `major_jump_unknown: 0`, so the gap is visible instead of silently counted as safe. An unknown jump is also never an automatic fix: whatever the score, the recommendation is `handoff` (or `report_only` without a fixed version), and the analysis records `jump_unknown_handoff: 1`. This flag, like `thresholds_fallback`, is not points: the score is unchanged.

## Exploited in the wild: urgency, not points

KEV does not change the score: it marks the urgency. When a finding is on CISA's list of vulnerabilities exploited in the wild (KEV), or the package itself is malicious, the analysis records the flag `exploited: 1` (always present, at 0 otherwise) and `urgency: urgent`. Like `jump_unknown_handoff`, this flag adds no points. The score measures the risk of the *fix* (how likely the update is to break something); a flaw being exploited makes the fix more urgent, not riskier. Adding points would also make `auto_fix` rarer for exactly the flaws that need fixing first.

What the urgency changes: the explanation says "Fix this first", the finding is listed first (`michel findings`, the API), and the digest lists it at the top, under "Exploited in the wild", every day until it is fixed or deferred or ignored with a decision. The EPSS score (FIRST's probability of exploitation within 30 days) is shown in the explanation from the 50th percentile; it changes neither the score nor the urgency.

## Thresholds

| Score | Recommendation |
| --- | --- |
| below 30 (`auto_fix_below`) | `auto_fix` |
| 30 to 60 inclusive (`handoff_up_to`) | `handoff` |
| above 60 | `handoff`, with a warning |

When no fixed version exists, the recommendation is `report_only`. The score is still computed and shown, and the warning can still appear with `report_only` when the score is above 60.

A project override that would make the thresholds inconsistent (`auto_fix_below` not below `handoff_up_to`) is refused by `project set`; if one is ever stored anyway, scoring falls back to the policy thresholds and records `thresholds_fallback: 1`.

## Where the values live

Defaults are in the `risk` section of the policy file (see `config.example.yaml`):

```yaml
risk:
  major_jump: 40
  breaking: 25
  direct: 10
  many_call_sites: 15
  no_tests: 20
  core_package: 20
  many_call_sites_threshold: 10
  auto_fix_below: 30
  handoff_up_to: 60
```

Each term must be between 0 and 100, `many_call_sites_threshold` at least 1, and `0 <= auto_fix_below < handoff_up_to <= 100`. An invalid policy is refused at startup.

## Per-project settings

A project can mark its core packages and override any value above (the keys are the names in the table and in the YAML):

```
michel project set my-shop --core-package symfony/http-kernel --core-package react
michel project set my-shop --risk major_jump=10 --risk no_tests=30
```

`--core-package` replaces the whole list; `--risk` changes one value and keeps the other overrides. Stored analyses remember a fingerprint of these settings (and of the policy values): after a change they are recomputed on the next scan or `michel analyze --project my-shop`. Unknown keys and values outside 0..100 are refused. Each change is recorded in the audit log as `project.set` (field names only, never command contents).
