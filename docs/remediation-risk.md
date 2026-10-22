# Remediation risk score

Lire en français : [remediation-risk.fr.md](remediation-risk.fr.md)

Michel gives every finding a risk score from 0 to 100 and a recommendation. The rule is public, deterministic and the same on every run: the same evidence always gives the same score.

**The AI model can never change these values.** The model may explain a score, but the score, its terms and the thresholds come only from the policy file and the project settings.

## Terms

Each term adds points when its condition is true. The points are summed and capped at 100.

| Term | Points | Condition |
| --- | --- | --- |
| `major_jump` | +40 | The fix needs a major version jump. |
| `breaking` | +25 | The changelog announces breaking changes. |
| `direct` | +10 | The package is a direct dependency of the project. |
| `many_call_sites` | +15 | The code calls the package in more places than `many_call_sites_threshold` (10, strictly more). |
| `no_tests` | +20 | No test touches the package. |
| `core_package` | +20 | The package is listed as a core package of the project. |

When the size of the jump cannot be determined (`unknown`), `major_jump` adds 0 and the analysis records `major_jump_unknown: 0`, so the gap is visible instead of silently counted as safe.

## Thresholds

| Score | Recommendation |
| --- | --- |
| below 30 (`auto_fix_below`) | `auto_fix` |
| 30 to 60 inclusive (`handoff_up_to`) | `handoff` |
| above 60 | `handoff`, with a warning |

When no fixed version exists, the recommendation is `report_only`. The score is still computed and shown.

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

`--core-package` replaces the whole list; `--risk` changes one value and keeps the other overrides. Unknown keys and values outside 0..100 are refused. Each change is recorded in the audit log as `project.set` (field names only, never command contents).
