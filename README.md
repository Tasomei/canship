# canship

A local static scanner for JavaScript and TypeScript projects. Detects exposed credentials and access-control misconfigurations without executing project code, uploading files, or making network requests during scans.

```powershell
npx canship .
```

Requires Node.js ≥18; no runtime dependencies. Git is used for local history checks. Unavailable Git in a repository makes the scan incomplete. On first use, `npx` may download the package from npm.

[简体中文](./README-zh-CN.md)

## Checks

| Check | Severity |
|---|---|
| Hardcoded credentials, private keys, and database URLs containing passwords | P0 |
| Private values in public environment variables | P0 |
| Client-accessible Supabase admin keys | P0 |
| Credentials or suspected private values in Git-tracked and historical `.env` files | P0 |
| Supabase tables without Row Level Security (RLS) | P1 |
| Firebase unconditional access and date-based test rules | P1 |
| Next.js API data operations without authentication | P0 / P1 |
| Credentialed CORS with reflected or wildcard origins | P1 / P2 |

Recognises OpenAI, Anthropic, AWS, Stripe, GitHub, npm, Slack, SendGrid, and other credential formats, plus common frontend public environment prefixes. API authentication checks cover Next.js `/api` handlers, including App Router, Pages Router, route groups, and workspace applications.

Confidence is `certain` or `likely`. Only certain findings are shown by default; hidden likely findings still affect the exit code.

## Options

Omitting the path scans the current directory.

| Option | Description |
|---|---|
| `-a`, `--all` | Include likely findings |
| `--json` | Output JSON |
| `--fix-prompt` | Output assistant instructions and separate manual actions |
| `--report[=file]` | Write HTML; default: `canship-report.html` |
| `--sarif[=file]` | Write SARIF 2.1.0; default: `canship.sarif` |
| `--best-effort` | Permit exit `0` for an incomplete scan with no findings |
| `--baseline[=file]` | Apply a baseline; default: `canship-baseline.json` |
| `--baseline-write[=file]` | Record current findings as a baseline and exit |
| `--only=ids` | Run matching rules; comma-separated and repeatable |
| `--skip=ids` | Exclude matching rules; comma-separated and repeatable |
| `--no-config` | Ignore project configuration |
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version |

`--json` and `--fix-prompt` are mutually exclusive. HTML and SARIF may be combined with either. Reports are in English; use `--all` to include likely findings in any format.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings and a complete scan, or an incomplete scan accepted with `--best-effort` |
| `1` | At least one certain P0/P1 finding |
| `2` | Other findings, including hidden likely findings |
| `3` | Invalid arguments, a tool error, or an unaccepted incomplete scan |

Findings take precedence over incompleteness; `--best-effort` does not change `1` or `2`. JSON retains `partial`, `errors`, and `skipped`; SARIF includes execution status and diagnostic notifications.

### JSON contract

JSON includes `schemaVersion: 1`, independent of the package `version`. Consumers should accept additive fields and reject unsupported schema versions. Published 0.2.1 reports omit `schemaVersion`; the Action also accepts that legacy format.

`findings` contains visible results after suppressions. `hiddenLikely`, `baselineSuppressed`, and `baselineStale` retain filtering counts. Check `partial`, `errors`, `skipped`, and `filesScanned` separately from findings and the exit code.

## GitHub Action

Run canship on pushes and pull requests by saving this workflow as `.github/workflows/canship.yml`. It scans the checkout without installing or executing project dependencies and writes a counts-only summary. Installation requires network access; scanning does not. SARIF upload is disabled by default.

The example pins the Action to a tested commit and installs the published scanner `0.2.1`. `version` selects the npm package; unreleased source changes are not included.

```yaml
name: canship
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Tasomei/canship@f10ba0d2d08d79ee354907fff0c0f646995b8c1f
        with:
          version: '0.2.1'
```

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory within the checkout |
| `version` | `0.2.1` | Exact npm version; no ranges or tags |
| `fail-on` | `blocking` | `blocking`: certain P0/P1; `any`: all findings; `none`: findings only reported |
| `only` / `skip` | unset | Mutually exclusive, comma-separated rule selectors |
| `baseline` | unset | Existing baseline relative to the scanned directory |
| `use-config` | `false` | Enable project configuration |
| `upload-sarif` | `false` | Upload SARIF to GitHub code scanning |
| `category` | `canship` | Distinct SARIF category for each scan target |

Incomplete scans, tool errors, and incompatible reports always fail, including with `fail-on: none`. Outputs: `exit-code`, `findings`, `blocking`, `partial`. All confidence levels participate in the selected policy. Baselines, source ignore markers, and built-in exclusions still apply; review them as part of the scan scope.

SARIF upload requires `security-events: write` and a repository eligible for [GitHub code scanning](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file). Fork pull requests may lack upload permission. Reports disclose paths and finding details; review disclosure risks before enabling upload. Use `pull_request`, not `pull_request_target`, for untrusted contributions. The Action sets Node.js 22 for subsequent steps; use a separate scan job if the project needs another runtime.

## Configuration and suppressions

Place `canship.config.json` in the scanned directory. Supported keys: `baseline`, `only`, `skip`, `all`.

```json
{
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

CLI options take precedence. `only` and `skip` are mutually exclusive and accept complete rule IDs or namespaces. Unrelated rules do not run; `ruleSelection.removed` counts only filtered findings from rules that ran. Use `--no-config` for untrusted projects. `bestEffort` is CLI-only.

A standalone comment containing `canship-ignore-file` excludes a file. `canship-ignore-next-line` suppresses the next line and accepts an optional rule ID:

```ts
// canship-ignore-next-line cors/wildcard-with-credentials
const corsOptions = { origin: '*', credentials: true }
```

Reports disclose exclusions, rule selection, and baseline suppression. Deliberate exclusions do not make the scan incomplete.

## Baselines

Record existing findings:

```powershell
npx canship --baseline-write
```

Report only new findings:

```powershell
npx canship --baseline
```

Bare options use the scanned directory; explicit paths are relative to the working directory. A successful write exits `0`, with a warning for incomplete or selectively scanned input.

Baseline format v2 contains no source excerpts but discloses paths, rules, titles, and issue types. Review it before committing. Fingerprints exclude line numbers: moving lines preserves identity, replacing credentials changes it. Missing, malformed, and v1 baselines exit `3`.

## Limitations

- Static heuristics may produce false positives or negatives. Runtime behaviour, rate limiting, injection, dependency vulnerabilities, and business authorisation are outside scope. No findings does not prove security.
- Redaction covers recognised formats only; unknown secrets may appear in evidence. Treat reports as internal material. Google/Firebase/Maps `AIza...` values are treated as public identifiers.
- Reads are limited to 2 MiB per file, 128 MiB and 10,000 files per scan, and 16 directory levels. Across rules, at most 100 findings per file are reported, prioritising severity and confidence.
- Git history checks cover up to 100 relevant revisions per file. Each Git command has a 30-second timeout. Exceeded limits and timeouts are reported as incomplete coverage.
- Symbolic links are not followed. Scan nested repositories and submodules separately. Skipped paths within scope make the scan incomplete; excluded build and dependency directories remain excluded.

## Development

Detection rules require positive and negative cases; see [test fixtures](./test/fixtures/).

```powershell
npm ci
```

```powershell
npm run prepublishOnly
```

Run the offline starter evaluation:

```powershell
npm run evaluate
```

The 12 cases cover cross-file API authentication, workspace routing, RLS migration replay, Firebase rules, CORS, and incomplete scans. Ten are synthetic; two use one adapted Supabase migration, with a pinned revision and licence under `test/fixtures/evaluation/`. Results compare rule, file, severity, confidence, and coverage, reporting missing and unexpected findings. This is a regression corpus, not a real-world accuracy estimate. Cases also run in `npm test`.

## License

[MIT](./LICENSE). The Supabase test fixture retains its [Apache-2.0 licence](./test/fixtures/evaluation/supabase-profiles/LICENSE).
