# canship

A local static scanner for JavaScript and TypeScript projects. Detects exposed credentials and access-control misconfigurations. Scans do not execute project code, upload files, or use the network.

This documentation covers 0.3.x: use a matching [npm version](https://www.npmjs.com/package/canship) or local build.

```powershell
npx canship .
```

Requires Node.js ≥18; no runtime dependencies. `npx` may download the package; scans use only local files and Git history. Unavailable Git in a repository marks the scan incomplete.

[简体中文](./README-zh-CN.md)

## Checks

| Check | Severity |
|---|---|
| Hardcoded credentials, private keys, and database URLs containing passwords | P0 |
| Private values in public environment variables | P0 |
| Supabase admin keys exposed to clients | P0 |
| Credentials or suspected private values in Git-tracked and historical `.env` files | P0 |
| Supabase tables without Row Level Security (RLS) in migrations | P1 |
| Firebase unconditional access and date-based test rules | P1 |
| Next.js API data operations without recognised authentication | P0 / P1 |
| Credentialed CORS with reflected or wildcard origins | P1 / P2 |

Supports OpenAI, Anthropic, AWS, Stripe, GitHub, npm, Slack, SendGrid, and other credential formats, plus common frontend public environment prefixes. API authentication checks cover only Next.js `/api`: App Router, Pages Router, route groups, and workspace applications.

Confidence is `certain` or `likely`, describing static evidence rather than credential validity or deployed state. Only certain findings are shown by default; hidden likely findings still affect the exit code.

## Usage

Omitting the path scans the current directory.

| Option | Description |
|---|---|
| `-a`, `--all` | Include likely findings |
| `--json` | Output JSON |
| `--fix-prompt` | Output remediation instructions and separate manual actions |
| `--report[=file]` | Write HTML; default: `canship-report.html` |
| `--sarif[=file]` | Write SARIF 2.1.0; default: `canship.sarif` |
| `--best-effort` | Permit exit `0` for an incomplete scan with no findings |
| `--baseline[=file]` | Apply a baseline; default: `canship-baseline.json` |
| `--baseline-write[=file]` | Write current findings as a baseline and exit; same default path |
| `--only=ids` | Run matching rules; comma-separated and repeatable |
| `--skip=ids` | Exclude matching rules; comma-separated and repeatable |
| `--no-config` | Ignore project configuration |
| `--no-ignore-markers` | Disregard ignore markers in scanned source |
| `--list-rules` | List rules and limits without scanning; supports `--json` |
| `--no-excerpts` | Omit source excerpts from every report; preserve findings and exit status |
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version |

`--json` and `--fix-prompt` are mutually exclusive; HTML and SARIF work with either. Reports are in English. `--all` applies to every format.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings, with a complete scan or an incomplete scan accepted by `--best-effort` |
| `1` | At least one certain P0/P1 finding |
| `2` | Other findings, including hidden likely findings |
| `3` | Invalid arguments, a tool error, or an unaccepted incomplete scan |

Finding exit codes take precedence over incompleteness; `--best-effort` does not change `1` or `2`.

### Machine-readable output

JSON uses `schemaVersion: 1`, independent of the package version; the npm package includes its [schema](./schemas/scan-report-v1.schema.json). Accept additive fields and reject unsupported schema versions. `--list-rules --json` is a separate `kind: "rule-catalog"` document.

`findings` contains results after suppressions and filtering; `hiddenLikely`, `baselineSuppressed`, and `baselineStale` provide related counts. Check coverage separately through `partial`, `errors`, `skipped`, and `filesScanned`. SARIF includes execution status and diagnostic notifications.

## GitHub Action

Save as `.github/workflows/canship.yml` to scan on pushes and pull requests, with a counts-only summary. Scanner installation requires network access; scanning does not. Project dependencies are not installed or executed, and SARIF upload is disabled by default.

The example pins the Action commit and explicitly installs npm version `0.3.0`; `version` does not use unreleased repository source. The Action accepts 0.2.1 reports without `schemaVersion`.

```yaml
name: canship
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Tasomei/canship@8b1a3aa88c77e92e2806b343af6003372855bc70
        with:
          version: '0.3.0'
```

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory within the checkout |
| `version` | `0.3.0` | Exact npm version; no ranges or tags |
| `fail-on` | `blocking` | `blocking`: certain P0/P1; `any`: all findings; `none`: findings only reported |
| `only` / `skip` | unset | Mutually exclusive, comma-separated rule selectors |
| `baseline` | unset | Existing baseline relative to the scanned directory |
| `use-config` | `false` | Enable project configuration |
| `upload-sarif` | `false` | Upload SARIF to GitHub code scanning |
| `category` | `canship` | Distinct SARIF category for each scan target |

Outputs: `exit-code`, `findings`, `blocking`, `partial`. Policies include likely findings; baselines and exclusions still apply. Incomplete scans, tool errors, and incompatible reports always fail, including with `fail-on: none`.

SARIF upload requires `security-events: write` and [GitHub code scanning support](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file); fork PRs may lack permission. Review paths and finding details before upload. Use `pull_request`, not `pull_request_target`, for untrusted PRs. The Action sets Node.js 22 for subsequent steps; use a separate scan job if another version is needed.

## Configuration and baselines

Place `canship.config.json` in the scanned directory. Supported keys: `baseline`, `only`, `skip`, `all`.

```json
{
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

CLI options take precedence. `only` and `skip` are mutually exclusive and accept rule IDs or namespaces. Unselected rules do not run; `ruleSelection.removed` counts filtered findings only from executed rules. For untrusted projects use `--no-config --no-ignore-markers`; the scanned project controls both. `bestEffort` is CLI-only.

### Ignore markers

A standalone `canship-ignore-file` comment excludes a file; `canship-ignore-next-line` suppresses the next line, with an optional rule ID:

```ts
// canship-ignore-next-line cors/wildcard-with-credentials
const corsOptions = { origin: '*', credentials: true }
```

Reports disclose exclusions, rule selection, and baseline suppression. Deliberate exclusions do not mark the scan incomplete. Markers can lower the exit code to `0`; `--no-config` does not affect them, `--no-ignore-markers` disables both kinds.

### Baselines

Record existing findings:

```powershell
npx canship --baseline-write
```

Report only new findings:

```powershell
npx canship --baseline
```

The default baseline is in the scanned directory; explicit paths are relative to the working directory. A successful write exits `0`, regardless of findings; incomplete or selectively scanned input produces a warning.

Baseline format v2 fingerprints survive line moves but change when credentials change. Missing, malformed, and v1 baselines exit `3`. Baselines omit source but retain paths, rules, and issue descriptions; review before committing.

## Privacy and limitations

- Static analysis may produce false positives or negatives. Deployed behaviour, rate limiting, injection, dependency vulnerabilities, and business authorisation are outside scope. No findings does not prove security.
- Redaction covers recognised formats only; unknown secrets may appear in source excerpts. `--no-excerpts` omits excerpts, recorded as `excerptsOmitted` in JSON. Paths, names, descriptions, and baselines are not anonymised; review before sharing.
- Google/Firebase/Maps `AIza...` values are public identifiers, not evidence of a leak on their own.
- Read limits: 2 MiB per file, 128 MiB and 10,000 files per scan, 16 directory levels. At most 100 findings per file across rules, prioritising severity and confidence.
- Git history checks cover up to 100 relevant revisions per file, with a 30-second timeout per Git command. Exceeded limits and timeouts report coverage gaps.
- Symbolic links are not followed; scan nested repositories and submodules separately. Skipped paths within scope mark the scan incomplete; built-in build and dependency exclusions do not.

## Development

New rules require positive and negative [test cases](./test/fixtures/).

```powershell
npm ci
```

```powershell
npm run prepublishOnly
```

Offline evaluation:

```powershell
npm run evaluate
```

The corpus has 10 synthetic cases and nine pinned upstream examples and mutations, also run by `npm test`. [Sources and licences](./test/fixtures/evaluation/) accompany the fixtures. Assertions cover rules, files, severity, confidence, and coverage, not real-world detection rates.

Five [application-directory snapshots](./test/evaluation/projects.json) provide additional evaluation. Preparation uses the network and verifies Git object hashes; the target must be a new directory outside Git:

```powershell
node scripts/fetch-evaluation-projects.mjs "$env:TEMP/canship-evaluation"
```

Then evaluate offline without installing or running sample dependencies:

```powershell
npm run evaluate:projects -- "$env:TEMP/canship-evaluation"
```

CI uses the same corpus. Git history and deployed behaviour are outside this evaluation.

## License

[MIT](./LICENSE). Supabase and Firebase fixtures retain Apache-2.0; Next.js and `cors` fixtures retain MIT. Each includes its source and licence.
