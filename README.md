# canship

A local static scanner for JavaScript and TypeScript projects. Detects exposed credentials and access-control misconfigurations without executing project code, uploading files, or making network requests.

[简体中文](./README-zh-CN.md)

## Quick start

```powershell
npx canship .
```

Requires Node.js ≥18; no runtime dependencies. Package installation may use the network. Git checks use local history only; unavailable Git in a repository marks the scan incomplete.

> Documentation for 0.4.0. Earlier [npm versions](https://www.npmjs.com/package/canship) may not include all features below.

## Checks

| Check | Severity |
|---|---|
| Hardcoded credentials, private keys, and database URLs containing passwords | P0 |
| Private values in public environment variables | P0 |
| Supabase admin credentials in source or public environment variables | P0 |
| Credentials or suspected private values in Git-tracked and historical `.env` files | P0 |
| Supabase tables without Row Level Security (RLS) in migrations | P1 |
| Supabase RLS policies with always-true conditions | P1 |
| Public Supabase storage buckets with listable contents | P2 |
| Firebase unconditional access and date-based test rules (Firestore, Storage, Realtime Database) | P1 |
| Server-side data operations without recognised authentication | P0 / P1 |
| Credentialed CORS with reflected or wildcard origins | P1 / P2 |

Recognises OpenAI, Anthropic, AWS, Stripe, GitHub, npm, and other credential formats, plus common frontend public environment prefixes. Use `--list-rules` for rule IDs, scope, and limits.

### Authentication coverage

| Framework | Checked entry points |
|---|---|
| Next.js | Route handlers under `app/`, Pages Router `/api`, and `'use server'` functions |
| SvelteKit | `+server` endpoints and `+page.server` form actions |
| Nuxt | `server/api` and `server/routes` |
| Remix / React Router | `loader` and `action` exports in `app/routes` |
| Astro | Endpoints in `src/pages` |

Supports route groups and workspace applications. SvelteKit page loads and remote functions are outside scope. Recognised Next.js and Astro middleware guards may suppress covered route findings; Server Functions require a guard within each function. SvelteKit hooks, Nuxt middleware, and local auth helpers can lower confidence without suppressing findings.

Supabase checks replay local migrations and read supported bucket configuration. Dashboard-only changes and policy conditions implied by missing clauses are not checked.

### Confidence and evidence

`certain` and `likely` describe static evidence, not credential validity or deployed state. Only `certain` findings are shown by default; hidden `likely` findings still affect exit status.

Admin-client findings include operation, import, and client-construction locations. Supabase constructor aliases and local auth imports, re-exports, and function-returning wrappers are recognised within bounded patterns. Auth resolution follows up to eight hops; evidence chains contain at most 24 steps and disclose truncation. Indirect auth evidence retains the finding at lower confidence; import relationships do not prove runtime data flow.

## CLI

Omitting the path scans the current directory. Reports are in English.

| Option | Effect |
|---|---|
| `-a`, `--all` | Include `likely` findings in every format |
| `--json` | Output JSON |
| `--fix-prompt` | Output repair instructions and separate manual actions |
| `--report[=file]` | Write HTML; default: `canship-report.html` |
| `--sarif[=file]` | Write SARIF 2.1.0; default: `canship.sarif` |
| `--no-excerpts` | Omit source excerpts; preserve findings and exit status |
| `--changed-since=ref` | Filter the report by changed files, not the scan or exit status |
| `--only=ids` / `--skip=ids` | Select or exclude rules; comma-separated and repeatable |
| `--list-rules` | List rules without scanning; supports `--json` |
| `--baseline[=file]` | Suppress recorded findings; default: `canship-baseline.json` |
| `--baseline-write[=file]` | Record findings and exit; same default path |
| `--no-config` | Ignore project configuration |
| `--no-ignore-markers` | Disregard source ignore markers |
| `--best-effort` | Allow exit `0` for an incomplete scan with no findings |
| `-h`, `--help` / `-v`, `--version` | Show help or version |

`--json` and `--fix-prompt` are mutually exclusive; HTML and SARIF can accompany either.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings; scan complete or incompleteness accepted by `--best-effort` |
| `1` | At least one `certain` P0/P1 finding |
| `2` | Other findings, including hidden `likely` findings |
| `3` | Invalid arguments, tool error, or unaccepted incomplete scan |

Counts apply after rule selection, ignore markers, and baselines. Findings take precedence over incompleteness; `--best-effort` does not change `1` or `2`.

### Changed-file view

`--changed-since=origin/main` compares the local merge base with the working tree, including non-ignored untracked files. It does not fetch. The whole project is still scanned; findings are shown when their primary or evidence locations changed. Repository-wide findings and truncated evidence are retained.

Hidden findings still affect exit status: this is a review view, not a “new issues only” CI policy. Missing Git, refs, or merge history exits `3`, even with `--best-effort`. Cannot be combined with `--baseline-write`.

### Structured reports

JSON uses `schemaVersion: 1`; the package includes its [schema](./schemas/scan-report-v1.schema.json). Consumers should accept additive fields and reject unsupported schema versions.

- `findings`: results after suppression and display filtering.
- `hiddenLikely`, `baselineSuppressed`, `baselineStale`: filtering and baseline counts.
- `partial`, `errors`, `skipped`, `filesScanned`: scan coverage; check separately from exit status.
- `changeView`: changed-file filtering counts and full-scan totals, when enabled.

SARIF includes execution diagnostics and related evidence locations. `--list-rules --json` returns a separate `kind: "rule-catalog"` document.

## Programmatic API

Node.js ESM with TypeScript declarations:

```js
import { scan, summarize, listRules } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
console.log(listRules())
```

`scan()` returns all confidence levels. Options: `only`, `skip`, `honorIgnoreMarkers` (default `true`), `noExcerpts` (default `false`). It does not load project configuration, apply baselines, write reports, or set the process exit code. Invalid arguments or root directories throw; coverage gaps remain in the result.

`summarize()` returns finding, blocking and likely counts, `partial`, and the default CLI exit code. `listRules()` returns an independent catalog copy.

## GitHub Action

Save as `.github/workflows/canship.yml`. The Action installs an exact npm version, scans the checkout, and produces a counts-only summary. It does not install or execute project dependencies; SARIF upload is opt-in.

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
      - uses: Tasomei/canship@b4cbbfe6b5c4c88164b9388d121f7651032259a4
        with:
          version: '0.4.0'
```

The commit pins the Action wrapper; `version` selects the npm scanner, not repository source. The pinned Action defaults to 0.3.2; this example explicitly selects 0.4.0.

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Scan directory within the checkout |
| `version` | `0.3.2` | Exact npm version; no ranges or tags |
| `fail-on` | `blocking` | `blocking`: certain P0/P1; `any`: all findings; `none`: report only |
| `only` / `skip` | unset | Mutually exclusive rule selectors |
| `baseline` | unset | Existing baseline relative to the scan directory |
| `use-config` | `false` | Enable project configuration |
| `upload-sarif` | `false` | Upload to GitHub code scanning |
| `category` | `canship` | SARIF category for the scan target |

Outputs: `exit-code`, `findings`, `blocking`, `partial`. Counts include likely findings after baselines and exclusions. Incomplete scans, tool errors, and incompatible reports always fail, even with `fail-on: none`.

SARIF upload needs `security-events: write` and [code scanning support](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file); fork PR permissions may be insufficient. Review reports before upload. Use `pull_request`, not `pull_request_target`, for untrusted PRs. The Action sets Node.js 22 for subsequent steps; isolate the scan job if another version is required.

## Configuration and baselines

`canship.config.json` in the scan directory accepts `baseline`, `only`, `skip`, and `all`:

```json
{
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

CLI options take precedence. `only` and `skip` are mutually exclusive and accept rule IDs or namespaces. `--best-effort` is CLI-only. For untrusted projects, use `--no-config --no-ignore-markers`.

### Ignore markers

A standalone `canship-ignore-file` comment excludes the file. `canship-ignore-next-line` suppresses the next line, optionally for one rule:

```ts
// canship-ignore-next-line cors/wildcard-with-credentials
const corsOptions = { origin: '*', credentials: true }
```

Reports disclose exclusions and suppressions. Deliberate exclusions do not mark the scan incomplete and can reduce the exit code to `0`. `--no-config` does not disable markers; `--no-ignore-markers` does.

### Baselines

Record existing findings:

```powershell
npx canship --baseline-write
```

Suppress them on subsequent scans:

```powershell
npx canship --baseline
```

The default path is relative to the scan directory; explicit paths are relative to the working directory. Read and write modes are mutually exclusive. Successful writes exit `0` regardless of findings; incomplete or selective scans produce a warning.

Format v2 fingerprints survive line moves but change with credentials. Missing, malformed, or v1 baselines exit `3`. Baselines omit source excerpts but retain paths, rules, and issue descriptions; review before committing.

## Privacy and limits

- Static checks can miss issues or report intentional configurations. They do not verify deployed behaviour, rate limiting, injection, dependency vulnerabilities, or business authorisation. No findings does not prove security.
- Redaction covers recognised formats only. Unknown secrets may remain in excerpts; `--no-excerpts` omits excerpts and sets JSON `excerptsOmitted`. Paths, names, descriptions, and baselines are not anonymised.
- Google/Firebase/Maps `AIza...` keys are treated as public identifiers, not leak evidence on their own.
- Read limits: 2 MiB per file, 128 MiB and 10,000 files per scan, 16 directory levels. At most 100 findings per file across rules, prioritising severity and confidence.
- Git history: up to 100 relevant revisions per file; 30-second timeout per Git command. Supabase policy and bucket statements: 4,000-character parse limit. Exceeded limits report incomplete coverage.
- Symbolic links are not followed; nested repositories and submodules need separate scans. Skipped in-scope paths mark coverage incomplete; built-in dependency and build exclusions do not.

## Development

```powershell
npm ci
```

```powershell
npm run prepublishOnly
```

```powershell
npm run test:package
```

New rules need positive and negative [fixtures](./test/fixtures/). Run the offline [evaluation corpus](./test/fixtures/evaluation/):

```powershell
npm run evaluate
```

For [application snapshots](./test/evaluation/projects.json), fetch and verify sources into a new directory outside Git:

```powershell
node scripts/fetch-evaluation-projects.mjs "$env:TEMP/canship-evaluation"
```

Then evaluate offline:

```powershell
npm run evaluate:projects -- "$env:TEMP/canship-evaluation"
```

Project evaluation compares all findings in original and open/guarded test variants using temporary copies. Sample dependencies are not installed or run. These tests do not measure real-world detection rates, Git-history coverage, or deployed behaviour.

## License

[MIT](./LICENSE). Supabase and Firebase fixtures retain Apache-2.0; Next.js and `cors` fixtures retain MIT. Sources and licences accompany the fixtures.
