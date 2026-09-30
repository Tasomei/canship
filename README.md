# canship

A local static scanner for JavaScript and TypeScript projects. Detects exposed credentials and access-control misconfigurations without executing project code, uploading files, or making network requests.

[简体中文](./README-zh-CN.md)

## Quick start

```powershell
npx canship .
```

Requires Node.js ≥18; no runtime dependencies. Installation may use the network. Git checks read local history only; unavailable Git in a repository marks coverage incomplete.

> Documentation for 0.5.0. `npx canship` runs the npm default version; use the corresponding Git tag for other releases.

## Checks

| Check | Severity |
|---|---|
| Hardcoded credentials, private keys, and database URLs containing passwords | P0 |
| Private values in public environment variables | P0 |
| Supabase admin credentials in source or public environment variables | P0 |
| Git-tracked or historical `.env` files, excluding templates | P0 |
| Supabase tables without RLS and policies with always-true conditions | P1 |
| Public Supabase storage buckets with listable contents | P2 |
| Firebase unconditional access and date-based test rules | P1 |
| Server-side data operations without recognised authentication | P0 / P1 |
| Credentialed CORS with reflected or wildcard origins | P1 / P2 |

Recognises OpenAI, Anthropic, AWS, Stripe, GitHub, npm, and other credential formats. Firebase checks cover Firestore, Storage, and Realtime Database. Use `--list-rules` for rule IDs and scope.

### Authentication

| Framework | Checked entry points |
|---|---|
| Next.js | `app/` route handlers, Pages Router `/api`, and `'use server'` functions |
| SvelteKit | `+server` endpoints and `+page.server` form actions |
| Nuxt | `server/api` and `server/routes` |
| Remix / React Router | `loader` and `action` exports in `app/routes` |
| Astro | Endpoints in `src/pages` |

Supports route groups, workspace applications, local helper chains, identity aliases and destructuring, argument requirements, and bounded branch/exception analysis. Raw request input, constants, unawaited promises, or helper names alone do not establish local authentication.

Recognised Next.js/Astro middleware may suppress covered findings; Server Functions require function-local checks. Local helpers, SvelteKit hooks, and Nuxt middleware may lower confidence but retain findings. SvelteKit page loads and remote functions are excluded.

`certain` and `likely` describe static evidence, not credential validity or runtime security. Default output shows only `certain`; hidden `likely` findings still affect exit status. Admin-client findings include operation, import, construction, and auth-helper locations.

## CLI

Omitting the path scans the current directory. Reports are in English.

| Option | Effect |
|---|---|
| `-a`, `--all` | Include `likely` findings |
| `--verbose` | Expand each terminal finding with its excerpt, explanation, trace and fix steps |
| `--json` | Output JSON |
| `--fix-prompt` | Output repair instructions and separate manual actions |
| `--report[=file]` | Write HTML; default: `canship-report.html` |
| `--sarif[=file]` | Write SARIF 2.1.0; default: `canship.sarif` |
| `--no-excerpts` | Omit source excerpts, preserving findings and exit status |
| `--changed-since=ref` | Show findings related to changed files; retain full-scan exit status |
| `--only=ids` / `--skip=ids` | Select or exclude rules; comma-separated and repeatable |
| `--list-rules` | List rules without scanning; supports `--json` |
| `--baseline[=file]` | Suppress recorded findings; default: `canship-baseline.json` |
| `--baseline-write[=file]` | Record findings and exit; same default path |
| `--no-config` | Ignore project configuration |
| `--no-ignore-markers` | Disregard source ignore comments |
| `--best-effort` | Allow an incomplete scan with no findings to exit `0` |
| `-h`, `--help` / `-v`, `--version` | Show help or version |

`--json` and `--fix-prompt` are mutually exclusive. HTML and SARIF can accompany either.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings; coverage complete or accepted by `--best-effort` |
| `1` | At least one `certain` P0/P1 finding |
| `2` | Other findings, including hidden `likely` findings |
| `3` | Invalid arguments, tool error, or unaccepted incomplete scan |

Codes apply after rule selection, ignore markers, and baselines. Findings take precedence over incompleteness; `--best-effort` does not change `1` or `2`.

### Changed-file view and reports

`--changed-since=origin/main` compares the local merge base with the working tree, including non-ignored untracked files; it does not fetch. The entire project is scanned. Results are shown when primary or evidence locations changed; repository-wide results and truncated evidence are retained. Hidden results still affect exit status. Missing Git, refs, or shared history exits `3`, even with `--best-effort`. Incompatible with `--baseline-write`.

JSON uses `schemaVersion: 1`; fields and filtering counts are defined in the [schema](./schemas/scan-report-v1.schema.json). Check `partial`, `errors`, `skipped`, and `filesScanned` separately from exit status. Allow additive fields; reject unsupported schema versions.

SARIF includes execution diagnostics and evidence locations. `--list-rules --json` returns a separate `kind: "rule-catalog"` document.

## Configuration

`canship.config.json` in the scan directory accepts `baseline`, `only`, `skip`, and `all`:

```json
{
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

CLI options take precedence. `only` and `skip` are mutually exclusive and accept rule IDs or namespaces. `--best-effort` is CLI-only. For untrusted projects, use `--no-config --no-ignore-markers`.

### Ignore comments

A standalone `canship-ignore-file` comment excludes the file. `canship-ignore-next-line` suppresses the next line, optionally for one rule:

```ts
// canship-ignore-next-line cors/wildcard-with-credentials
const corsOptions = { origin: '*', credentials: true }
```

Reports disclose exclusions. Deliberate suppression does not mark coverage incomplete and may reduce the exit code to `0`. `--no-config` does not disable these comments.

### Baselines

Record existing findings, then suppress them on subsequent scans:

```powershell
npx canship --baseline-write
```

```powershell
npx canship --baseline
```

Default paths are relative to the scan directory; explicit paths are relative to the working directory. Read/write modes are mutually exclusive. A successful write exits `0`, not a clean-scan verdict; incomplete or selective scans produce a warning.

Format v2 survives line moves but detects credential changes. Missing, malformed, and v1 baselines exit `3`. Baselines omit excerpts but retain paths, rules, and descriptions; review before committing.

## API

Node.js ESM with TypeScript declarations:

```js
import { scan, summarize, listRules } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
console.log(listRules())
```

`scan()` returns all confidence levels. Options: `only`, `skip`, `honorIgnoreMarkers` (default `true`), `noExcerpts` (default `false`). It does not load configuration, apply baselines, write reports, or set exit status. Invalid arguments or roots throw; coverage gaps remain in the result.

`summarize()` returns finding counts, `partial`, and the default CLI exit code. `listRules()` returns an independent catalog copy.

## GitHub Action

Save as `.github/workflows/canship.yml`. The Action installs an exact npm scanner version and writes a counts-only summary. It does not install or run project dependencies; SARIF upload is opt-in.

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
      - uses: Tasomei/canship@97c14d1f1e494a49adf716c455b597edf6ae1d88
        with:
          version: '0.5.0'
          honor-ignore-markers: false
```

The commit pins the wrapper; `version` selects the npm scanner, not repository source. This pinned wrapper defaults to 0.5.0.

| Input | Default | Meaning |
|---|---|---|
| `version` | `0.5.0` | Exact npm version; no ranges or tags |
| `fail-on` | `blocking` | `blocking`: certain P0/P1; `any`: all findings; `none`: report only |
| `use-config` | `false` | Enable project configuration |
| `honor-ignore-markers` | `true` | Honour file/line ignore comments |
| `upload-sarif` | `false` | Upload to GitHub code scanning |

Path, rule-selection, baseline, and category inputs are documented in [action.yml](./action.yml).

Outputs: `exit-code`, `findings`, `blocking`, `partial`. Counts include likely findings after suppression. Incomplete scans, tool errors, and incompatible reports fail even with `fail-on: none`.

SARIF upload requires `security-events: write` and code scanning support; fork PR permissions may be insufficient. Review reports before upload. Use `pull_request`, not `pull_request_target`, for untrusted PRs. The Action sets Node.js 22; use a separate scan job when needed.

## Privacy and limits

- Static checks can miss issues or flag intentional configurations. They do not verify deployed behaviour, business authorisation, rate limiting, injection, or dependency vulnerabilities. No findings does not prove security.
- Redaction covers recognised formats only. Unknown secrets may remain in excerpts; `--no-excerpts` removes excerpts and sets JSON `excerptsOmitted`. Paths, names, descriptions, and baselines are not anonymised.
- Google/Firebase/Maps `AIza...` keys are treated as public identifiers, not leak evidence alone.
- Supabase checks use local migrations and supported bucket configuration, not dashboard-only changes or policy conditions implied by omitted clauses.
- Symbolic links are not followed. Nested repositories and submodules need separate scans. In-scope skipped paths mark coverage incomplete; built-in dependency/build exclusions do not.

| Limit | Bound |
|---|---|
| File reads, including probes | 2 MiB per file; 128 MiB and 10,000 files per scan |
| Directory discovery | 50,000 entries; 16 levels |
| Findings | 100 per file, prioritising severity and confidence |
| Git history | 100 relevant revisions per file; 30 seconds per Git command |
| Auth resolution | 8 hops; 128 symbols per route file |
| Identity/control flow | 8 value hops; 4,000 expression characters; 512 assignments/conditional regions per function; 8 nested branch/exception regions |
| Supabase policy/bucket parsing | 4,000 characters per statement |

Exceeded scan/analysis limits report incomplete coverage. Evidence chains are capped at 24 steps and disclose truncation. Getter names and import relationships remain syntactic evidence, not runtime verification.

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

New rules require positive and negative [fixtures](./test/fixtures/). Run the offline corpus:

```powershell
npm run evaluate
```

For application evaluation, use the [snapshot manifest](./test/evaluation/projects.json), [fetch script](./scripts/fetch-evaluation-projects.mjs), and [offline evaluator](./scripts/evaluate-projects.ts). Tests compare original and paired variants in temporary copies without running sample dependencies; they do not measure real-world detection rates, Git-history coverage, or deployed behaviour.

## License

[MIT](./LICENSE). Supabase/Firebase fixtures retain Apache-2.0; Next.js/`cors` fixtures retain MIT. Sources and licences accompany the fixtures.
