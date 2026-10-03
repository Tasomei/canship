# canship

A local static scanner for JavaScript and TypeScript web apps. Checks exposed credentials, access-control configuration, and unsafe request-input flows. No project-code execution, uploads, or network requests during scanning.

[简体中文](./README-zh-CN.md)

> Documentation for `0.6.0`. Check the installed version with `npx canship --version`.

## Quick start

```powershell
npx canship
```

Scans the current directory or a specified path. Requires Node.js ≥18; no runtime dependencies. Installation may use the network. Git checks cover locally tracked files and commit history without contacting remotes; inaccessible history marks coverage incomplete.

Output examples use sample data from a pre-release development build.

![Terminal report](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/terminal.png)

## Checks

| Category | Severity | Scope |
|---|:---:|---|
| Credentials | `P0` | Hardcoded keys, private keys, password-bearing database URLs, public env exposure, Supabase admin keys, non-template `.env` files tracked by Git or present in history |
| API access | `P0/P1` | Database operations without recognised authentication, server-side trust in Supabase `getSession()`, unverified Stripe webhooks |
| Database rules | `P1/P2` | Supabase tables without RLS, unconditional policies, public object listing in storage buckets; Firebase open rules and time-limited test rules |
| CORS | `P1/P2` | Reflected or wildcard origins with credentials |
| Request input | `P1/P2` | Request input in SQL or command construction, caller-chosen request hosts and redirect targets |

Credential formats include OpenAI, Anthropic, AWS, Stripe, GitHub, and npm. Firebase covers Firestore, Storage, and Realtime Database. `--list-rules` lists rule IDs, scope, and limitations.

### Server entry points

| Framework | Entry points |
|---|---|
| Next.js | App Router handlers, Pages Router `/api`, `'use server'` functions |
| SvelteKit | `+server` endpoints and `+page.server` form actions |
| Nuxt | `server/api`, `server/routes` |
| Remix / React Router | `loader` and `action` exports in `app/routes` |
| Astro | Endpoints in `src/pages` |

Recognised Next.js/Astro middleware may suppress covered auth findings; Server Functions need local checks. Local helpers, SvelteKit hooks, and Nuxt middleware may lower confidence without suppressing findings. Input analysis follows visible assignments, destructuring, and string construction; helper names alone do not prove sanitisation.

SvelteKit page loads, remote functions, and standalone Express/Hono/Fastify handlers are outside route analysis. Content-based checks, including credentials and CORS, still apply.

## Results

Reports are in English. The terminal groups findings by file; `--verbose` adds excerpts, explanations, evidence, and fixes. HTML is a self-contained offline report with filters, grouping, manual steps, and copyable fix prompts.

![HTML report](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/report.png)

`certain` indicates strong static evidence; `likely` requires review. Findings in tests and examples are downgraded to `likely`. Default output shows only `certain`; `--all` includes both. Confidence reflects static evidence, not credential validity or runtime verification.

| Exit | Meaning |
|---|---|
| `0` | No findings; coverage complete or accepted with `--best-effort` |
| `1` | At least one `certain` P0/P1 finding |
| `2` | Other findings, including hidden `likely` results |
| `3` | Invalid arguments, tool error, or unaccepted incomplete coverage |

Status is calculated after rule selection, ignore comments, and baselines. Findings take precedence over incomplete coverage; `--best-effort` never changes `1` or `2`.

## CLI

`npx canship [path] [options]`

| Option | Effect |
|---|---|
| `-a`, `--all` | Include `likely` findings |
| `--verbose` | Expand terminal findings |
| `--report[=file]` | Write HTML; default `canship-report.html` |
| `--open` | Open `--report` output; disabled in CI and non-interactive shells |
| `--json` | Print JSON |
| `--sarif[=file]` | Write SARIF 2.1.0; default `canship.sarif` |
| `--fix-prompt` | Print repair instructions and separate manual actions |
| `--no-excerpts` | Remove excerpts from all reports |
| `--changed-since=ref` | Show changed-file findings; preserve full-scan status |
| `--only=ids` / `--skip=ids` | Select/exclude rules or namespaces; comma-separated, repeatable |
| `--list-rules` | List rules without scanning; supports `--json` |
| `--baseline[=file]` / `--baseline-write[=file]` | Suppress/record findings; default `canship-baseline.json` |
| `--no-config` / `--no-ignore-markers` | Ignore project configuration/source suppression comments |
| `--best-effort` | Allow incomplete coverage with no findings to exit `0` |
| `-h`, `--help` / `-v`, `--version` | Show help/version |

`--json` and `--fix-prompt` are mutually exclusive; either supports HTML and SARIF output.

`--changed-since` compares the local merge base with the working tree, including non-ignored untracked files. It does not fetch or narrow scan scope. Missing Git, refs, or shared history exits `3`; it cannot be combined with `--baseline-write`.

## Configuration

`canship.config.json` accepts `baseline`, `only`, `skip`, and `all`. CLI options take precedence; `only` and `skip` are mutually exclusive.

```json
{ "skip": ["cors/wildcard-with-credentials"], "all": false }
```

A standalone `canship-ignore-file` comment excludes a file. `canship-ignore-next-line [rule]` suppresses the next line, optionally for one rule. Exclusions are disclosed and may reduce status to `0` without marking coverage incomplete. For untrusted projects, use `--no-config --no-ignore-markers`.

Baselines accept existing findings without fixing them. Format v2 tolerates line moves but reports credential changes.

Default paths are relative to the scan directory; explicit paths are relative to the working directory. Read/write modes are mutually exclusive. Missing, invalid, or v1 baselines exit `3`. A successful write exits `0`, with a warning for incomplete or selective scans.

## GitHub Action

Save as `.github/workflows/canship.yml`:

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
      - uses: Tasomei/canship@7dfebc9502b786edd5c7fd71266e4926d0ad764b
        with:
          version: '0.6.0'
          honor-ignore-markers: false
```

The commit hash pins the Action implementation; `version` selects the npm scanner, not development-branch source. The Action uses Node.js 22, does not install or run project dependencies, and writes a counts-only summary.

| Input | Default | Meaning |
|---|---|---|
| `version` | `0.6.0` | Exact npm scanner version |
| `fail-on` | `blocking` | `blocking`: certain P0/P1; `any`: all findings; `none`: report only |

Incomplete scans and tool errors always fail. Project configuration and SARIF upload are disabled by default. Inputs and outputs: [action.yml](./action.yml).

SARIF upload requires `security-events: write` and code scanning support; fork PRs may lack permission. Review reports before upload. Use `pull_request`, not `pull_request_target`, for untrusted PRs.

## API and structured output

```js
import { scan, summarize } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
```

`scan()` returns all confidence levels. Options: `only`, `skip`, `honorIgnoreMarkers` (default `true`), `noExcerpts` (default `false`). It does not load configuration, apply baselines, write reports, or set process exit status. Invalid arguments throw. `listRules()` returns the rule catalogue.

JSON uses [schemaVersion 1](./schemas/scan-report-v1.schema.json). Check `partial`, `errors`, `skipped`, and `filesScanned` independently of exit status. SARIF includes evidence locations and execution diagnostics.

## Privacy and limits

- Static checks may miss issues or flag intentional configurations. Business authorisation, rate limiting, dependency vulnerabilities, and deployed settings are not verified.
- Redaction covers recognised formats only. Unknown secrets may remain in excerpts; `--no-excerpts` omits excerpts. Paths, names, and baseline descriptions remain visible.
- Google/Firebase/Maps `AIza…` keys are treated as public identifiers, not leak evidence alone. Supabase checks use local migrations and supported bucket configuration.
- Evaluation snapshot downloads and optional SARIF uploads may use the network.
- Symbolic links are not followed; nested repositories and submodules need separate scans. In-scope skipped paths and analysis limits mark coverage incomplete; auth helper resolution limits are noted on the affected finding instead, because they cannot hide findings. Dependency and build directories excluded by default do not count as coverage gaps.

| Limit | Bound |
|---|---|
| File reads | 2 MiB per file; 128 MiB and 10,000 files per scan, including probes |
| Directory discovery | 50,000 entries; 16 levels |
| Findings | 100 per file, prioritising severity and confidence |
| Git history | 100 relevant revisions per file; 30 seconds per command |
| Auth helper resolution | 8 hops; 64 symbols per helper, 1,024 per route file |
| Identity/control flow | 8 value hops; 4,000 expression characters; 512 assignments/regions per function; 8 nested regions |
| Request-input tracking | 8 value hops; 512 assignments/regions; 64 KiB per expression; 8 URL-analysis levels; 200 static-prefix characters |
| Supabase policy/bucket parsing | 4,000 characters per statement |

Evidence traces are capped at 24 steps and disclose truncation.

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

```powershell
npm run evaluate
```

New rules require positive and negative [fixtures](./test/fixtures/). Pinned project evaluation: [manifest](./test/evaluation/projects.json), [fetch script](./scripts/fetch-evaluation-projects.mjs), [evaluator](./scripts/evaluate-projects.ts). Passing samples do not establish real-world detection rates.

## License

[MIT](./LICENSE). Supabase/Firebase fixtures retain Apache-2.0; Next.js/`cors` fixtures retain MIT.
