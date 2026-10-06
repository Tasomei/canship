# canship

A local static scanner for JavaScript and TypeScript web apps. Checks exposed credentials, access-control configuration, and unsafe request-input flows. No project-code execution, uploads, or network requests during scanning.

[简体中文](./README-zh-CN.md)

> Development branch. For npm `0.7.1`, see the [release documentation](https://github.com/Tasomei/canship/blob/v0.7.1/README.md). Check your version with `npx canship --version`.

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
| Express | `app`/`Router` routes, including `.route()` chains, mounted routers, and controllers in other files |
| Hono | Method routes, `OpenAPIHono.openapi()` / `openapiRoutes()`, chains, `basePath`, and `app.route()` sub-apps |
| Fastify | Shorthand and `route()` declarations, `register()` prefixes and encapsulation, `@fastify/autoload` directories |

Recognised Next.js/Astro middleware may suppress covered auth findings; Server Functions need local checks. Express/Hono/Fastify require resolved rejection logic or known auth libraries. Fastify decorator and plugin evidence is scoped to the local instance.

Session checks and webhook verification (Stripe, Polar, Clerk, Svix, QStash) must reject failures; asynchronous calls must be awaited or returned. Indirect evidence from project helpers/wrappers, SvelteKit hooks, or Nuxt middleware may lower confidence. Unresolved auth sources do not suppress findings.

Input analysis follows assignments, destructuring, string construction, and resolvable cross-file passthrough helpers. Helper names alone do not prove sanitisation.

For Express, Hono, and Fastify routes, writes inside called project functions are followed two levels (handler → service → model); file-based routes report writes in the route file only. SvelteKit page loads and remote functions are outside route analysis. Content-based checks, including credentials and CORS, still apply.

OpenAPI configuration supports inline objects, constants, and static ESM imports/re-exports, with literal paths and at most eight resolution steps. Middleware retains its defining file. Dynamic configuration, detected mutations, and multiple `export *` sources cannot prove protection; arbitrary module side effects are not modelled. `security` declarations and validation hooks are not authentication.

`openapiRoutes()` supports static arrays, spreads, and `defineOpenAPIRoute()` entries. Only literal `addRoute: false` skips an entry. Unresolved entries or handlers mark coverage incomplete when route-based checks are selected.

## Results

Reports are in English. The terminal groups findings by file; `--verbose` adds excerpts, explanations, evidence, and fixes. Follow-up commands retain scan targets and privacy options. Offline HTML supports severity/confidence filters, grouping, stable finding links, copyable references and fix prompts. Printing includes all findings present in the report, then restores the view. Filters cannot reveal results omitted during generation; use `--all` to include likely findings.

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
| `--list-rules` | List rules without scanning; supports `--only` / `--skip` and `--json` |
| `--explain-config` | Show effective settings, sources, and selected rules without scanning; supports `--json` |
| `--doctor` | Run read-only environment checks; supports `--json`, `--no-config`, `--baseline`, and output-path checks |
| `--init[=config\|ci]` | Print a minimal configuration or pinned CI template without reading or changing project files |
| `--baseline[=file]` / `--baseline-write[=file]` | Suppress/record findings; default `canship-baseline.json` |
| `--baseline-migrate[=file]` | Print a migrated baseline as JSON; preserve the source file |
| `--baseline-review` | Compare accepted and current findings; supports `--baseline[=file]` and `--json` |
| `--baseline-prune` | Print a v4 candidate retaining only active, matched acceptances; preserve the source |
| `--baseline-accept=ids` | Print a candidate accepting selected `fingerprint[:count]` entries; default count `1`, comma-separated and repeatable |
| `--baseline-reason=text` / `--baseline-expires=UTC` | With `--baseline-accept`, record a reason and/or UTC expiry |
| `--no-config` / `--no-ignore-markers` | Ignore project configuration/source suppression comments |
| `--best-effort` | Allow incomplete coverage with no findings to exit `0` |
| `-h`, `--help` / `-v`, `--version` | Show help/version |
| `--build-info` | Show channel, source revision, dirty state and capabilities; supports `--json` |

`--json` and `--fix-prompt` are mutually exclusive; either supports HTML and SARIF output.

`--init` is a standalone preview: stdout contains the template; stderr names its intended destination. Review before saving. CI previews use the scanner's package version; confirm that version is published and review the Action pin before enabling the workflow.

`--changed-since` compares the local merge base with the working tree, including non-ignored untracked files. It does not fetch or narrow scan scope. Missing Git, refs, or shared history exits `3`; it cannot be combined with `--baseline-write`.

`--doctor` checks Node.js, directory access, configuration, baseline structure, and local Git metadata. In this mode, `--report` / `--sarif` only check destinations; no reports or test files are written. Exit `3` indicates preflight errors; `0` may include warnings and does not establish scan coverage, baseline matches, or successful future writes. JSON uses `kind: "doctor"`; diagnostics omit project content, baseline entries, environment variables, and remote addresses.

## Configuration

`canship.config.json` accepts `baseline`, `only`, `skip`, and `all`. CLI options take precedence; `only` and `skip` are mutually exclusive.

For editor completion, set `$schema` to the bundled [configuration schema](./schemas/config-v1.schema.json), e.g. `./node_modules/canship/schemas/config-v1.schema.json` after local installation. Canship does not fetch this reference. Invalid fields include a field path and line/column; JSON syntax errors include a location when available. Schema validation does not verify baseline files or path containment.

```json
{ "skip": ["cors/wildcard-with-credentials"], "all": false }
```

`--explain-config` resolves the same settings as a scan. It does not read source or baseline contents, check Git history, or write files. Exit `0` confirms configuration resolution, not scan coverage or baseline validity. JSON uses `kind: "effective-config"`, not the scan-report schema. Paths remain visible; review output before sharing. Report output, baseline writes/migration, and `--changed-since` cannot be combined with this mode.

A standalone `canship-ignore-file` comment excludes a file. `canship-ignore-next-line [rule]` suppresses the next line, optionally for one rule. Exclusions are disclosed and may reduce status to `0` without marking coverage incomplete. For untrusted projects, use `--no-config --no-ignore-markers`.

Baselines accept existing findings without fixing them. New baselines use v4 with optional reasons and expiry; v2/v3 remain readable. The v3 fingerprint algorithm is unchanged: title, language, and line moves do not change identity; source evidence does. SARIF retains v2 and v3 fingerprints. Older scanners reject v4 instead of ignoring expiry.

`--baseline-review` lists retained, unmatched, unaccepted, and expired records; unmatched does not mean fixed. Review and acceptance start empty only when the implicit default baseline is absent; explicit or configured missing files fail. Prune and acceptance require complete, unfiltered coverage without source suppressions. Both print candidates without changing the source: pruning accepts nothing new; acceptance adds only selected counts and preserves old v3/v4 records. Select full fingerprints from the review, then save the reviewed candidate to a different file. v2 acceptance requires all old entries to match. These commands use operation status, not finding severity; incomplete reviews exit `3`.

Reasons are optional, limited to 500 characters, and should contain no secrets or personal data. Expiry requires a future UTC timestamp such as `2030-01-01T00:00:00Z`; records stop suppressing at that instant. Different decisions for the same fingerprint keep separate counts and expiry. Reports disclose expired counts; review shows the reason and deadline. Omitting expiry creates a permanent acceptance.

`--baseline-migrate` requires a complete, unfiltered scan and matching, unexpired entries. It accepts no new findings, prints v4 JSON, and leaves the old file unchanged. Review/prune unmatched or expired decisions first. Reports and baselines are written atomically; existing unrelated files and symbolic-link targets are not overwritten.

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
      - uses: Tasomei/canship@7465c9560b8b3692777af080e8cc67b4be2335d7
        with:
          version: '0.7.1'
          honor-ignore-markers: false
```

The commit hash pins the Action implementation; `version` selects the npm scanner, not development-branch source. The Action uses Node.js 22, does not install or run project dependencies, and writes a counts-only summary.

| Input | Default | Meaning |
|---|---|---|
| `version` | `0.7.0` | Exact npm scanner version |
| `fail-on` | `blocking` | `blocking`: certain P0/P1; `any`: all findings; `none`: report only |

Incomplete scans and tool errors always fail. Project configuration and SARIF upload are disabled by default. Inputs and outputs: [action.yml](./action.yml).

SARIF upload requires `security-events: write` and code scanning support; fork PRs may lack permission. Review reports before upload. Use `pull_request`, not `pull_request_target`, for untrusted PRs.

## API and structured output

```js
import { scan, summarize } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
```

`scan()` returns all confidence levels. Options: `only`, `skip`, `honorIgnoreMarkers` (default `true`), `noExcerpts` (default `false`). It does not load configuration, apply baselines, write reports, or set process exit status. Invalid arguments throw. `listRules()` returns the rule catalogue; `getBuildInfo()` and `getCapabilities()` identify the build and permission boundaries.

JSON uses [schemaVersion 1](./schemas/scan-report-v1.schema.json). Check `partial`, `errors`, `skipped`, and `filesScanned` independently of exit status. New reports include stable `errors[].code` values; older reports may omit them. CLI failures include `[CODE]` on stderr without corrupting JSON stdout. SARIF includes evidence locations and execution diagnostics.

Build identity distinguishes development, prerelease, and release artifacts. Only a clean checkout matching the version tag is marked as a release; this label is not publisher authentication. JSON includes optional `build` metadata; consumers must tolerate absent metadata and unknown diagnostic codes. `--version` retains its package-version format.

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
| OpenAPI batches | 256 items per call, including spreads; 8 array levels |
| Findings | 100 per file, prioritising severity and confidence |
| Git history | 100 relevant revisions per file; 30 seconds per command |
| Auth helper resolution | 8 hops; 64 symbols per helper, 1,024 per route file |
| Delegated writes | 2 call levels; 256 callees per file; writes beyond these limits are not reported |
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
