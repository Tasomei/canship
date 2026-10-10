# Canship reference

[Overview](../README.md) · [简体中文](./reference-zh-CN.md)

This reference covers `0.8.1`. Other versions are listed under [Releases](https://github.com/Tasomei/canship/releases).

## Server entry points

[Framework coverage and regression cases](./framework-support.md) detail entry recognition, authentication, request inputs and analysis boundaries.

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

For Express/Hono/Fastify, conditional middleware cannot protect registrations outside its branch or function. Literal `true`/`false` branches and simple boolean short circuits are recognised; other conditions are not evaluated. Distinct helper-call contexts retain their own middleware evidence. This is bounded static registration analysis, not general control-flow execution.

Project router factories support top-level `const app = make()` calls when a synchronous, zero-argument function returns a fresh Express, Hono/OpenAPIHono or Fastify instance. Static ESM imports, named/default re-exports and a single `export *` source are followed. Literal Hono `basePath()` prefixes are retained; middleware remains instance-local. Conditional or async returns, parameters, shared instances, mutation and arbitrary wrapper chains are not inferred. Resolution limits mark coverage incomplete; unsupported syntax may remain outside route discovery.

Factory imports use the nearest `tsconfig.json` / `jsconfig.json` for single-target `paths` mappings with `baseUrl`, comments and trailing commas. Configuration inheritance and project references remain unresolved. Workspace resolution requires an explicit `dependencies` link (`workspace:*`, `workspace:^` or `workspace:~`) and a matching package in a `package.json` workspace list; patterns allow one segment wildcard. Only declared export subpaths are followed. Runtime export conditions must converge on one source; type-only branches, differing targets, duplicate package names and registry version ranges cannot establish that source. These mappings identify source candidates, not deployment behaviour: [TypeScript paths](https://www.typescriptlang.org/tsconfig/paths.html) do not rewrite runtime imports; [package exports](https://nodejs.org/api/packages.html#conditional-exports) may depend on the environment.

Session checks and webhook verification (Stripe, Polar, Clerk, Svix, QStash) must reject failures; asynchronous calls must be awaited or returned. Indirect evidence from project helpers/wrappers, SvelteKit hooks, or Nuxt middleware may lower confidence. Unresolved auth sources do not suppress findings.

Input analysis follows assignments, destructuring, string construction, and resolvable cross-file passthrough helpers. Helper names alone do not prove sanitisation.

For Express, Hono, and Fastify routes, writes inside called project functions are followed two levels (handler → service → model); file-based routes report writes in the route file only. SvelteKit page loads and remote functions are outside route analysis. Content-based checks, including credentials and CORS, still apply.

OpenAPI configuration supports inline objects, constants, and static ESM imports/re-exports, with literal paths and at most eight resolution steps. Middleware retains its defining file. Dynamic configuration, detected mutations, and multiple `export *` sources cannot prove protection; arbitrary module side effects are not modelled. `security` declarations and validation hooks are not authentication.

`openapiRoutes()` supports static arrays, spreads, and `defineOpenAPIRoute()` entries. Only literal `addRoute: false` skips an entry. Unresolved entries or handlers mark coverage incomplete when route-based checks are selected.

## CLI

`npx canship [path] [options]`

Terminal report layout adapts down to 24 columns, accounting for common CJK characters and emoji. Narrow views stack counts and separate command labels from copyable commands. Paths, excerpts, code examples and commands retain complete logical lines; the terminal may soft-wrap them. Glyph widths can vary by terminal and font. Redirected output is uncoloured by default; `FORCE_COLOR=0` disables colour, and nonempty `NO_COLOR` takes precedence. Windows follow-up commands use PowerShell quoting.

| Option | Effect |
|---|---|
| `-a`, `--all` | Include `likely` findings |
| `--verbose` | Expand terminal findings |
| `--no-progress` | Disable interactive stderr progress; structured output and redirected streams stay quiet |
| `--report[=file]` | Write HTML; default `canship-report.html` |
| `--open` | Open `--report` output; disabled in CI and non-interactive shells |
| `--json` | Print JSON |
| `--probe=url` | Preview a deployment probe without DNS or HTTP requests |
| `--confirm-probe=hash` | Execute only the matching reviewed probe plan |
| `--probe-expect-auth` | Review HEAD/canary responses other than the requested 401/403 rejection |
| `--probe-canary-sha256=hash` | Add a bounded GET of a dedicated synthetic canary |
| `--workspace=path` | Scan explicit subprojects independently; repeatable, up to 32; terminal or JSON output |
| `--compare=before.json` + `--with=after.json` | Compare saved scan reports; supports `--json` and `--report` |
| `--share-summary` | Print counts and scope flags without project text; supports `--json`, never uploads |
| `--sarif[=file]` | Write SARIF 2.1.0; default `canship.sarif` |
| `--fix-prompt` | Print repair instructions and separate manual actions |
| `--no-excerpts` | Remove excerpts from all reports |
| `--changed-since=ref` | Show changed-file findings; preserve full-scan status |
| `--only=ids` / `--skip=ids` | Select/exclude rules or namespaces; comma-separated, repeatable |
| `--exclude=path` | Exclude a literal project-relative file or directory; repeatable |
| `--list-rules` | List rules without scanning; supports `--only` / `--skip` and `--json` |
| `--explain-config` | Show effective settings, sources, and selected rules without scanning; supports `--json` |
| `--doctor` | Run read-only environment checks; supports `--json`, `--no-config`, `--baseline`, and output-path checks |
| `--init[=config\|ci\|ci-workspaces\|pre-commit]` | Preview config, CI or hook templates; no file changes |
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

Repeat `--workspace=apps/web --workspace=apps/admin` to scan selected directories separately. Paths must be literal, non-overlapping, and free of symlink components. Each project uses its own config and baseline; parent config and unselected sources are not inherited. CLI rule, exclusion, visibility, and privacy options override each project's settings; bare `--baseline` selects each project's default file. Results include configuration sources, per-project coverage, and full-confidence counts. A failed project makes the batch exit `3`; otherwise normal finding precedence applies. Only terminal and JSON (`kind: "workspace-report"`) are supported; use individual scans for HTML/SARIF or baseline maintenance.

`--compare` reads two local v1 JSON reports (up to 10 MiB and 50,000 findings each). It lists added, persisting, and no-longer-observed records using stable identities and counts; missing source digests remain unpaired. Coverage gaps, filters, baselines, different roots, and changed or unverifiable scanner builds limit comparison. Exit `0` means no known comparison limitation, `2` means limited comparison, and `3` means invalid input or output failure—not the scan's release policy. Absence is not proof of remediation. Titles, excerpts and scan roots are omitted; finding paths remain. No source scan or project-code execution occurs. JSON uses `kind: "report-comparison"`.

Comparison output is read-only by default. `--report` explicitly writes an offline HTML view to `canship-comparison.html` in the working directory; `--report=file.html` selects another path and can accompany `--json`. Inputs and unrelated files are not overwritten. HTML shows up to 2,000 detail rows and 512 UTF-16 code units per path/rule reference, disclosing truncation; all aggregate counts and the comparison exit status are retained. Use JSON for full references. Other scan and output modes, including `--open`, remain unavailable in comparison mode.

`--share-summary` counts all confidence levels after rule selection, source suppressions, and baselines, with the normal scan exit status. It omits paths, titles, identifiers, excerpts, and diagnostic details; handled failures show only a code and local troubleshooting advice. Detailed reports and changed-file views cannot be combined with it. JSON uses `kind: "share-summary"`, not the scan-report schema. Counts may still be sensitive; review before sharing.

`--init` is a standalone preview: stdout contains the template; stderr names its intended destination. Review before saving. CI previews use the scanner's package version; confirm that version is published and review the Action pin before enabling the workflow.

`--init=ci-workspaces` previews a matrix with independent jobs, `fail-fast: false`, and distinct SARIF categories. Replace sample paths and names before use. Project configuration and SARIF upload remain disabled; enabling upload also requires the appropriate permissions.

`--init=pre-commit` previews a Node hook, without installing it or changing Git settings. Review before saving as `pre-commit` in the [Git hooks directory](https://git-scm.com/docs/githooks); make it executable where required. Set `CANSHIP_CLI` to a trusted, separately installed `dist/cli.js` outside the worktree; its version must match the template. The hook scans the full working tree, including unstaged changes, with all findings visible and project suppressions disabled. It does not validate the staged snapshot: review staged-only content separately. Every nonzero exit blocks the commit; the hook makes no downloads and times out after two minutes of scanning.

`--changed-since` compares the local merge base with the working tree, including non-ignored untracked files. It does not fetch or narrow scan scope. Missing Git, refs, or shared history exits `3`; it cannot be combined with `--baseline-write`.

`--doctor` checks Node.js, directory access, configuration, baseline structure, and local Git metadata. In this mode, `--report` / `--sarif` only check destinations; no reports or test files are written. Exit `3` indicates preflight errors; `0` may include warnings and does not establish scan coverage, baseline matches, or successful future writes. JSON uses `kind: "doctor"`; diagnostics omit project content, baseline entries, environment variables, and remote addresses.

## Configuration

`canship.config.json` accepts `baseline`, `only`, `skip`, `exclude`, and `all`. CLI options take precedence; `only` and `skip` are mutually exclusive.

For editor completion, set `$schema` to the bundled [configuration schema](../schemas/config-v1.schema.json), e.g. `./node_modules/canship/schemas/config-v1.schema.json` after local installation. Canship does not fetch this reference. Invalid fields include a field path and line/column; JSON syntax errors include a location when available. Schema validation does not verify baseline files or path containment.

```json
{ "skip": ["cors/wildcard-with-credentials"], "all": false }
```

`--explain-config` resolves the same settings as a scan. It does not read source or baseline contents, check Git history, or write files. Exit `0` confirms configuration resolution, not scan coverage or baseline validity. JSON uses `kind: "effective-config"`, not the scan-report schema. Paths remain visible; review output before sharing. Report output, baseline writes/migration, and `--changed-since` cannot be combined with this mode.

A standalone `canship-ignore-file` comment excludes a file. `canship-ignore-next-line [rule]` suppresses the next line, optionally for one rule. Exclusions are disclosed and may reduce status to `0` without marking coverage incomplete. For untrusted projects, use `--no-config --no-ignore-markers`.

`exclude` uses case-sensitive literal paths, such as `generated/` or `test/fixtures/`; no globs or traversal. Up to 64 paths of 512 characters are accepted. CLI paths replace the configuration list; `--no-config` disables project-provided exclusions. Matching file contents and environment-history objects are not read; configuration, baseline, and Git metadata reads are separate. Reports disclose requested and matched exclusion paths, not excluded file counts. Baseline maintenance refuses this restricted scope.

Baselines accept existing findings without fixing them. New baselines use v4 with optional reasons and expiry; v2/v3 remain readable. The v3 fingerprint algorithm is unchanged: title, language, and line moves do not change identity; source evidence does. SARIF retains v2 and v3 fingerprints. Older scanners reject v4 instead of ignoring expiry.

`--baseline-review` lists retained, unmatched, unaccepted, and expired records; unmatched does not mean fixed. Review and acceptance start empty only when the implicit default baseline is absent; explicit or configured missing files fail. Prune and acceptance require complete, unfiltered coverage without source suppressions. Both print candidates without changing the source: pruning accepts nothing new; acceptance adds only selected counts and preserves old v3/v4 records. Select full fingerprints from the review, then save the reviewed candidate to a different file. v2 acceptance requires all old entries to match. These commands use operation status, not finding severity; incomplete reviews exit `3`.

Reasons are optional, limited to 500 characters, and should contain no secrets or personal data. Expiry requires a future UTC timestamp such as `2030-01-01T00:00:00Z`; records stop suppressing at that instant. Different decisions for the same fingerprint keep separate counts and expiry. Reports disclose expired counts; review shows the reason and deadline. Omitting expiry creates a permanent acceptance.

`--baseline-migrate` requires a complete, unfiltered scan and matching, unexpired entries. It accepts no new findings, prints v4 JSON, and leaves the old file unchanged. Review/prune unmatched or expired decisions first. Reports and baselines are written atomically; existing unrelated files and symbolic-link targets are not overwritten.

Default paths are relative to the scan directory; explicit paths are relative to the working directory. Read/write modes are mutually exclusive. Missing, invalid, or v1 baselines exit `3`. A successful write exits `0`, with a warning for incomplete or selective scans.

## Deployment probes

`--probe=https://app.example.com/status` previews two requests: HEAD and OPTIONS with a fixed probe Origin. Replace the example with an authorized target. Review the target, limits and privacy notice; repeat the same options with the displayed `--confirm-probe` digest to execute. The digest binds options, not domain ownership. This standalone CLI mode supports `--json`; it never reads project configuration or enables networking in `scan()` or the editor.

Only HTTPS on port 443 with a simple literal path is accepted: no credentials, queries, fragments or encoded path components. DNS answers must all be ordinary public addresses. If both A and AAAA queries cannot reach the configured DNS servers (common with VPN or proxy adapters), the system resolver is used within the same time limit; negative answers do not fall back. Connections are pinned while preserving hostname/TLS verification. No redirects or authenticated requests are made. Configured proxies, network debug settings and insecure TLS overrides are refused rather than bypassed. Limits: DNS 3 seconds, each request 5 seconds, response headers 16 KiB.

Optional `--probe-canary-sha256` adds GET only for a resource named `canship-canary`, `canship-canary.txt` or `canship-canary.json`. Use dedicated synthetic content of 16–4096 bytes. The response is hashed in memory; only match state and byte count are reported, never the body or computed digest. Compressed and oversized bodies fail. No Supabase/Firebase admin key or business-record export is supported.

Execution reveals the connecting IP and requested path to the target; requests can have side effects. Header presence, status codes and a readable canary do not prove general application security. Preview exits `0`; execution exits `0` for completed requests without review items, `2` for observations requiring review, or `3` for invalid/incomplete execution. JSON uses `probe-plan` or `probe-report`, not the scan-report schema. Acceptance has been run against a dedicated GitHub Pages target, covering HEAD, OPTIONS, canary matching and mismatch, expected-denial review and an unfollowed redirect.

Address policy references: [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry), [IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry), and [Azure platform address](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16). Application filtering does not replace network egress controls.

## API and structured output

```js
import { scan, summarize } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
```

`scan()` returns all confidence levels. Options: `only`, `skip`, `exclude`, `honorIgnoreMarkers` (default `true`), `noExcerpts` (default `false`), `signal`, and `onProgress`. It does not load configuration, apply baselines, write reports, or set process exit status. Invalid arguments throw. `listRules()` returns the rule catalogue; `getBuildInfo()` and `getCapabilities()` identify the build and permission boundaries.

`signal` accepts an AbortSignal. Cancellation rejects with `ScanCancelledError` (`name: "AbortError"`, `code: "SCAN_CANCELLED"`), not a clean or partial result. `onProgress` receives immutable stage/count snapshots; async callbacks are awaited and failures reject with `ScanProgressError`. Completion stages do not prove coverage; inspect the returned result. Cancellation is checked between file batches and rules, not inside active synchronous file/Git calls. CLI Ctrl+C uses the same boundary; progress contains no filenames.

JSON uses [schemaVersion 1](../schemas/scan-report-v1.schema.json). Check `partial`, `errors`, `skipped`, and `filesScanned` independently of exit status. New reports include stable `errors[].code` values; older reports may omit them. CLI failures include `[CODE]` on stderr without corrupting JSON stdout. SARIF includes evidence locations and execution diagnostics.

Canship v3 fingerprints identify findings for its own baselines and report comparisons. Within `partialFingerprints`, [GitHub code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support#result-object) uses only `primaryLocationLineHash`, which the pinned `upload-sarif` Action adds from checked-out source and valid line locations; direct REST uploads cannot rely on Canship's custom v3 fingerprint for deduplication. That hash covers the flagged line and the code immediately after it, so editing nearby lines can close a GitHub alert and open a new one even when the Canship fingerprint is unchanged.

Build identity distinguishes development, prerelease, and release artifacts. Only a clean checkout matching the version tag is marked as a release; this label is not publisher authentication. JSON includes optional `build` metadata; consumers must tolerate absent metadata and unknown diagnostic codes. `--version` retains its package-version format.

## Compatibility

Pin exact scanner versions in CI and consult the documentation for that release. Before 1.0, inspect release notes and regenerate reports when upgrading.

For the 1.0 contract, breaking changes to public CLI options, exit semantics or exported API types require a major release. Incompatible report or baseline formats require a format-version change and migration guidance. Package versions and data-format versions are separate: scan JSON is v1, new baselines are v4 (v2/v3 readable), stable fingerprints are v3, and SARIF is 2.1.0. Dispatch JSON by operation `kind` and `schemaVersion`; ordinary scan reports have no `kind`. Accept documented optional additions and unknown diagnostic codes, but reject unsupported format versions rather than interpreting them as clean results.

Rule additions and detection corrections can change findings without breaking an interface. Review result and baseline changes after upgrades. Rule IDs and source fingerprints identify findings; wording and line moves do not. HTML structure, embedded view data, terminal spacing and internal modules are not machine APIs. Use exported APIs and documented JSON instead. The editor preview has its own version; the Action commit and npm scanner version are selected independently.

For support, start with `--doctor --json` and review the output locally. It omits source, environment-variable values, baseline entries and remote addresses; it is not a project archive and is never uploaded automatically.

## Privacy and limits

- Static checks may miss issues or flag intentional configurations. Business authorisation, rate limiting, dependency vulnerabilities, and deployed settings are not verified.
- Redaction covers recognised formats only. Unknown secrets may remain in excerpts; `--no-excerpts` omits excerpts. Paths, names, and baseline descriptions remain visible.
- Google/Firebase/Maps `AIza…` keys are treated as public identifiers, not leak evidence alone. Supabase checks use local migrations and supported bucket configuration.
- Evaluation downloads, optional SARIF uploads, and explicitly confirmed deployment probes may use the network. Static scanning stays offline.
- Symbolic links are not followed; nested repositories and submodules need separate scans. In-scope skipped paths and analysis limits mark coverage incomplete; auth helper resolution limits are noted on the affected finding instead, because they cannot hide findings. Dependency and build directories excluded by default do not count as coverage gaps.

| Limit | Bound |
|---|---|
| File reads | 2 MiB per file; 128 MiB and 10,000 files per scan, including file-type probes |
| Directory discovery | 50,000 entries; 16 levels |
| OpenAPI batches | 256 items per call, including spreads; 8 array levels |
| Project router factories | 8 resolution steps; 4,000 expression characters; 256 candidates per file; 8 literal base-path calls |
| Factory module metadata | 65,536 UTF-16 code units per config; 128 path mappings; 64 workspace patterns; 8 export-condition levels, 32 entries per level |
| Route registration context | 512 regions per file; 32 statement levels; 4,000-character prefixes; 4,096 project graph sites; 256 inherited middleware references per site |
| Findings | 100 per file, prioritising severity and confidence |
| Git history | 100 relevant revisions per file; 30 seconds per command |
| Auth helper resolution | 8 hops; 64 symbols per helper, 1,024 per route file |
| Delegated writes | 2 call levels; 256 callees per file; writes beyond these limits are not reported |
| Identity/control flow | 8 value hops; 4,000 expression characters; 512 assignments/regions per function; 8 nested regions |
| Request-input tracking | 8 value hops; 512 assignments/regions; 64 KiB per expression; 8 URL-analysis levels; 200 static-prefix characters |
| Supabase policy/bucket parsing | 4,000 characters per statement |

Evidence traces are capped at 24 steps and disclose truncation.

## Development

Publishing is staged for human approval: stable versions use `latest`; prereleases use `next`. The workflow requires an exact SemVer version without build metadata and a matching Git tag. Pushing `main` does not publish. See [npm staged publishing](https://docs.npmjs.com/cli/v11/commands/npm-stage/).

From the repository root, after installing development dependencies, `node --import tsx scripts/prepare-sarif-validation.ts` previews five synthetic SARIF cases: initial findings, a repeat, moved lines, changed wording/version, and fewer findings. It does not scan, write files or upload. To verify GitHub alert continuity and closure, upload the reports with explicit approval and matching synthetic fixture commits on an isolated test branch.

The repository includes a [synthetic HTML demonstration](https://github.com/Tasomei/canship/blob/main/docs/demo.html). Download and open it locally; it is not included in the npm package and never scans a project. The page and copied prompts identify the data as examples. `npm run demo` previews HTML on stdout, `npm run demo -- --check` verifies the committed artifact, and explicit `npm run demo -- --write` regenerates it. Automated tests reject a stale demo.

The [VS Code extension](https://github.com/Tasomei/canship/tree/main/extensions/vscode#readme) is a development preview, separate from the npm package. See its README for host acceptance coverage and remaining checks. Marketplace publication is pending.

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

New rules require positive and negative [fixtures](https://github.com/Tasomei/canship/tree/main/test/fixtures/). Pinned project evaluation: [manifest](https://github.com/Tasomei/canship/tree/main/test/evaluation/projects.json), [fetch script](https://github.com/Tasomei/canship/blob/main/scripts/fetch-evaluation-projects.mjs), [evaluator](https://github.com/Tasomei/canship/blob/main/scripts/evaluate-projects.ts). Passing samples do not establish real-world detection rates.
