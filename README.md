# canship

canship is a read-only static scanner for JavaScript and TypeScript web projects. It detects exposed credentials, misuse of public environment variables, and access-control misconfigurations in Next.js, Vite, Nuxt, Create React App, Expo, Supabase, and Firebase projects.

The scan does not execute project code, upload content, or initiate network requests. The npm package has no runtime dependencies. When scanning a Git repository, canship reads only the local working tree and local commit history.

```bash
npx canship
```

Node.js 18 or later is required. Git is optional; only commit-history checks require a local Git installation and a readable repository. If canship is not already in the npm cache, `npx` may download it from the npm registry before the scan starts; that download is performed by npm and is not part of the scan.

[简体中文](./README.zh-CN.md)

## Checks

| Check | Risk | Severity |
|---|---|---|
| Hardcoded credentials | A scanned file contains a recognised OpenAI, Anthropic, AWS, Stripe, GitHub, npm, Slack, SendGrid, private-key, or database credential | P0 |
| Private values in public environment variables | The value may be included in browser-delivered code | P0 |
| Supabase `service_role` key reachable from client code | A `service_role` key can bypass Row Level Security (RLS) policies | P0 |
| Git-tracked `.env` files | Recognised credentials remain in repository history; substantial unrecognised values may also produce a lower-confidence finding | P0 |
| Supabase tables without RLS | A table exposed through the Supabase Data API lacks row-level access control | P1 |
| Firebase rules allowing unconditional access | Unauthorised clients may be able to read or write data | P1 |
| Next.js API routes accessing data without authentication | An unverified caller may access data or perform administrative operations | P0 / P1 |
| CORS reflecting `Origin` while allowing credentials | Another site may access an endpoint with the user's credentials and read the response | P1 |

Severity (P0, P1, P2) describes potential impact. Confidence (`certain`, `likely`) describes how strongly the code supports the finding. A `certain` P0/P1 finding blocks release and exits with status `1`; all other findings exit with status `2`.

`Access-Control-Allow-Origin: *` combined with credentials is reported at P2 because browsers reject that configuration. A bare wildcard is not reported.

For Git-tracked `.env` files, a recognised credential is reported at `certain` confidence. A substantial value that is not recognised but does not look public or placeholder-like is reported at `likely` confidence. Environment templates, public values, placeholders, and short settings do not trigger this Git rule solely because the file is tracked.

## Usage

```bash
npx canship [path]
```

The current directory is scanned when no path is provided.

| Option | Description |
|---|---|
| `-a`, `--all` | Show `likely` findings |
| `--json` | Write machine-readable JSON |
| `--fix-prompt` | Write remediation instructions for a coding assistant |
| `--report[=file]` | Write a self-contained HTML report; defaults to `canship-report.html` |
| `--best-effort` | Allow exit `0` when the scan is incomplete and has no findings; does not change the status of existing findings |
| `--baseline[=file]` | Hide findings recorded in the baseline, so only new ones are reported; defaults to `canship-baseline.json` |
| `--baseline-write[=file]` | Record the current findings as a baseline and exit; defaults to `canship-baseline.json` |
| `--only=ids` | Report only these rules; comma-separated and repeatable |
| `--skip=ids` | Report everything except these rules; comma-separated and repeatable |
| `--sarif[=file]` | Write a SARIF 2.1.0 log for CI code scanning; defaults to `canship.sarif` |
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show the version |

`--json` and `--fix-prompt` are mutually exclusive. `--report` writes a separate file and may be combined with either mode.

### Exit status

| Status | Meaning |
|---|---|
| `0` | No findings at any confidence and the scan completed; with `--best-effort`, it may also mean an incomplete scan was accepted |
| `1` | At least one `certain` P0/P1 finding |
| `2` | Findings exist, but none is a confirmed P0/P1 release blocker |
| `3` | Invalid arguments, a tool error, or an incomplete scan without `--best-effort` |

When findings and an incomplete scan coexist, status `1` or `2` takes precedence. The JSON fields `partial`, `errors`, and `skipped` still preserve the incomplete-scan state.

The default view expands only `certain` findings. Hidden `likely` findings still produce status `2`; the terminal and HTML report display a warning, and JSON reports the count in `hiddenLikely`. Use `--all` to include their full details.

### Excluding a file

Add `canship-ignore-file` on a line by itself to exclude the entire file. The marker may be wrapped only in `//`, `#`, `--`, `*`, `/* */`, or `<!-- -->` comment syntax. Intentionally excluded files are listed in the report and do not make the scan incomplete.

### Excluding a single line

Add `canship-ignore-next-line` on the line above a finding to suppress it there. The same comment syntax applies, and the marker must be the whole content of its line — a line that also holds code or prose does not suppress anything.

```ts
// canship-ignore-next-line
const documentedExample = "sk-proj-not-a-real-key"
```

A bare marker suppresses every rule on the following line. A rule id after it narrows the suppression to that rule, so a line with one known false positive is not also blind to a different finding:

```ts
// canship-ignore-next-line secrets/hardcoded/openai
const key = process.env.OPENAI_KEY
```

Rule ids appear in `--json` output; the terminal and HTML reports do not print them, which is why the bare form exists.

The marker governs the line immediately after it, with no allowance for blank lines. Suppressed findings are listed by file, line, and rule in the terminal, the HTML report, and the `ignoredFindings` field of `--json`. They do not make the scan incomplete, and the report states that the result is not finding-free.

### Configuration

Settings a project makes once can be committed to `canship.config.json` in the scanned directory. A command-line flag always overrides the file.

```json
{
  "baseline": "canship-baseline.json",
  "skip": ["cors/wildcard-with-credentials"],
  "all": false,
  "bestEffort": false
}
```

| Setting | Equivalent flag |
|---|---|
| `baseline` | `--baseline=file` |
| `only` | `--only=ids` |
| `skip` | `--skip=ids` |
| `all` | `--all` |
| `bestEffort` | `--best-effort` |

The format is JSON and not JavaScript. A `canship.config.js` would be project code, and the scan does not execute project code.

An unknown setting, a wrong type, a rule id that names no rule, or `only` and `skip` together are all errors and exit `3`. A missing config file is not an error.

### Selecting rules

`--only` and `--skip` take the rule ids that appear in `--json` output, comma-separated and repeatable. A selector matches an id exactly, or matches every id beneath it at a `/` boundary — `secrets` covers every credential format, `secrets/hardcoded/openai` covers one. A partial id such as `secrets/hardcoded/open` matches nothing and is rejected, so a mistyped id cannot quietly disable a rule.

`--only` and `--skip` cannot be combined. Selection filters findings rather than skipping the rules themselves, so it does not reduce scan time. Every report states which selection was in force and how many findings it hid.

### Baseline

An existing project usually has findings on the first run. A baseline records them so that subsequent runs report only what appeared afterwards, which is what makes canship usable in continuous integration for a project that did not start with it.

```bash
npx canship --baseline-write   # accept the current findings
npx canship --baseline         # report only new ones
```

`--baseline-write` writes `canship-baseline.json` and exits `0` without scanning further. Commit that file: it is the record of what was accepted, and it is meant to be reviewed in the pull request that adds it.

**Consider what committing it publishes.** Each entry names a file path, a rule id, and a finding title, and every entry describes a problem that has not been fixed. canship searches gitignored credential files by design, so an entry may describe a file the repository does not contain — `.env.local` and the name of a variable in it, for example. The file holds no credential values. On a private repository this is the intended use; on a public one, weigh the disclosure before committing.

Paths are resolved where they came from: a path typed on the command line is relative to the working directory, a bare `--baseline` or `--baseline-write` uses the scanned project's own `canship-baseline.json`, and a path in `canship.config.json` is relative to that file. So `npx canship ./app --baseline-write` writes into `./app`, which is where `npx canship ./app --baseline` then looks.

A baseline entry is matched by rule, file, title, and a hash of the excerpt. The line number is deliberately excluded, so editing a file above a finding does not report it as new. Each entry carries the number of times it was seen; an additional occurrence beyond that count is reported.

The baseline stores a SHA-256 hash rather than the excerpt itself, because the file is intended to be committed and canship cannot guarantee that an unrecognised credential is masked.

A baseline hides real findings. Every output states how many:

- the terminal and HTML report never show a clean result while a baseline is suppressing findings, and name the count and the file
- `--json` reports `baselineSuppressed`
- baseline entries that no longer match anything are reported as `baselineStale`; they do not affect the exit status

Findings of every confidence are recorded. A baseline that cannot be read — missing, malformed, or written by a different format version — exits `3` rather than proceeding with no suppression. `--baseline` and `--baseline-write` cannot be combined.

### Remediation instructions

`--fix-prompt` separates code changes that a coding assistant can perform from actions that require the project maintainer, such as rotating credentials, changing provider settings, or rewriting Git history.

## Rule activation

| Rule | Activation conditions |
|---|---|
| Public environment variables | The name starts with `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`, `VUE_APP_`, or `PUBLIC_` |
| Git-tracked environment files | The target is inside a readable local Git repository whose `.git` metadata is inside the checkout or names it back; templates, public values, placeholders, and short settings are excluded, and at most the 100 most recent relevant revisions of each file are inspected |
| Next.js API authentication | Only data-accessing handlers under `app/api/**` and `pages/api/**`; recognises enforcing authentication calls, identity conditions that control rejection, and middleware `matcher` coverage for the route |
| Supabase RLS | The current project scope contains `supabase/`, an `@supabase/supabase-js` or `@supabase/ssr` import, or a `SUPABASE_URL`; table-related DDL is replayed across migrations within that project scope |
| Other credential and configuration rules | Match known file formats and content patterns without requiring a specific front-end framework |

## Known limitations

- canship uses static heuristics and does not verify runtime behaviour. Custom authentication wrappers, dynamic configuration, and unsupported syntax can cause false positives or false negatives.
- Detection and redaction use the same credential patterns. A credential that canship cannot recognise cannot be guaranteed to be masked; if another rule quotes the same line, the original value may appear in the report. Treat reports as internal material.
- Entropy-based detection is intentionally not used because random identifiers, hashes, and ordinary Base64 text cannot be classified reliably from entropy alone.
- Files are limited to 2 MiB, traversal to 16 directory levels, and output to 100 findings per file. Git history checks inspect at most the 100 most recent relevant revisions of each file. Reaching a limit is recorded explicitly.
- Symbolic links are not followed and make the scan incomplete.
- Nested Git repositories and submodules are not expanded by the parent scan. They are listed as skipped and the parent scan is marked incomplete.
- A `.git` file may point outside the checkout. canship follows it only when the target names this checkout back, which is what git records for a linked worktree and for a submodule. Anything else is read as a redirect to an unrelated repository: file scanning continues, history checks are marked incomplete.
- Google, Firebase, and Maps `AIza...` keys are treated as public identifiers. Their application and API restrictions exist in Google Cloud and cannot be verified from local source, so the key value alone is not reported as a credential leak.
- Rate limiting, injection, dependency vulnerabilities, and business authorisation beyond caller authentication are outside the scan scope.

A canship result describes only what the implemented rules observed in the files that were read. It is not proof that the project has no other security defects.

## Planned

`--probe` is not implemented. The planned mode would, after explicit confirmation, issue read-only verification requests to service endpoints found in local project configuration. The current release does not initiate network requests.

## Contributing

Every new or changed detection rule should include at least two fixtures: one that must be reported and one that must not. See [`test/fixtures/`](./test/fixtures/).

```bash
npm ci
npm run prepublishOnly
```

## License

[MIT](./LICENSE)
