# canship

A local static security scanner for JavaScript and TypeScript web projects. canship finds exposed credentials and common access-control mistakes without executing project code, uploading source files, or making network requests.

```bash
npx canship .
```

Requires Node.js 18 or later. The package has no runtime dependencies. Git is optional and is used only to inspect local commit history. If canship is not cached, `npx` may download it from npm before the scan begins.

[简体中文](./README.zh-CN.md)

## Checks

| Check | Typical impact | Severity |
|---|---|---|
| Hardcoded credentials | Exposes recognised OpenAI, Anthropic, AWS, Stripe, GitHub, npm, Slack, SendGrid, private-key, or database credentials | P0 |
| Private values in public environment variables | Includes private values in browser-delivered code | P0 |
| Client-accessible Supabase `service_role` keys | Bypasses Row Level Security policies | P0 |
| Credentials in Git-tracked `.env` files | Leaves credentials in local repository history | P0 |
| Supabase tables without RLS | Exposes rows through the Supabase Data API without row-level controls | P1 |
| Firebase rules allowing unconditional access | Permits unauthorised reads or writes | P1 |
| Unauthenticated Next.js API routes | Allows unverified callers to access data or administrative operations | P0 / P1 |
| Credentialed CORS with reflected origins | Allows another site to read authenticated responses | P1 |

API authentication checks apply to handlers under `app/api/**` and `pages/api/**`. The other checks are framework-independent and include public environment prefixes used by Next.js, Vite, Nuxt, Create React App, Expo, Gatsby, Vue CLI, and SvelteKit.

Severity describes potential impact. Confidence (`certain` or `likely`) describes the strength of the evidence. A `certain` P0/P1 finding blocks release with exit code `1`; other findings use exit code `2`.

## Usage

```bash
npx canship [path] [options]
```

The current directory is scanned when `path` is omitted.

| Option | Description |
|---|---|
| `-a`, `--all` | Show `likely` findings |
| `--json` | Write machine-readable JSON to stdout |
| `--fix-prompt` | Write remediation instructions for a coding assistant |
| `--report[=file]` | Write a self-contained HTML report; default: `canship-report.html` |
| `--sarif[=file]` | Write a SARIF 2.1.0 log; default: `canship.sarif` |
| `--best-effort` | Permit exit `0` for an incomplete scan with no findings |
| `--baseline[=file]` | Hide findings recorded in a baseline; default: `canship-baseline.json` |
| `--baseline-write[=file]` | Record current findings as a baseline and exit |
| `--only=ids` | Report only matching rule IDs; comma-separated and repeatable |
| `--skip=ids` | Exclude matching rule IDs; comma-separated and repeatable |
| `--no-config` | Ignore `canship.config.json` in the scanned directory |
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show the version |

`--json` and `--fix-prompt` are alternative stdout modes. `--report` may be combined with either.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Complete scan with no findings, or an incomplete finding-free scan accepted with `--best-effort` |
| `1` | At least one `certain` P0/P1 finding |
| `2` | Findings exist, but none is a `certain` P0/P1 blocker |
| `3` | Invalid arguments, a tool error, or an incomplete scan without `--best-effort` |

Findings take precedence over incomplete-scan status. Machine-readable output preserves incompleteness in `partial`, `errors`, and `skipped`.

By default, the terminal expands only `certain` findings. Hidden `likely` findings still produce exit code `2`; use `--all` to view them.

## Configuration

Commit project settings as `canship.config.json` in the scanned directory:

```json
{
  "baseline": "canship-baseline.json",
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

Supported keys are `baseline`, `only`, `skip`, and `all`. Command-line options override the file. `only` and `skip` cannot be combined, and selectors must match a complete rule ID or rule namespace. Rule IDs are available in JSON output.

The configuration is JSON because canship does not execute project code. When scanning untrusted code, use `--no-config` so the target cannot alter rule selection. `bestEffort` is intentionally available only as a command-line decision.

## Suppressions

Exclude an entire file with a standalone comment containing `canship-ignore-file`. Suppress a finding on the next line with `canship-ignore-next-line`:

```ts
// canship-ignore-next-line
const documentedExample = "sk-proj-not-a-real-key"
```

Append a rule ID to narrow the suppression:

```ts
// canship-ignore-next-line secrets/hardcoded/openai
const key = process.env.OPENAI_KEY
```

Markers must occupy the whole comment line. Suppressed findings and excluded files remain visible in reports; they do not make the scan incomplete.

## Baselines

Use a baseline to adopt canship in a project with existing findings:

```bash
npx canship --baseline-write
npx canship --baseline
```

The first command records current findings; the second reports only new ones. Baselines contain hashes rather than source excerpts, but they still disclose file paths, rule IDs, finding titles, and unresolved issue types. Review a baseline before committing it, especially in a public repository.

Baseline format version 2 fingerprints the original source evidence before redaction and excludes line numbers, so moving a finding does not make it new while replacing a credential does. Version 1 baselines are rejected with exit code `3`; review the findings and regenerate the file with `--baseline-write`.

Every output reports how many findings a baseline suppressed. Missing, malformed, or incompatible baselines fail closed with exit code `3`.

## Scope and limitations

- canship uses static heuristics and cannot verify runtime behaviour. Custom authentication, dynamic configuration, and unsupported syntax may produce false positives or false negatives.
- Detection and redaction use the same credential patterns. Unrecognised secrets cannot be guaranteed to be masked; treat reports as internal material.
- Files are limited to 2 MiB, traversal to 16 directory levels, output to 100 findings per file, and Git inspection to the 100 most recent relevant revisions per file. Reaching a limit is reported explicitly.
- Symbolic links are not followed. Nested Git repositories and submodules are listed as skipped; these conditions make the scan incomplete.
- Google, Firebase, and Maps `AIza...` values are treated as public identifiers because their server-side restrictions cannot be verified from source alone.
- Rate limiting, injection, dependency vulnerabilities, and business authorisation beyond caller authentication are outside the scan scope.

A clean result means only that the implemented rules found no issue in the files that were read. It is not proof that the project is secure.

## Contributing

Changed detection rules should include a positive and a negative fixture under [`test/fixtures/`](./test/fixtures/).

```bash
npm ci
npm run prepublishOnly
```

## License

[MIT](./LICENSE)
