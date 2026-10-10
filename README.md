# canship

Pre-deployment security checks for JavaScript and TypeScript web applications. Canship finds exposed credentials, missing access controls and unsafe handling of request input in your source code, and can optionally probe a deployment you own.

Static scans run locally: they are read-only, execute no project code and make no network requests. Deployment probes are a separate, opt-in mode that contacts only a target you confirm.

[简体中文](./README-zh-CN.md) · [Reference](./docs/reference.md) · [Releases](https://github.com/Tasomei/canship/releases) · [npm](https://www.npmjs.com/package/canship)

> Documentation for `0.8.0` on npm `latest`. Other versions are listed under [Releases](https://github.com/Tasomei/canship/releases).

## Quick start

Requires Node.js 18 or later; no runtime dependencies.

```powershell
npx canship@0.8.0
```

Scan a specific directory:

```powershell
npx canship@0.8.0 "./my-app"
```

Example output for a synthetic project:

![Terminal report](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/terminal.png)

## Checks

| Category | Severity | Covers |
|---|:---:|---|
| Credentials | `P0` | Hardcoded secrets, secrets in public environment variables, Supabase service keys, `.env` files tracked by Git or present in history |
| API access | `P0/P1` | Database operations without recognised authentication, server-side trust in Supabase `getSession()`, unverified Stripe webhooks |
| Database rules | `P1/P2` | Missing Supabase RLS, permissive policies, public storage listing, open Firebase rules |
| CORS | `P1/P2` | Reflected or wildcard origins combined with credentials |
| Code | `P1/P2` | SQL and shell commands built from request input; server-side requests and redirects to caller-chosen URLs |

Route analysis covers documented entry points in Next.js, SvelteKit, Nuxt, Remix / React Router, Astro, Express, Hono and Fastify. See [entry points and limits](./docs/reference.md#server-entry-points).

```powershell
npx canship@0.8.0 --list-rules
```

## Reviewing findings

Each finding is rated `certain` (strong static evidence) or `likely` (needs review); only `certain` findings are shown by default. Neither rating proves that a credential is valid or that an issue is exploitable.

```powershell
npx canship@0.8.0 --all --verbose
```

```powershell
npx canship@0.8.0 --all --report
```

![HTML report](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/report.png)

The offline HTML report supports filtering and copyable repair prompts; `--fix-prompt` prints the same instructions in the terminal. Reports include file paths and may include source excerpts: use `--no-excerpts` to omit excerpts, or `--share-summary` for counts only. A [synthetic sample report](https://github.com/Tasomei/canship/blob/main/docs/demo.html) is available for download.

| Exit code | Meaning |
|---|---|
| `0` | No findings, with complete coverage (or incomplete coverage accepted via `--best-effort`) |
| `1` | At least one `certain` P0/P1 finding |
| `2` | Other findings, including hidden `likely` findings |
| `3` | Invalid input, tool error, or incomplete coverage |

## Continuous integration

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
      - uses: Tasomei/canship@8ae4d5f4508fbd68fc2cf440e138c1217064a0e0
        with:
          version: '0.8.0'
          honor-ignore-markers: false
```

The commit hash pins the Action and `version` pins the npm scanner. The Action does not install project dependencies and writes a counts-only job summary; it always fails on incomplete scans or tool errors. SARIF upload is opt-in.

| Input | Default in the pinned Action | Meaning |
|---|---|---|
| `version` | `0.8.0` | Exact npm scanner version; set explicitly as above |
| `fail-on` | `blocking` | `blocking`: `certain` P0/P1; `any`: all findings; `none`: report only |

See all [Action inputs](https://github.com/Tasomei/canship/blob/main/action.yml).

## Beyond scanning

- **Baselines**: accept reviewed findings with an optional reason and expiry date. See [baseline management](./docs/reference.md#configuration).
- **Report comparison**: compare two saved JSON reports to list added, persisting and no-longer-observed findings. See the [CLI reference](./docs/reference.md#cli).
- **Workspaces and configuration**: scan monorepo packages independently, exclude paths, and inspect effective settings with `--explain-config` or `--doctor`.
- **Templates**: preview CI and pre-commit setups with `--init`. The pre-commit hook scans the working tree, not the staged snapshot.
- **Deployment probes**: `--probe=https://…` previews a small set of unauthenticated HTTPS requests; nothing is sent until you confirm the plan. Review the [scope and privacy notes](./docs/reference.md#deployment-probes) first.
- **API and editor**: a [programmatic API](./docs/reference.md#api-and-structured-output) and a [VS Code extension preview](https://github.com/Tasomei/canship/tree/main/extensions/vscode#readme).

## Limitations

- Static analysis can miss issues or flag intentional configurations. It does not assess business authorisation, rate limiting or dependency vulnerabilities.
- Redaction covers recognised secret formats only. Treat detailed reports and baselines as internal material.
- Google and Firebase `AIza…` keys are public identifiers and are not reported as leaks on their own.

See [privacy and coverage limits](./docs/reference.md#privacy-and-limits).

## Development and license

See the [development reference](./docs/reference.md#development). Licensed under [MIT](./LICENSE); Supabase and Firebase test fixtures retain Apache-2.0, and Next.js and `cors` fixtures retain MIT.
