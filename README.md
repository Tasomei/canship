# canship

A local static scanner for JavaScript and TypeScript web apps. Detects exposed credentials, access-control misconfiguration, and unsafe request-input flows.

Static scans are offline, read-only, and execute no project code. Deployment probes are separate and require explicit plan confirmation.

[简体中文](./README-zh-CN.md) · [Reference](./docs/reference.md) · [npm](https://www.npmjs.com/package/canship)

> Development branch. For npm `0.7.1`, see the [release documentation](https://github.com/Tasomei/canship/blob/v0.7.1/README.md). Features documented here may not be published yet.

## Scan a project

Requires Node.js ≥18. No runtime dependencies; installation may use the network.

```powershell
npx canship
```

To scan another directory:

```powershell
npx canship "./my-app"
```

Git checks inspect locally tracked files and commit history without contacting remotes. Unreadable history marks coverage incomplete.

The following screenshots use synthetic data from a development build.

![Terminal report](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/terminal.png)

## Checks

| Category | Severity | Scope |
|---|:---:|---|
| Credentials | `P0` | Hardcoded credentials, public env exposure, Supabase admin keys, non-template `.env` files tracked by Git or present in history |
| API access | `P0/P1` | Database operations without recognised authentication, server-side trust in Supabase `getSession()`, unverified Stripe webhooks |
| Database rules | `P1/P2` | Supabase RLS, unconditional policies and public object listing; Firebase open rules and test-mode expiry |
| CORS | `P1/P2` | Reflected or wildcard origins with credentials |
| Request input | `P1/P2` | SQL and command construction, caller-controlled request hosts and redirect targets |

Route analysis supports documented entry points in Next.js, SvelteKit, Nuxt, Remix / React Router, Astro, Express, Hono and Fastify—not arbitrary framework behaviour. See [entry points and limits](./docs/reference.md#server-entry-points).

```powershell
npx canship --list-rules
```

## Review results

Reports are in English. `certain` means strong static evidence; `likely` requires review. Tests and examples are downgraded to `likely`. Neither confidence level proves credential validity or exploitability.

Show all confidence levels and detailed evidence:

```powershell
npx canship --all --verbose
```

Generate an offline HTML report:

```powershell
npx canship --all --report
```

![HTML report](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/report.png)

[Synthetic HTML sample](https://github.com/Tasomei/canship/blob/main/docs/demo.html): download the file and open it locally; no scanner installation is required.

HTML provides severity/confidence filters, stable finding links, and copyable repair prompts. Use `--no-excerpts` to omit excerpts; paths and other project text remain. For counts without project text, use `--share-summary` and review before sharing.

| Exit | Static scan result |
|---|---|
| `0` | No findings; coverage complete or accepted with `--best-effort` |
| `1` | At least one `certain` P0/P1 finding |
| `2` | Other findings, including hidden `likely` results |
| `3` | Invalid arguments, tool error, or unaccepted incomplete coverage |
| `130` / `143` | Interrupted by SIGINT / SIGTERM; no scan report generated |

Status is calculated after rule selection, source suppressions and baselines. Findings take precedence over incomplete coverage; `--best-effort` never changes `1` or `2`. Check JSON `partial`, `errors`, `skipped` and `filesScanned` separately.

Baselines accept findings; they do not fix them. Review existing decisions, accept selected results, and set optional reasons or expiry through [baseline management](./docs/reference.md#configuration). [Saved-report comparison](./docs/reference.md#cli) provides terminal, JSON and offline HTML views of added, persisting and no-longer-observed records without claiming remediation.

## Connect to CI

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

The hash pins the Action implementation; `version` selects the published npm scanner, not development-branch source. The Action uses Node.js 22, does not install or run project dependencies, and writes a counts-only summary.

| Input | Pinned Action default | Meaning |
|---|---|---|
| `version` | `0.7.0` | Exact npm scanner version; overridden above |
| `fail-on` | `blocking` | `blocking`: certain P0/P1; `any`: all findings; `none`: report only |

Incomplete scans and tool errors always fail. Project configuration and SARIF upload are disabled by default. Upload requires `security-events: write` and code scanning support; review reports first. Use `pull_request`, not `pull_request_target`, for untrusted PRs. See [Action inputs](https://github.com/Tasomei/canship/blob/main/action.yml).

## Advanced use

[Full CLI reference](./docs/reference.md#cli) covers JSON/SARIF output, rules, configuration, exclusions, independent workspaces, diagnostics and template previews. The [API](./docs/reference.md#api-and-structured-output) returns structured findings without loading project configuration or writing files.

The pre-commit template scans the **working tree, not the staged snapshot**. Deployment probes are opt-in, HTTPS-only and unauthenticated; [review their scope and privacy limits](./docs/reference.md#deployment-probes) before use.

The [VS Code extension](https://github.com/Tasomei/canship/tree/main/extensions/vscode#readme) is a separate development preview. See its README for local VSIX packaging and verified host coverage. Marketplace publication is pending.

## Privacy and limitations

- Static analysis may miss issues or flag intentional configurations. It does not verify business authorisation, rate limiting or dependency vulnerabilities.
- Redaction covers recognised formats only. Unknown sensitive values may remain in excerpts; detailed reports and baselines should be treated as internal material.
- Google/Firebase/Maps `AIza…` keys are public identifiers, not leak evidence alone.
- Symbolic links are not followed. Nested repositories and submodules need separate scans. In-scope skips and analysis limits are disclosed; default dependency/build exclusions are not coverage gaps.
- Explicit deployment probes contact the approved target; installation, evaluation downloads and optional SARIF upload may also use the network. Static scans remain offline.

See [resource bounds and coverage limits](./docs/reference.md#privacy-and-limits).

## Development and license

Run `npm ci`, `npm run prepublishOnly`, `npm run test:package` and `npm run evaluate` separately. New rules require positive and negative fixtures; passing samples do not establish real-world detection rates. See [development reference](./docs/reference.md#development).

[MIT](./LICENSE). Supabase/Firebase fixtures retain Apache-2.0; Next.js/`cors` fixtures retain MIT.
