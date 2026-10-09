# Canship for VS Code

[简体中文](https://github.com/Tasomei/canship/blob/main/extensions/vscode/README-zh-CN.md)

Development extension; not a published Marketplace release. Requires VS Code 1.95 or later and a trusted local-filesystem workspace.

Run **Canship: Scan Workspace** to inspect saved files. Multi-root workspaces require non-overlapping roots and select one project per scan. Findings appear in Problems and hover text; **Show Scan Summary** discloses hidden findings, baselines, exclusions, and incomplete coverage.

- Bundles its scanner; never runs a workspace's `npx`, scripts, or scanner binary.
- Uses the selected folder's Canship configuration and configured baseline. Application-level settings can disable them or include likely findings.
- Save-triggered scanning is opt-in and debounced. Cancellation, source edits, and settings changes invalidate pending results.
- **Copy Finding Fix Prompt** copies one current finding. **Review Line Suppression** previews a rule-specific comment and requires confirmation; it edits the buffer without saving. Unsupported syntax or changed source must use manual review or a CLI baseline.
- Scans saved files only. Unsaved buffers and external changes require a fresh scan. Comments in JSX, JSON, and ambiguous string contexts are not edited automatically.

No telemetry, project uploads, or scan-time network requests. Excerpts are omitted; paths, descriptions, and copied prompts can still be sensitive. Reports describe static evidence, not proof that deployment or authorization is correct. The editor displays at most 5,000 findings per scan and discloses omitted counts.

## Development

### Local package

Requires Node.js 22 or later for packaging tools only; the scanner's runtime requirement is unchanged. From the repository root:

```powershell
npm run package:extension
```

This installs locked development tools locally, builds both entry points, and verifies the VSIX file list and bytes. Tool installation may use the network. The uniquely named package is written to `.scratch/vsix/`; existing packages are not overwritten. No Marketplace login or publication occurs.

The VSIX contains the manifest, two runtime files, both READMEs and the license, plus two format metadata files. Source, tests, logs and local configuration are excluded. `npm run test:extension-package` also tests rejection cases and runs the packaged worker outside the source tree.

Install the generated file with **Extensions: Install from VSIX** in the target VS Code window. Installation, activation, scanning and source navigation were verified in an isolated Windows / VS Code 1.141.0 profile, without development-host flags. This does not publish the extension or verify other editor versions.

### Development host

From the repository root:

```powershell
npm run build:extension
```

Launch an isolated Extension Development Host with this directory as `--extensionDevelopmentPath`. Do not change your normal editor profile for testing. Marketplace publication and publisher registration are separate release steps.

Host tests use `scripts/run-editor-host.mjs` with an installed VS Code executable's absolute path. They use an isolated profile and synthetic workspace without disabling Workspace Trust. Windows / VS Code 1.141.0 passed the eight basic checks and nine workflow checks: saves off by default, enabled saves, final results after consecutive saves, disabled saves, project selection, per-project configuration, retained sibling results, cancellation without success, and clearing. VS Code 1.95 and other versions/platforms remain unverified.

Use `--workflows` for save, cancellation and multi-root checks; follow the named project buttons and picker. `--prepare` opens manual checks; `--session=<absolute-test-directory>` reuses a validated session without overwriting results. Confirm trust in the active window. Trust timeout, incomplete selection or an unobserved cancellation window reports `blocked`, never a pass. Failures show their stage; successful tests close automatically. Temporary settings are restored and generated load files removed; session results stay local.
