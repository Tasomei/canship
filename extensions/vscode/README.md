# Canship for VS Code

[简体中文](https://github.com/Tasomei/canship/blob/main/extensions/vscode/README-zh-CN.md) · [CLI](https://github.com/Tasomei/canship#readme) · [Rule reference](https://github.com/Tasomei/canship/blob/main/docs/reference.md)

Pre-deployment security checks for JavaScript and TypeScript web apps, in the editor. Finds exposed credentials, missing access controls and unsafe handling of request input, using the same scanner as the `canship` CLI.

Preview. Requires VS Code 1.95 or later and a trusted local workspace.

## Usage

Run **Canship: Scan Workspace** from the Command Palette. Findings appear in the Problems panel.

| Command | Purpose |
| --- | --- |
| Scan Workspace | Scan saved files in the selected folder |
| Cancel Scan | Stop the running scan; no partial results are kept |
| Clear Results | Remove Canship diagnostics |
| Show Scan Summary | List hidden findings, baselines, exclusions and incomplete coverage |
| Copy Finding Fix Prompt | Copy a fix prompt for one finding, for use with a coding assistant |
| Review Line Suppression | Preview a rule-specific suppression comment; edits the buffer only after confirmation |

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `canship.scanOnSave` | `false` | Scan after saves |
| `canship.saveDelay` | `750` | Delay in milliseconds before a save-triggered scan |
| `canship.includeLikely` | `false` | Show likely findings as well as certain ones |
| `canship.useProjectConfig` | `true` | Use the folder's Canship config and baseline |
| `canship.honorIgnoreMarkers` | `true` | Honour suppression comments in source |

## Notes

- Scans saved files only. Rescan after unsaved or external changes.
- Uses its bundled scanner; never runs the workspace's `npx`, scripts or binaries.
- Multi-root workspaces must not overlap; each scan covers one project.
- Suppression comments are not inserted in JSX, JSON or ambiguous string contexts.
- Shows up to 5,000 findings per scan and reports any omitted.
- Findings are static evidence, not proof that a deployment or its authorisation is correct.

## Privacy

No telemetry, uploads or network requests. Diagnostics omit source excerpts; file paths, descriptions and copied prompts may still be sensitive.

## Development

From the repository root:

```powershell
npm run build:extension
```

Builds both entry points for an Extension Development Host.

```powershell
npm run package:extension
```

Builds and verifies a VSIX in `.scratch/vsix/` (Node.js 22 or later). Nothing is published. Editor host tests use `scripts/run-editor-host.mjs` with an isolated profile; verified on Windows with VS Code 1.141.0.
