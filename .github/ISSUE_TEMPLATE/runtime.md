---
name: Installation, runtime or performance
about: Report installation failures, crashes, incomplete scans or performance problems.
title: ''
labels: ''
assignees: ''
---

Do not include real credentials, personal data, internal paths, environment dumps, or a private repository. Review any diagnostic output before sharing. For a vulnerability in Canship itself, follow the [security policy](https://github.com/Tasomei/canship/security/policy).

### Environment

- Canship version or development revision:
- Node.js version:
- Operating system:
- Installation method (npm, Action, or source):

### Reproduction

Provide the command with private paths replaced and a minimal synthetic example if possible. State the exit code and diagnostic code rather than attaching the whole report.

### Expected and actual behavior

For performance issues, include approximate file count and size, elapsed time, and whether Git history was checked. These counts may also be sensitive; omit details you cannot share.

### Optional diagnostics

Review `canship --doctor --json` locally before including relevant checks. Do not paste system environment variables, authentication files, or full debug logs.

### Privacy review

- [ ] I reviewed the reproduction and removed credentials, personal data, and internal identifiers.
