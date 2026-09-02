# Security Policy

## Reporting a vulnerability

No public source repository or private reporting address has been announced yet. Do not publish
credentials, exploit details, or a complete reproduction in a public issue. When the package
metadata names a repository or security contact, use that private channel.

Include the smallest file or directory layout that reproduces it, the version
(`npx canship --version`), and your OS. **Do not include real credentials** — every behaviour in
this project reproduces with a fake one.

This is a small project. There is no response-time guarantee; reports are read and acknowledged
when they are seen.

## What counts as a vulnerability

canship reads repositories it has no reason to trust and prints what it finds, so the boundary that
matters is between *a repository someone hands you* and *your terminal, your report, and the
assistant you paste into*. In scope:

- **A complete credential reaching the output** — terminal, `--json`, `--report` or `--fix-prompt`.
  Redaction is pattern-based and cannot mask a format it does not recognise, which the README states
  under Limits; a value in a format it *does* recognise arriving unmasked is this category.
- **File content changing the shape of the output rather than appearing in it** — terminal escape
  sequences, bidirectional overrides, or anything that lets a scanned file forge report lines.
- **canship running something from the repository it is scanning**, or reading outside the path it
  was pointed at.
- **A crafted file or directory layout that makes canship hang, exhaust memory, or run unbounded.**
- **`--fix-prompt` output that reads as an instruction to the assistant it is pasted into** rather
  than as quoted data.

## What does not

These are ordinary bugs, and they are wanted — open an issue rather than an advisory.

- **A missed detection.** A credential canship did not find is a false negative, and the README says
  plainly that pattern-based detection will miss things.
- **A false positive.**
- **A vulnerability in the project canship scanned.** That one belongs to whoever owns it.

## Supported versions

Before the first release, fixes target the current release candidate. After publication, fixes
target the latest published version only.
