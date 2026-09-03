# Security Policy

## Reporting a vulnerability

Report it privately, through this repository's **Security** tab -> *Report a vulnerability*, so the
details stay out of public view until there is a fix. If that option is not offered, open an issue
saying only that you have found something and that you are waiting to be contacted — do not put
credentials, exploit details, or a complete reproduction in it.

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

Fixes target the latest published version only. Older versions stay on npm because unpublishing
breaks anyone who pinned them, not because they are still maintained.
