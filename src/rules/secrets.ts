/**
 * P0-1: secrets hardcoded in source code.
 *
 * Division of labour: this rule **deliberately skips .env files.**
 * Holding secrets is what .env is for, so flagging it is pure noise. The two
 * real risks around .env are handled elsewhere:
 *   - a secret carrying a public prefix, bundled into the frontend -> exposure.ts
 *   - the .env file itself being committed to git                  -> gitleak.ts
 */

import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { redactLine } from '../redact.js'
import { basename } from 'node:path'
import { isEnvFile } from '../walker.js'
import { SECRET_PATTERNS, isPlaceholder, isCommentedOut, secretPartOf } from './patterns.js'
import { isClientCode } from './framework.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'


export const secretsRule: Rule = {
  id: 'secrets/hardcoded',
  severity: 'P0',

  appliesTo(file: ScanFile): boolean {
    // The .env family is handled entirely by the exposure rule (see header) —
    // with one exception. A template like `.env.example` is not where secrets
    // are supposed to live; it is the file people commit *instead of* the one
    // holding them, which makes a real key in it public by design. Three rules
    // each had a good reason to skip it, and between them nothing looked
    // inside at all.
    if (isEnvFile(basename(file.path))) return file.isExampleContext
    return true
  },

  check(file: ScanFile, ctx: ScanContext): Finding[] {
    const findings: Finding[] = []
    // Built once per file instead of counted from the start of the file for
    // every match. See offsets.ts.
    const lineStarts = lineStartsOf(file.content)

    for (const pat of SECRET_PATTERNS) {
      // A value the issuing provider designed to ship in client code (a
      // Firebase apiKey, a Maps Platform key) is not a leak here whatever the
      // file is — see the note on SecretPattern.publicByDesign.
      if (pat.publicByDesign) continue
      // The pattern carries the g flag and is reused, so lastIndex must be
      // reset before every use.
      pat.pattern.lastIndex = 0
      let match: RegExpExecArray | null

      if (findings.length >= MAX_FINDINGS_PER_FILE) break

      while ((match = pat.pattern.exec(file.content)) !== null) {
        // A ceiling, and one that says so. A file under the size cap can still
        // hold thousands of secret-shaped strings, and every one of them used
        // to become a finding with its own paragraphs of explanation — enough
        // to make the report, the HTML and the JSON larger than the input by
        // orders of magnitude. Stopping is fine; stopping quietly would be the
        // same silence this rule has been fixing all round.
        if (findings.length >= MAX_FINDINGS_PER_FILE) {
          ctx.reportIncomplete(
            'secrets/hardcoded',
            `${file.path} holds more than ${MAX_FINDINGS_PER_FILE} credential-shaped strings; ` +
              `the rest were not reported`,
          )
          break
        }
        const secret = match[0]
        // Placeholder checking targets the secret itself (e.g. the password
        // inside a connection string), not unrelated parts like the host.
        if (isPlaceholder(secretPartOf(match, pat))) continue
        // Correctly formatted but pointing somewhere meaningless — skip.
        if (pat.ignoreIf?.(match)) continue

        const line = lineNumberAt(lineStarts, match.index)
        const rawLine = file.lines[line - 1] ?? ''

        // The same secret is a very different problem depending on where it
        // lives: in client code every visitor can read it, in server code it is
        // "this is now in your git history". Getting that wrong would misdirect
        // the user's fix priority.
        const clientSide = isClientCode(file)

        const parts: string[] = [pat.impact]
        if (clientSide) {
          parts.push(
            `This file is client-side code — it is sent to the browser in full. ` +
              `Any visitor can open dev tools and read this key straight out of your bundle. ` +
              `You do not need to be attacked for this to leak; it is already public to everyone who loads the page.`,
          )
        } else {
          parts.push(
            `Hardcoding it in source means it goes into your git history, and it will be bundled into the browser ` +
              `if this file is ever imported from client-side code.`,
          )
        }
        if (isCommentedOut(rawLine)) {
          parts.push(
            `Commenting the line out does not help — the key is still in the file, and if this file is in git, it is in your history forever.`,
          )
        }

        const fix = [
          `Remove the key from this file.`,
          clientSide
            ? `Move the code that uses it to the server (an API route or server action), and keep the key in .env without a public prefix.`
            : `Put it in .env and read it with process.env (never with a NEXT_PUBLIC_ prefix).`,
          `Make sure .env is listed in .gitignore.`,
        ]

        // Rotation cannot be automated and is the only step that actually
        // revokes the leaked key, so it is kept out of the code-fix list.
        const humanOnly = [
          `Rotate this ${pat.rotateLabel ?? pat.name}${pat.rotateAt ? ` at ${pat.rotateAt}` : ''}. Treat the old one as compromised — ` +
            (clientSide
              ? `if this page has ever been deployed, assume the key is already in someone else's hands.`
              : `if this file was ever pushed, assume it has already been scraped.`),
        ]

        // Tests, fixtures, examples and docs are where fake keys live, so a
        // match here is usually scaffolding — but only usually. A real key
        // committed in a test file is exactly as stolen as one in src/, and
        // waving the whole directory through is how those go unreported for
        // years. Lower confidence, hidden by default, still findable with
        // --all; add canship-ignore-file to silence a file for good.
        const scaffolding = file.isExampleContext

        findings.push({
          ruleId: `secrets/hardcoded/${pat.id}`,
          severity: 'P0',
          confidence: scaffolding ? 'likely' : 'certain',
          title: scaffolding
            ? `${pat.name} is hardcoded in a test or example file`
            : clientSide
              ? `${pat.name} is hardcoded in code that runs in the browser`
              : `${pat.name} is hardcoded in your source code`,
          file: file.path,
          line,
          excerpt: redactLine(rawLine, secret),
          why: parts,
          fix,
          humanOnly,
        })
      }
    }

    return findings
  },
}
