/**
 * P1-6: Firebase security rules left wide open.
 *
 * Firestore and Storage rules are the Firebase equivalent of RLS: the client
 * SDK talks to the database directly, so these rules are the only access
 * control that exists. Two patterns account for almost every real incident:
 *
 *   allow read, write: if true;          <- everything public, forever
 *   allow read, write: if request.time   <- "test mode", public until a date
 *          < timestamp.date(2026, 1, 1);
 *
 * Test mode is the sneakier of the two. Firebase offers it during setup, it
 * works, and nothing complains — until the date passes and the app breaks, or
 * it does not pass and the data stays public for weeks.
 */

import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { basename } from 'node:path'
import { noiseMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'

/** Whether this file is a Firebase rules file */
function isRulesFile(file: ScanFile): boolean {
  const name = basename(file.path).toLowerCase()
  if (name.endsWith('.rules')) return true
  // firebase.json points at custom filenames, but these two cover the defaults
  return name === 'firestore.rules' || name === 'storage.rules'
}

/** Which product this rules file governs, for clearer wording */
function productOf(path: string): string {
  const name = basename(path).toLowerCase()
  if (name.includes('storage')) return 'Storage'
  if (name.includes('firestore')) return 'Firestore'
  return 'Firebase'
}

/** allow ...: if true  — unconditionally open */
const ALLOW_IF_TRUE = /\ballow\s+([a-z,\s]+?)\s*:\s*if\s+true\s*;/gi

/**
 * Operations that let someone change your data.
 *
 * The read/write distinction matters more than it first appears. Firestore
 * rules default to deny, so `allow read: if true` opens reads and leaves writes
 * denied — that is "public read-only data", which is a perfectly normal design
 * for announcements, blog posts or a public catalogue. Treating it the same as
 * `allow write: if true` would flood legitimate projects with noise.
 */
const WRITE_OPS = new Set(['write', 'create', 'update', 'delete'])

/** Parse an "allow read, write" operation list */
function parseOps(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
}

/**
 * Firestore match paths contain their own braces — `match /posts/{postId} {`
 * and `match /{document=**} {`. Those wildcards break naive brace matching:
 * scanning for the block's opening brace lands on `{postId}` instead, and the
 * "block" ends up being the wildcard itself.
 *
 * Replace each wildcard with underscores of the same length. Offsets stay
 * valid, and only the braces that actually delimit blocks remain.
 */
function neutralizePathWildcards(content: string): string {
  return content.replace(/\{[a-zA-Z_]\w*(?:\s*=\s*\*\*)?\}/g, (m) => '_'.repeat(m.length))
}

/**
 * Extract the innermost `match` block containing the given offset, using brace
 * matching. Used to see whether an open read rule sits next to an explicit
 * write denial in the same block.
 *
 * @param neutralized content with path wildcards already neutralised
 */
function enclosingMatchBlock(neutralized: string, index: number): string {
  const matchStart = neutralized.slice(0, index).lastIndexOf('match ')
  if (matchStart < 0) return neutralized
  const braceStart = neutralized.indexOf('{', matchStart)
  if (braceStart < 0 || braceStart > index) return neutralized

  let depth = 0
  for (let i = braceStart; i < neutralized.length; i++) {
    if (neutralized[i] === '{') depth++
    else if (neutralized[i] === '}') {
      depth--
      if (depth === 0) return neutralized.slice(braceStart, i + 1)
    }
  }
  return neutralized.slice(braceStart)
}

/**
 * Remove nested match blocks, leaving only the statements of this scope.
 *
 * A deny inside a child match applies to the child, not to the parent. Without
 * this, an `allow write: if false` on `/private/{id}` cancelled the public
 * `allow read: if true` on `/{document=**}` above it — a rule that restricts
 * one path was read as retracting permission on every path.
 *
 * The input has already had its path wildcards neutralised, so every remaining
 * brace really does delimit a block.
 */
function ownStatements(block: string): string {
  let out = ''
  let i = 0
  while (i < block.length) {
    const rest = block.slice(i)
    const nested = /^\s*match\s+[^{]*\{/.exec(rest)
    if (nested && i > 0) {
      // Skip the whole child block, braces included.
      let depth = 0
      let j = i + nested[0].length - 1
      for (; j < block.length; j++) {
        if (block[j] === '{') depth++
        else if (block[j] === '}') {
          depth--
          if (depth === 0) {
            j++
            break
          }
        }
      }
      i = j
      continue
    }
    out += block[i]
    i++
  }
  return out
}

/**
 * Whether this scope explicitly denies writes.
 * `allow read: if true` together with `allow write: if false` is a deliberate
 * public read-only design, not a mistake — do not report it.
 */
function blockDeniesWrites(block: string): boolean {
  const denial = /\ballow\s+([a-z,\s]+?)\s*:\s*if\s+false\s*;/gi
  let m: RegExpExecArray | null
  while ((m = denial.exec(block)) !== null) {
    if (parseOps(m[1] ?? '').some((op) => WRITE_OPS.has(op))) return true
  }
  return false
}

/**
 * Test-mode rules, which stay open until a hardcoded date.
 * Captures the date parts so the report can say whether it has already passed.
 */
const TEST_MODE =
  /\ballow\s+([a-z,\s]+?)\s*:\s*if\s+request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)\s*;/gi

/** Normalise "read, write" into readable prose */
function describeOps(raw: string): string {
  const ops = parseOps(raw)
  if (ops.includes('write') && ops.includes('read')) return 'read and write'
  if (ops.length === 1) return ops[0]!
  return ops.join(' and ')
}


export const firebaseRulesRule: Rule = {
  id: 'firebase/open-rules',
  severity: 'P1',

  appliesTo(file: ScanFile): boolean {
    // Held at lower confidence by the engine rather than skipped here.
    return isRulesFile(file)
  },

  check(file: ScanFile, ctx: ScanContext): Finding[] {
    const findings: Finding[] = []
    const product = productOf(file.path)
    // Stopping is fine; stopping quietly is the silence this whole rule set
    // exists to remove. Called from both loops below — the engine deduplicates
    // the receipt, so reaching the ceiling twice still says so once.
    const capReached = (): boolean => {
      if (findings.length < MAX_FINDINGS_PER_FILE) return false
      ctx.reportIncomplete(
        'firebase/open-rules',
        `${file.path} holds more than ${MAX_FINDINGS_PER_FILE} open rules; the rest were not reported`,
      )
      return true
    }
    // Comments first. Firebase rules use JavaScript comment syntax, and a
    // single commented-out line — `// allow read, write: if true;`, the sort
    // of thing left behind after tightening a rule — was reported as a
    // certain-confidence wide-open database.
    const content = noiseMaskedOf(file)
    // Then path wildcards, so brace matching has a chance.
    const neutralized = neutralizePathWildcards(content)
    // Built once per file rather than counted per match. See offsets.ts.
    const contentLines = lineStartsOf(content)

    // ── Unconditionally open ──
    ALLOW_IF_TRUE.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = ALLOW_IF_TRUE.exec(content)) !== null) {
      if (capReached()) break
      const rawOps = m[1] ?? ''
      const canWrite = parseOps(rawOps).some((op) => WRITE_OPS.has(op))

      // A public read paired with an explicit write denial is a deliberate
      // read-only design, not a mistake.
      if (!canWrite && blockDeniesWrites(ownStatements(enclosingMatchBlock(neutralized, m.index)))) continue

      const ops = describeOps(rawOps)
      findings.push({
        ruleId: 'firebase/open-rules',
        severity: 'P1',
        // Open writes are unambiguous. An open read might be intentional
        // (a public catalogue, announcements), so it stays lower-confidence.
        confidence: canWrite ? 'certain' : 'likely',
        title: canWrite
          ? `Your ${product} rules let anyone ${ops} this data`
          : `Your ${product} rules make this data publicly readable`,
        file: file.path,
        line: lineNumberAt(contentLines, m.index),
        excerpt: m[0].trim(),
        why: canWrite
          ? [
              `"if true" grants access unconditionally — no sign-in, no ownership check, nothing. The Firebase ` +
                `client SDK talks to your database straight from the browser, so these rules are the only access ` +
                `control that exists.`,
              `Anyone who finds your project id can read every document here, overwrite it, or delete all of it. ` +
                `Project ids are not secret; they ship inside your frontend bundle.`,
            ]
          : [
              `"if true" grants read access unconditionally, so anyone who finds your project id can list every ` +
                `document in this collection. Project ids are not secret; they ship inside your frontend bundle.`,
              `Writes are still denied by default, so this is only a problem if the data is not meant to be ` +
                `public. If it is a public catalogue or announcements, ignore this — and consider adding ` +
                `"allow write: if false;" to make that intent explicit.`,
            ],
        fix: canWrite
          ? [
              `Decide who should actually have access. For per-user data the usual rule is: allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`,
              `For data that is genuinely public, restrict it to reads only: allow read: if true; allow write: if false;`,
              `Test your rules with the Firebase emulator before deploying, so you do not lock yourself out.`,
              `If this database has been open for a while, assume the data has already been copied.`,
            ]
          : [
              `If this data is meant to be public, add "allow write: if false;" to the same block. That documents the intent and silences this warning.`,
              `If it is not meant to be public, require sign-in: allow read: if request.auth != null;`,
            ],
      })
    }

    // ── Test mode: open until a hardcoded date ──
    TEST_MODE.lastIndex = 0
    while ((m = TEST_MODE.exec(content)) !== null) {
      if (capReached()) break
      const rawOps = m[1] ?? ''
      const ops = describeOps(rawOps)
      const year = Number(m[2])
      const month = Number(m[3])
      const day = Number(m[4])
      // Compare against the date the scan runs, not a build-time constant
      const expiry = new Date(year, month - 1, day)
      const expired = expiry.getTime() < Date.now()
      const dateStr = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`

      findings.push({
        ruleId: 'firebase/test-mode-rules',
        severity: 'P1',
        // A hardcoded expiry date is never a deliberate authorisation design,
        // so this stays certain whether or not writes are involved.
        confidence: 'certain',
        title: expired
          ? `Your ${product} rules are in test mode and expired on ${dateStr}`
          : `Your ${product} rules allow ${ops} to anyone until ${dateStr}`,
        file: file.path,
        line: lineNumberAt(contentLines, m.index),
        excerpt: m[0].trim(),
        why: expired
          ? [
              `This is the "test mode" rule Firebase creates during setup. The date has passed, so this rule ` +
                `now denies everything. Whatever part of your app depends on it is broken — and it was fully ` +
                `public up until ${dateStr}.`,
              `Assume anything stored here before that date was readable by anyone.`,
            ]
          : [
              `This is the "test mode" rule Firebase creates during setup. Until ${dateStr}, it grants ${ops} ` +
                `access to anyone, with no sign-in required. After that date it flips to denying everything, and ` +
                `your app will break instead.`,
              `Neither state is what you want in production.`,
            ],
        fix: [
          `Replace the date check with a real authorisation rule. For per-user data: allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`,
          `Test the new rules with the Firebase emulator before deploying.`,
          expired
            ? `Note that your app is currently denied access here, so fixing this also fixes whatever stopped working.`
            : `Do this before ${dateStr}, otherwise your app breaks on that date.`,
        ],
      })
    }

    return findings
  },
}
