/**
 * Accepting the findings a project already has, so only new ones fail.
 *
 * Without this, canship is a tool for new projects only. Point it at a
 * three-year-old repository, get thirty findings, and there is nothing to do
 * with that: the build is red on the first day and stays red, so it comes back
 * out of CI within the week. A baseline records what was there when the tool
 * was adopted and reports only what appeared afterwards, which is the state
 * that can actually be held at zero.
 *
 * That is also the dangerous part. A baseline makes a real finding invisible,
 * and a live P0 someone accepted in a hurry is a leak with a receipt saying it
 * was fine. Two things follow from that, and both are load-bearing:
 *
 *   - Suppression is never silent. Every output surface prints how many
 *     findings the baseline hid and which file did it.
 *   - The baseline is meant to be committed and reviewed, so it must be
 *     readable by a person deciding whether to approve it — rule, file and
 *     title in plain text — and must not itself contain a credential.
 *
 * That second point cuts both ways, and the cost is stated here rather than
 * discovered later. Readable enough to review means readable enough to be a
 * map: every entry names a file, a rule and a title, and every entry is by
 * definition a problem nobody has fixed. canship deliberately searches
 * gitignored credential files, so an entry can describe `.env.local` — a file
 * the repository does not contain and whose existence and contents are not
 * otherwise derivable from public source.
 *
 * The trade is kept rather than resolved, because both ways out are worse.
 * Dropping `file` and `title` leaves a list of hashes nobody can approve,
 * which defeats the reason it is committed at all; not committing it defeats
 * the feature. So the file stays readable and every surface that recommends
 * committing it says what committing it publishes.
 */

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import type { Finding } from './types.js'

/**
 * Format version of the baseline file.
 *
 * Read strictly: a file claiming a version this build does not know is an
 * error rather than something to interpret optimistically. Guessing at an
 * unknown format is how a baseline silently suppresses the wrong findings.
 */
export const BASELINE_VERSION = 1

/** Where `--baseline` looks when given no path */
export const DEFAULT_BASELINE_PATH = 'canship-baseline.json'

/**
 * One accepted finding.
 *
 * `ruleId`, `file` and `title` are here for the human reviewing the diff that
 * adds this entry — they are the sentence "you are accepting an exposed
 * service_role key in lib/supabase-admin.ts". They take no part in matching;
 * `fingerprint` does all of it.
 */
export interface BaselineEntry {
  /** sha256 over the identifying fields. See fingerprintOf. */
  fingerprint: string
  ruleId: string
  file: string | null
  title: string
  /**
   * How many times this fingerprint was seen.
   *
   * Not always 1, because the fingerprint deliberately leaves out the line
   * number (see fingerprintOf), so the same problem twice in one file collapses
   * to one fingerprint. Without a count, accepting one of them would accept
   * every future copy of it in that file for free.
   */
  count: number
}

/** The on-disk shape */
export interface BaselineFile {
  version: number
  generatedAt: string
  entries: BaselineEntry[]
}

/**
 * What a finding is, for the purpose of "have we already accepted this one".
 *
 * The line number is deliberately absent, and that is the whole design. A
 * fingerprint including it is correct for exactly one commit: add an import to
 * the top of a file and every finding below shifts down, so the baseline stops
 * matching anything in that file and reports the same untouched problems as
 * new. A baseline that goes stale on the next commit does not get used.
 *
 * What is left is rule, file, title and excerpt — the excerpt being what tells
 * two different keys on one line apart, the same reason `dedupe` in the engine
 * carries it.
 *
 * NUL separates the fields because it is the one byte none of them can hold:
 * every string here has been through the output boundary in engine.ts, which
 * strips U+0000 along with the rest of the control characters. So no
 * combination of field values can imitate a different combination. This
 * function therefore expects **sanitized** findings — the ones `scan()`
 * returns — and not raw output from a rule.
 */
export function fingerprintOf(f: Finding): string {
  const identity = [f.ruleId, f.file ?? '', f.title, f.excerpt ?? ''].join('\u0000')
  return createHash('sha256').update(identity, 'utf8').digest('hex')
}

/**
 * Build a baseline from a completed scan.
 *
 * Every finding goes in, `likely` ones included. The baseline answers "what did
 * this project look like when we adopted the tool", and a likely finding is
 * part of that picture — it is also still enough to exit 2, so leaving it out
 * would leave the build red for a reason the baseline claimed to have settled.
 */
export function buildBaseline(findings: Finding[], now = new Date()): BaselineFile {
  const byFingerprint = new Map<string, BaselineEntry>()
  for (const f of findings) {
    const fingerprint = fingerprintOf(f)
    const existing = byFingerprint.get(fingerprint)
    if (existing) {
      existing.count++
      continue
    }
    byFingerprint.set(fingerprint, {
      fingerprint,
      ruleId: f.ruleId,
      file: f.file,
      title: f.title,
      count: 1,
    })
  }
  // Sorted so regenerating an unchanged baseline produces an unchanged file.
  // A diff that churns every line is a diff nobody reads, and this one exists
  // to be read.
  const entries = [...byFingerprint.values()].sort(
    (a, b) =>
      (a.file ?? '').localeCompare(b.file ?? '') ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.fingerprint.localeCompare(b.fingerprint),
  )
  return { version: BASELINE_VERSION, generatedAt: now.toISOString(), entries }
}

/** Serialise a baseline. Trailing newline so the file is well-formed text. */
export function serializeBaseline(baseline: BaselineFile): string {
  return `${JSON.stringify(baseline, null, 2)}\n`
}

/** Write a baseline to disk. Throws on an unwritable path. */
export function writeBaseline(path: string, baseline: BaselineFile): void {
  writeFileSync(path, serializeBaseline(baseline), 'utf8')
}

/**
 * An unusable baseline file.
 *
 * A distinct type so the CLI can tell "you asked for a baseline and it is
 * broken" apart from a rule crashing. Both end the run, and they end it for
 * different reasons the user has to be told apart to fix.
 */
export class BaselineError extends Error {}

/** Whether a parsed value is a usable entry */
function isEntry(value: unknown): value is BaselineEntry {
  if (typeof value !== 'object' || value === null) return false
  const e = value as Record<string, unknown>
  return (
    typeof e['fingerprint'] === 'string' &&
    e['fingerprint'].length > 0 &&
    typeof e['ruleId'] === 'string' &&
    (e['file'] === null || typeof e['file'] === 'string') &&
    typeof e['title'] === 'string' &&
    typeof e['count'] === 'number' &&
    Number.isInteger(e['count']) &&
    e['count'] > 0
  )
}

/**
 * Read a baseline file.
 *
 * Every failure here is loud. A baseline that cannot be read is not the same as
 * an empty one: silently continuing with no suppression would be the safe
 * direction for *findings*, but it hides a broken path or a corrupted file from
 * someone who believes their baseline is in force, and the next person to look
 * at the green build would be reading a claim nobody made.
 */
export function readBaseline(path: string): BaselineFile {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (err) {
    throw new BaselineError(
      `could not read baseline ${path}: ${err instanceof Error ? err.message : String(err)}`,
    )
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new BaselineError(`baseline ${path} is not valid JSON`)
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new BaselineError(`baseline ${path} is not a baseline file`)
  }
  const obj = parsed as Record<string, unknown>

  const version = obj['version']
  if (version !== BASELINE_VERSION) {
    throw new BaselineError(
      `baseline ${path} has version ${String(version)}; this canship reads version ${BASELINE_VERSION}`,
    )
  }

  const rawEntries = obj['entries']
  if (!Array.isArray(rawEntries)) {
    throw new BaselineError(`baseline ${path} has no entries array`)
  }
  // One bad entry fails the file rather than being dropped. Dropping it would
  // mean the findings it covered come back as new, with no explanation.
  const entries: BaselineEntry[] = []
  for (const [i, raw] of rawEntries.entries()) {
    if (!isEntry(raw)) throw new BaselineError(`baseline ${path}: entry ${i} is malformed`)
    entries.push({
      fingerprint: raw.fingerprint,
      ruleId: raw.ruleId,
      file: raw.file,
      title: raw.title,
      count: raw.count,
    })
  }

  const generatedAt = typeof obj['generatedAt'] === 'string' ? obj['generatedAt'] : ''
  return { version: BASELINE_VERSION, generatedAt, entries }
}

/** What applying a baseline did */
export interface BaselineApplication {
  /** Findings that were not in the baseline. These are what the run reports. */
  kept: Finding[]
  /** How many findings the baseline suppressed */
  suppressed: number
  /**
   * Accepted findings that no longer occur, so the baseline can be pruned.
   *
   * Counted rather than acted on: a stale entry suppresses nothing and must not
   * fail a build, but a baseline nobody prunes grows into a list of things that
   * were fixed years ago, which is how the next reviewer stops reading it.
   */
  stale: number
}

/**
 * Remove the findings the baseline already accepted.
 *
 * Matching consumes budget: an entry with `count: 2` covers the first two
 * findings carrying that fingerprint and no more. A third one is new, because
 * from the reader's point of view it is — a second identical key added to a
 * file that already had two is a leak nobody accepted.
 */
export function applyBaseline(findings: Finding[], baseline: BaselineFile): BaselineApplication {
  const remaining = new Map<string, number>()
  for (const entry of baseline.entries) {
    remaining.set(entry.fingerprint, (remaining.get(entry.fingerprint) ?? 0) + entry.count)
  }

  const kept: Finding[] = []
  let suppressed = 0
  for (const f of findings) {
    const budget = remaining.get(fingerprintOf(f)) ?? 0
    if (budget > 0) {
      remaining.set(fingerprintOf(f), budget - 1)
      suppressed++
      continue
    }
    kept.push(f)
  }

  let stale = 0
  for (const left of remaining.values()) stale += left

  return { kept, suppressed, stale }
}
