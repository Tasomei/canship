/**
 * What every renderer has to agree about.
 *
 * There are four output surfaces — the terminal report, the HTML report, the
 * fix prompt and `--json` — and three of them had built these answers
 * separately. Two had already drifted:
 *
 *   - A finding with no file rendered as "repository" in the terminal and the
 *     HTML, and "the repository" in the prompt. One finding, two names,
 *     depending on which flag you passed.
 *   - The terminal translated a SkipReason through a table of prose; the HTML
 *     interpolated the enum, so the shareable report — the one meant to be
 *     handed to someone else — showed a reader `directory-unreadable` where the
 *     terminal said "could not be listed".
 *
 * The third is worse for being still in agreement: the verdict counts are
 * re-derived in terminal.ts, html.ts and cli.ts, and cli.ts's copy decides the
 * exit code. Three truths about whether something is blocking, and a change
 * applied to two of them prints "do not deploy" from a process exiting 2.
 */

import type { Finding, SkipReason } from '../types.js'
import { BLOCKING } from '../types.js'

/**
 * Singular or plural, so a count and its noun agree.
 *
 * terminal.ts had this; html.ts inlined `${n === 1 ? '' : 's'}` five separate
 * times instead.
 */
export function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`
}

/** Where a finding is, for a reader. Findings with no file belong to the repo. */
export function locationOf(f: Finding): string {
  if (!f.file) return 'the repository'
  return f.line ? `${f.file}:${f.line}` : f.file
}

/** What the findings add up to, counted once. */
export interface Verdict {
  /** Confirmed and serious enough not to ship — this is what exits 1 */
  blocking: number
  /** Confirmed, but nothing is exposed */
  minor: number
  /** Everything shown that canship is not certain about */
  unsure: number
}

/**
 * Severity decides whether shipping is a mistake; confidence decides how sure
 * canship is. Conflating them once made a P2 that browsers reject on the
 * user's behalf render as "do not deploy".
 */
export function verdictOf(findings: Finding[]): Verdict {
  let blocking = 0
  let minor = 0
  let unsure = 0
  for (const f of findings) {
    if (f.confidence !== 'certain') unsure++
    else if (BLOCKING.has(f.severity)) blocking++
    else minor++
  }
  return { blocking, minor, unsure }
}

/** What was passed over, and why, in words rather than an enum name */
export const SKIP_LABEL: Record<SkipReason, { noun: string; because: string }> = {
  'too-large': { noun: 'file', because: 'too large to read' },
  unreadable: { noun: 'file', because: 'could not be opened' },
  'directory-unreadable': { noun: 'directory', because: 'could not be listed' },
  binary: { noun: 'file', because: 'not readable as text' },
  symlink: { noun: 'symbolic link', because: 'was not followed' },
  'nested-repository': { noun: 'nested repository', because: 'must be scanned separately' },
}

/** The same reason as a phrase, for renderers that print one per line */
export function skipPhrase(reason: SkipReason): string {
  return SKIP_LABEL[reason].because
}
