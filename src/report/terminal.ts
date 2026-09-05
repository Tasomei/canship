/**
 * Terminal report.
 *
 * The audience is **people who are not security engineers**, so the wording
 * here matters more than the code:
 *   - state the consequence, not the category ("anyone can read your whole
 *     database", not "privilege escalation risk")
 *   - give steps that can be followed as-is, never "consider hardening your
 *     configuration"
 *   - when the result is clean, say exactly what was and was not checked, and
 *     never imply the app is secure
 */

import type { Finding, ScanResult, SkipReason } from '../types.js'
import { bold, dim, red, green, yellow, cyan, gray } from '../colors.js'
import { SKIP_LABEL, locationOf, plural, verdictOf } from './shared.js'

const INDENT = '  '

export interface RenderOptions {
  /** Project root that was scanned, shown in the header */
  root: string
  /** Whether likely-confidence findings are being shown */
  showingLikely: boolean
  /** How many likely findings are hidden */
  hiddenLikely: number
  /**
   * How many findings a baseline removed from this report.
   *
   * Optional so the renderer keeps working for callers that do not use one, but
   * once it is non-zero it is not optional to *print*: a baseline is the second
   * thing in canship that can empty this report without the project being
   * clean, and the first one (--all hiding likely findings) already has a line
   * in the footer for exactly this reason.
   */
  baselineSuppressed?: number
  /** Baselined findings that no longer occur, so the file can be pruned */
  baselineStale?: number
  /** Which file did the suppressing, so the reader can go and read it */
  baselinePath?: string | null
}

/**
 * What the baseline did, for the reader.
 *
 * Printed on both the clean and the non-clean path, because the clean one is
 * where it matters most: a report saying "no findings" over a baseline holding
 * a live service_role key is the single most misleading thing this tool could
 * produce.
 */
function renderBaseline(opts: RenderOptions): string[] {
  const suppressed = opts.baselineSuppressed ?? 0
  const stale = opts.baselineStale ?? 0
  if (suppressed === 0 && stale === 0) return []

  const out: string[] = []
  if (suppressed > 0) {
    const where = opts.baselinePath ? ` (${opts.baselinePath})` : ''
    out.push(
      `${INDENT}${yellow(`${suppressed} ${plural(suppressed, 'finding')} hidden by the baseline${where}`)}`,
    )
    out.push(`${INDENT}${dim('These problems still exist. Re-run without --baseline to see them.')}`)
  }
  if (stale > 0) {
    out.push(
      // Not plural() — that helper only appends an s, and "entrys" is not a
      // word. The irregular ones have to be written out.
      `${INDENT}${dim(`${stale} baseline ${stale === 1 ? 'entry' : 'entries'} no longer ${stale === 1 ? 'matches' : 'match'} anything — re-run --baseline-write to prune.`)}`,
    )
  }
  return out
}

export function renderReport(result: ScanResult, opts: RenderOptions): string {
  const out: string[] = ['']
  const { findings } = result

  // ── Header ──
  out.push(
    `${INDENT}${bold('canship')} ${dim(`scanned ${result.filesScanned} ${plural(result.filesScanned, 'file')} in ${result.durationMs}ms`)}`,
  )
  out.push(`${INDENT}${dim(opts.root)}`)
  out.push('')

  if (findings.length === 0) {
    out.push(...renderClean(result, opts))
    return out.join('\n')
  }

  // ── Verdict banner ──
  //
  // "Critical" is a claim about severity, not about certainty. Counting every
  // certain finding as critical meant a P2 configuration mistake — one that
  // browsers reject outright, so nothing is exposed — printed "do not deploy".
  const { blocking, minor: confirmedMinor, unsure } = verdictOf(findings)
  if (blocking > 0) {
    out.push(`${INDENT}${red(bold(`✗ ${blocking} critical ${plural(blocking, 'issue')} — do not deploy`))}`)
  } else if (confirmedMinor > 0) {
    out.push(
      `${INDENT}${yellow(bold(`! ${confirmedMinor} ${plural(confirmedMinor, 'thing')} to fix — nothing exposed`))}`,
    )
  } else {
    out.push(`${INDENT}${yellow(bold(`! ${unsure} possible ${plural(unsure, 'issue')} to review`))}`)
  }
  out.push('')

  // ── Findings ──
  findings.forEach((f, i) => {
    out.push(...renderFinding(f, i + 1))
    out.push('')
  })

  // ── Footer ──
  out.push(`${INDENT}${gray('─'.repeat(60))}`)
  out.push('')
  if (result.partial) {
    out.push(...renderIncomplete(result))
    out.push('')
  }
  out.push(...renderIgnored(result))
  out.push(...renderBaseline(opts))
  if (!opts.showingLikely && opts.hiddenLikely > 0) {
    out.push(
      `${INDENT}${dim(`${opts.hiddenLikely} lower-confidence ${plural(opts.hiddenLikely, 'finding')} hidden. Run with --all to see ${opts.hiddenLikely === 1 ? 'it' : 'them'}.`)}`,
    )
  }
  out.push(`${INDENT}${dim('Rotate any key that was exposed. Removing it from the code is not enough.')}`)
  out.push('')

  return out.join('\n')
}

function renderFinding(f: Finding, index: number): string[] {
  const out: string[] = []
  const marker = f.confidence === 'certain' ? red('✗') : yellow('!')
  const location = locationOf(f)

  out.push(`${INDENT}${marker} ${bold(`[${index}] ${f.title}`)}`)
  out.push(`${INDENT}${INDENT}${cyan(location)}${f.confidence === 'likely' ? dim('  (lower confidence)') : ''}`)

  if (f.excerpt) {
    out.push('')
    out.push(`${INDENT}${INDENT}${gray(f.excerpt)}`)
  }

  out.push('')
  // Joined here rather than stored joined: the boundary has already stripped
  // every newline from inside each paragraph, so the only breaks in this string
  // are the ones this line puts there. See Finding.why.
  for (const line of wrapText(f.why.join('\n\n'), 76)) {
    // The blank line between paragraphs stays genuinely blank. Indenting it
    // would put trailing whitespace into output people paste elsewhere.
    out.push(line === '' ? '' : `${INDENT}${INDENT}${line}`)
  }

  if (f.fix.length > 0) {
    out.push('')
    out.push(`${INDENT}${INDENT}${bold('How to fix:')}`)
    f.fix.forEach((step, i) => {
      const wrapped = wrapText(step, 72)
      wrapped.forEach((line, j) => {
        const prefix = j === 0 ? `${i + 1}. ` : '   '
        out.push(`${INDENT}${INDENT}${INDENT}${dim(prefix)}${line}`)
      })
    })
  }

  // Shown separately and last, because these are the steps that actually
  // revoke access — and the ones people skip.
  if (f.humanOnly && f.humanOnly.length > 0) {
    out.push('')
    out.push(`${INDENT}${INDENT}${yellow(bold('Only you can do this:'))}`)
    f.humanOnly.forEach((step) => {
      wrapText(step, 72).forEach((line, j) => {
        const prefix = j === 0 ? '· ' : '  '
        out.push(`${INDENT}${INDENT}${INDENT}${dim(prefix)}${line}`)
      })
    })
  }

  return out
}

function renderClean(result: ScanResult, opts: RenderOptions): string[] {
  const out: string[] = []

  // Nothing was examined at all. This is a different statement from "examined
  // and found clean", and it needs different words: the reassuring checklist
  // below would be a lie here, since not one of those checks had any input.
  //
  // It is also the failure the reader is least likely to suspect, because the
  // output of a scan that found nothing looks exactly like success. The
  // headline command takes no argument, so the wrong working directory is the
  // ordinary mistake rather than an exotic one.
  if (result.filesScanned === 0) {
    out.push(`${INDENT}${yellow(bold('! No files were scanned — nothing was checked'))}`)
    out.push('')
    for (const line of wrapText(
      'canship found no files it could read here, so none of its checks ran. ' +
        'This is not a clean result — it is an empty one.',
      76,
    )) {
      out.push(`${INDENT}${line}`)
    }
    out.push('')
    out.push(`${INDENT}${dim('Most likely one of:')}`)
    out.push(`${INDENT}${dim('  · this is not the directory you meant to scan')}`)
    out.push(`${INDENT}${dim('  · everything here is gitignored, or is build output canship skips')}`)
    out.push(`${INDENT}${dim('  · the project lives in a subdirectory — try: npx canship ./app')}`)
    // Naming the real cause when it is known beats offering three guesses. If
    // the user excluded every file themselves, the list above is a set of
    // wrong answers and the right one is sitting in `ignored`.
    if (result.ignored.length > 0) {
      out.push(`${INDENT}${dim('  · every file here was excluded by canship-ignore-file')}`)
      out.push('')
      out.push(...renderIgnored(result))
    }
    out.push('')
    return out
  }

  // The green tick is a promise, and it is only honest when the project was
  // actually examined. A rule that crashed or a file that could not be read
  // means "nothing was found in what was checked" — a much weaker statement,
  // and the one a reader is most likely to mistake for the strong one.
  if (result.partial) {
    const headline =
      opts.hiddenLikely > 0
        ? `! No certain findings — ${opts.hiddenLikely} lower-confidence ${plural(opts.hiddenLikely, 'finding')} hidden, and not everything was checked`
        : '! No findings — but not everything was checked'
    out.push(`${INDENT}${yellow(bold(headline))}`)
  } else if (opts.hiddenLikely > 0) {
    out.push(
      `${INDENT}${yellow(bold(`! No certain findings — ${opts.hiddenLikely} lower-confidence ${plural(opts.hiddenLikely, 'finding')} hidden`))}`,
    )
  } else if ((opts.baselineSuppressed ?? 0) > 0) {
    // The green tick is a promise about the project, not about the diff. With a
    // baseline in force it would be describing a repository whose findings were
    // filed away rather than fixed — which is the whole reason this branch
    // exists above the tick rather than beside it.
    const suppressed = opts.baselineSuppressed ?? 0
    out.push(
      `${INDENT}${yellow(bold(`! No new findings — ${suppressed} ${plural(suppressed, 'finding')} accepted by the baseline`))}`,
    )
  } else {
    out.push(`${INDENT}${green(bold('✓ No exposed credentials found'))}`)
  }
  out.push('')
  out.push(...renderBaseline(opts))
  if ((opts.baselineSuppressed ?? 0) > 0 || (opts.baselineStale ?? 0) > 0) out.push('')
  // This block is deliberate: a user must never walk away thinking
  // "it passed, therefore I am secure".
  out.push(`${INDENT}${dim('canship checked for:')}`)
  out.push(`${INDENT}${dim('  · API keys hardcoded in source code')}`)
  out.push(`${INDENT}${dim('  · Server-side secrets exposed to the browser via public env prefixes')}`)
  out.push(`${INDENT}${dim('  · Supabase service_role keys reachable from the client')}`)
  out.push(`${INDENT}${dim('  · .env files committed to git, including in history')}`)
  out.push(`${INDENT}${dim('  · Supabase tables with no Row Level Security')}`)
  out.push(`${INDENT}${dim('  · Firebase rules left open to anyone')}`)
  out.push(`${INDENT}${dim('  · API routes that query your database with no sign-in check')}`)
  out.push(`${INDENT}${dim('  · CORS that lets other sites act as your signed-in visitors')}`)
  out.push('')
  out.push(`${INDENT}${dim('It does not check rate limiting, injection, or whether the checks it')}`)
  out.push(`${INDENT}${dim('did find are the right ones.')}`)
  // The closing sentence is the one people quote back. It must not say the
  // checks passed when something was found and then silenced — by --all hiding
  // it, or by a marker in the source. The tick above stays either way, matching
  // how canship-ignore-file has always behaved: the user made this call
  // deliberately, in their own file, and a line marker hides strictly less than
  // the file marker that already keeps it.
  if (opts.hiddenLikely > 0) {
    out.push(`${INDENT}${dim('This is not a finding-free result. Review the hidden items with --all.')}`)
  } else if (result.ignoredFindings.length > 0) {
    out.push(
      `${INDENT}${dim('This is not a finding-free result — some were silenced in the source. See below.')}`,
    )
  } else {
    out.push(`${INDENT}${dim('A clean result means these checks passed — not that your app is secure.')}`)
  }
  if (result.partial) {
    out.push('')
    out.push(...renderIncomplete(result))
  }
  const optedOut = renderIgnored(result)
  if (optedOut.length > 0) {
    out.push('')
    out.push(...optedOut)
  }
  if (opts.hiddenLikely > 0) {
    out.push('')
    out.push(`${INDENT}${dim(`${opts.hiddenLikely} lower-confidence ${plural(opts.hiddenLikely, 'finding')} hidden. Run with --all to see ${opts.hiddenLikely === 1 ? 'it' : 'them'}.`)}`)
  }
  out.push('')
  return out
}

/**
 * One line naming the files the user excluded on purpose.
 *
 * Deliberate exclusions are not failures, so they do not make the scan partial
 * — but they still have to be visible. A file dropping out of a security scan
 * with nothing said about it is the same problem as a silent crash, only more
 * comfortable, and comfortable is how it survives.
 */
function renderIgnored(result: ScanResult): string[] {
  const out: string[] = []
  if (result.ignored.length > 0) {
    const shown = result.ignored.slice(0, 3).join(', ')
    const more = result.ignored.length > 3 ? `, and ${result.ignored.length - 3} more` : ''
    out.push(
      `${INDENT}${dim(`${result.ignored.length} ${plural(result.ignored.length, 'file')} excluded by canship-ignore-file: ${shown}${more}`)}`,
    )
  }
  // A rule that was turned off is a check that did not happen, and the reader
  // has to see it from the report alone — otherwise a config file committed a
  // year ago decides what "clean" means and never says so.
  if (result.ruleSelection !== null) {
    const { only, skip, removed } = result.ruleSelection
    const which =
      only.length > 0 ? `only ${only.join(', ')}` : `everything except ${skip.join(', ')}`
    const cost = removed > 0 ? `, hiding ${removed} ${plural(removed, 'finding')}` : ''
    out.push(`${INDENT}${dim(`Rule selection in force: ${which}${cost}`)}`)
  }
  // A silenced finding is a decision about a specific rule at a specific
  // place, so the locations are named rather than counted. "Three findings
  // were silenced" is not something a reviewer can check.
  if (result.ignoredFindings.length > 0) {
    const n = result.ignoredFindings.length
    const shown = result.ignoredFindings
      .slice(0, 3)
      .map((f) => `${f.file}:${f.line} (${f.ruleId})`)
      .join(', ')
    const more = n > 3 ? `, and ${n - 3} more` : ''
    out.push(
      `${INDENT}${dim(`${n} ${plural(n, 'finding')} silenced by canship-ignore-next-line: ${shown}${more}`)}`,
    )
  }
  // canship's decision, not the user's, so it says so. Dependency trees are
  // skipped because a third-party fixture's example key is a false positive —
  // but a reader who keeps their own code under `vendor/` deserves to find out
  // from the report rather than from a scan that quietly covered less.
  if (result.vendored > 0) {
    out.push(
      `${INDENT}${dim(`${result.vendored} ${plural(result.vendored, 'file')} skipped inside dependency directories (node_modules, vendor, Pods, .yarn, .pnpm-store)`)}`,
    )
  }
  return out
}

/**
 * Say exactly what did not get checked.
 *
 * Deliberately concrete. "Scan may be incomplete" teaches people to skip the
 * line; naming the rule that crashed and the file that could not be opened
 * tells them whether it matters to them.
 */
function renderIncomplete(result: ScanResult): string[] {
  const out: string[] = []
  out.push(`${INDENT}${yellow(bold('Not everything was checked:'))}`)

  // Reachable with findings present: a repository whose working tree is
  // entirely gitignored still has a git history, and the history rule reads
  // it. Those findings are real — but no file-based check ever ran, so the
  // absence of the others means nothing.
  if (result.filesScanned === 0) {
    out.push(
      `${INDENT}${INDENT}${dim('·')} no files could be read at this path, so every file-based check was skipped`,
    )
  }

  for (const err of result.errors.slice(0, 5)) {
    const where = err.file ? ` on ${err.file}` : ''
    // A rule that hit a ceiling did not fail, and saying it did sends someone
    // looking for a bug instead of reading the sentence that follows.
    const verb = err.kind === 'incomplete' ? 'did not finish' : 'failed'
    out.push(`${INDENT}${INDENT}${dim('·')} the ${err.ruleId} check ${verb}${where} — ${err.message}`)
  }
  if (result.errors.length > 5) {
    out.push(`${INDENT}${INDENT}${dim(`· and ${result.errors.length - 5} more`)}`)
  }

  const byReason = new Map<SkipReason, string[]>()
  for (const skip of result.skipped) {
    const list = byReason.get(skip.reason) ?? []
    list.push(skip.path)
    byReason.set(skip.reason, list)
  }
  for (const [reason, paths] of byReason) {
    const { noun, because } = SKIP_LABEL[reason]
    const shown = paths.slice(0, 3).join(', ')
    const more = paths.length > 3 ? `, and ${paths.length - 3} more` : ''
    out.push(
      `${INDENT}${INDENT}${dim('·')} ${paths.length} ${plural(paths.length, noun)} ${because}: ${shown}${more}`,
    )
  }

  out.push('')
  out.push(`${INDENT}${dim('Anything could be in what was skipped. Re-run once it is readable.')}`)
  return out
}

/** Wrap to a width, preserving explicit newlines in the source text */
function wrapText(text: string, width: number): string[] {
  const out: string[] = []
  for (const paragraph of text.split('\n')) {
    if (paragraph.trim() === '') {
      out.push('')
      continue
    }
    let line = ''
    for (const word of paragraph.split(/\s+/)) {
      if (line === '') {
        line = word
      } else if (`${line} ${word}`.length <= width) {
        line += ` ${word}`
      } else {
        out.push(line)
        line = word
      }
    }
    if (line) out.push(line)
  }
  return out
}
