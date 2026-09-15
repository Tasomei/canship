/** 生成终端报告，展示影响、证据、修复步骤和扫描范围。 */

import type { Finding, ScanResult, SkipReason } from '../types.js'
import { bold, dim, red, green, yellow, cyan, gray } from '../colors.js'
import { SKIP_LABEL, locationOf, plural, verdictOf } from './shared.js'

const INDENT = '  '

export interface RenderOptions {
  /** 报告标题使用的扫描根目录。 */
  root: string
  /** 是否展示疑似结果。 */
  showingLikely: boolean
  /** 隐藏的疑似结果数。 */
  hiddenLikely: number
  /** 基线抑制数量；非零时必须披露。 */
  baselineSuppressed?: number
  /** 不再匹配的基线条目数。 */
  baselineStale?: number
  /** 应用的基线文件路径。 */
  baselinePath?: string | null
}

/** 无论有无新结果，都显示基线抑制信息。 */
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
      // 不规则复数单独处理。
      `${INDENT}${dim(`${stale} baseline ${stale === 1 ? 'entry' : 'entries'} no longer ${stale === 1 ? 'matches' : 'match'} anything — re-run --baseline-write to prune.`)}`,
    )
  }
  return out
}

export function renderReport(result: ScanResult, opts: RenderOptions): string {
  const out: string[] = ['']
  const { findings } = result

  // 报告标题。
  out.push(
    `${INDENT}${bold('canship')} ${dim(`scanned ${result.filesScanned} ${plural(result.filesScanned, 'file')} in ${result.durationMs}ms`)}`,
  )
  out.push(`${INDENT}${dim(opts.root)}`)
  out.push('')

  if (findings.length === 0) {
    out.push(...renderClean(result, opts))
    return out.join('\n')
  }

  // 按严重度和置信度生成结论。
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

  // 结果详情。
  findings.forEach((f, i) => {
    out.push(...renderFinding(f, i + 1))
    out.push('')
  })

  // 报告页尾。
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
  // 输出边界已清理段内换行，此处恢复段落结构。
  for (const line of wrapText(f.why.join('\n\n'), 76)) {
    // 段落空行不增加缩进，避免尾随空白。
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

  // 人工操作单独列出，突出凭据轮换等必要步骤。
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

  // 零文件扫描使用独立提示。
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
    // 全部文件被主动忽略时说明具体原因。
    if (result.ignored.length > 0) {
      out.push(`${INDENT}${dim('  · every file here was excluded by canship-ignore-file')}`)
      out.push('')
      out.push(...renderIgnored(result))
    }
    out.push('')
    return out
  }

  // 扫描未完成时不得显示正常通过。
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
    // 基线隐藏结果时不得宣称项目无问题。
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
  // 明确静态检查的能力边界。
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
// 结束语必须保留隐藏、忽略和筛选信息。
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

/** 列出主动排除的文件，这些排除不影响完整性。 */
function renderIgnored(result: ScanResult): string[] {
  const out: string[] = []
  if (result.ignored.length > 0) {
    const shown = result.ignored.slice(0, 3).join(', ')
    const more = result.ignored.length > 3 ? `, and ${result.ignored.length - 3} more` : ''
    out.push(
      `${INDENT}${dim(`${result.ignored.length} ${plural(result.ignored.length, 'file')} excluded by canship-ignore-file: ${shown}${more}`)}`,
    )
  }
  // 披露被排除的规则范围。
  if (result.ruleSelection !== null) {
    const { only, skip, removed } = result.ruleSelection
    const which =
      only.length > 0 ? `only ${only.join(', ')}` : `everything except ${skip.join(', ')}`
    const cost = removed > 0 ? `, hiding ${removed} ${plural(removed, 'finding')}` : ''
    out.push(`${INDENT}${dim(`Rule selection in force: ${which}${cost}`)}`)
  }
  // 逐条列出忽略标记对应的位置及规则。
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
  // 披露工具默认排除的第三方目录数量。
  if (result.vendored > 0) {
    out.push(
      `${INDENT}${dim(`${result.vendored} ${plural(result.vendored, 'file')} skipped inside dependency directories (node_modules, vendor, Pods, .yarn, .pnpm-store)`)}`,
    )
  }
  return out
}

/** 列出未完成的检查和跳过原因。 */
function renderIncomplete(result: ScanResult): string[] {
  const out: string[] = []
  out.push(`${INDENT}${yellow(bold('Not everything was checked:'))}`)

  // 零工作区文件仍可能存在历史扫描结果。
  if (result.filesScanned === 0) {
    out.push(
      `${INDENT}${INDENT}${dim('·')} no files could be read at this path, so every file-based check was skipped`,
    )
  }

  for (const err of result.errors.slice(0, 5)) {
    const where = err.file ? ` on ${err.file}` : ''
    // 区分规则异常与规则达到资源上限。
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

/** 按宽度换行，保留显式段落分隔。 */
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
