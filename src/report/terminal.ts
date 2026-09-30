/** 生成终端报告：先给结论和汇总，再按文件列出结果；--verbose 展开每条结果的说明和修复步骤。 */

import type { Finding, ScanResult, SkipReason } from '../types.js'
import { bold, dim, red, green, yellow, gray } from '../colors.js'
import {
  categoryCounts, categoryOf, changeViewNotice, groupByFile, locationOf, manualSteps, plural, SEVERITIES, SKIP_LABEL, verdictOf,
} from './shared.js'

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
  /** 展开每条结果的摘录、说明、追踪、修复步骤和人工操作。 */
  verbose?: boolean
  /** 页眉显示的扫描器版本。 */
  version?: string
  /** 预期退出码；由调用方按完整结果计算。 */
  exitCode?: 0 | 1 | 2 | 3
  /** 输出宽度；默认取终端列数。 */
  width?: number
}

/** 结果行的缩进：严重度 4 列、行号 4 列及间隔。 */
const DETAIL = ' '.repeat(12)

function widthOf(opts: RenderOptions): number {
  const columns = opts.width ?? (process.stdout.isTTY ? process.stdout.columns : undefined) ?? 96
  return Math.max(60, Math.min(120, columns))
}

/** 严重度只用红色与琥珀色区分，其余保持默认颜色。 */
function severityColor(severity: Finding['severity']): (s: string) => string {
  return severity === 'P0' ? red : severity === 'P1' ? yellow : (s: string) => s
}

/** 去除颜色控制序列后的可见长度。 */
const ANSI = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g')
const visibleLength = (s: string): number => s.replace(ANSI, '').length

/** 按项拼接，放不下时整项换行，不在项内截断。 */
function joinFitting(items: string[], separator: string, width: number): string[] {
  const lines: string[] = []
  let line = ''
  for (const item of items) {
    const next = line === '' ? item : `${line}${separator}${item}`
    if (line !== '' && visibleLength(next) > width) {
      lines.push(line)
      line = item
    } else {
      line = next
    }
  }
  if (line !== '') lines.push(line)
  return lines
}

const pad = (s: string, n: number): string => (s.length >= n ? s : s + ' '.repeat(n - s.length))
const rpad = (s: string, n: number): string => (s.length >= n ? s : ' '.repeat(n - s.length) + s)

export function renderReport(result: ScanResult, opts: RenderOptions): string {
  const width = widthOf(opts)
  const out: string[] = []
  const rule = (): void => { out.push(dim('─'.repeat(width))) }

  out.push(`${bold('canship')}${opts.version ? ` ${opts.version}` : ''} ${dim('·')} ${opts.root}`)
  out.push('─'.repeat(width))
  out.push('')

  const { findings } = result
  if (findings.length === 0) {
    out.push(...renderClean(result, opts, width))
    out.push(...renderNext(opts, width))
    return out.join('\n')
  }

  out.push(...renderVerdict(result, opts, width))
  out.push('')
  rule()
  out.push('')
  out.push(...renderSummary(findings))
  const steps = renderManualSteps(findings, width)
  if (steps.length > 0) out.push('', ...steps)
  out.push('')
  rule()
  out.push('')
  out.push(`${bold('Findings')}${dim('  grouped by file · most severe first')}`)
  out.push('')
  for (const group of groupByFile(findings)) {
    out.push(`${group.file ?? 'repository'}${dim(` — ${group.findings.length}`)}`)
    for (const f of group.findings) out.push(...renderFinding(f, width, opts.verbose === true))
    out.push('')
  }
  rule()

  const notes = [...renderIncomplete(result, width), ...renderIgnored(result), ...renderBaseline(opts)]
  if (!opts.showingLikely && opts.hiddenLikely > 0) {
    notes.push(dim(`${opts.hiddenLikely} lower-confidence ${plural(opts.hiddenLikely, 'finding')} hidden. Run with --all to see ${opts.hiddenLikely === 1 ? 'it' : 'them'}.`))
  }
  if (notes.length > 0) out.push(...notes, '')
  out.push(...renderNext(opts, width))
  return out.join('\n')
}

/** 结论与说明句按严重程度选择，变更视图仍以完整扫描的阻断数为准。 */
function renderVerdict(result: ScanResult, opts: RenderOptions, width: number): string[] {
  const { findings } = result
  const { blocking: visibleBlocking, minor, unsure } = verdictOf(findings)
  const blocking = result.changeView?.totalBlocking ?? visibleBlocking
  const rotations = manualSteps(findings).filter(step => /^Rotate\b/.test(step.text)).length
  const out: string[] = []
  let explanation: string
  if (blocking > 0) {
    out.push(`${red(bold(`${blocking} blocking ${plural(blocking, 'finding')}.`))} ${bold('Do not deploy yet.')}`)
    explanation = 'Every certain P0 or P1 result below needs a code change.' + (rotations > 0
      ? ` ${rotations} exposed ${plural(rotations, 'credential')} must also be rotated in ${rotations === 1 ? 'its provider' : 'their providers'}; a code change does not revoke ${rotations === 1 ? 'it' : 'them'}.`
      : '')
  } else if (minor > 0) {
    out.push(`${yellow(bold(`${minor} ${plural(minor, 'finding')} to fix.`))} ${bold('Nothing blocking.')}`)
    explanation = 'No certain P0 or P1 result was found; the findings below are lower severity.'
  } else {
    out.push(`${yellow(bold(`${unsure} ${plural(unsure, 'finding')} to review.`))}`)
    explanation = 'These are likely findings: the static evidence is not conclusive, so check each one.'
  }
  for (const line of wrapText(explanation, width)) out.push(dim(line))
  out.push('')
  const facts = [
    `${dim('findings')} ${findings.length} ${dim('shown')}${opts.hiddenLikely > 0 && !opts.showingLikely ? dim(`, ${opts.hiddenLikely} likely hidden (--all)`) : ''}`,
    `${dim('files scanned')} ${result.filesScanned}`,
    `${dim('coverage')} ${result.partial ? yellow('incomplete') : 'complete'}`,
    `${result.durationMs} ${dim('ms')}`,
  ]
  out.push(...joinFitting(facts, dim('  ·  '), width))
  if (result.changeView) for (const line of wrapText(changeViewNotice(result.changeView), width)) out.push(yellow(line))
  return out
}

/** 类别 × 严重度计数，数字按严重度着色，空格显示短横线。 */
function renderSummary(findings: Finding[]): string[] {
  const rows = categoryCounts(findings)
  const out = [bold('By category'), dim(pad('', 22) + SEVERITIES.map(s => rpad(s, 5)).join('') + rpad('total', 8))]
  for (const row of rows) {
    out.push(pad(row.category, 22) + SEVERITIES.map(s => row.counts[s]
      ? severityColor(s)(rpad(String(row.counts[s]), 5)) : dim(rpad('–', 5))).join('') + rpad(String(row.total), 8))
  }
  const totals = SEVERITIES.map(s => findings.filter(f => f.severity === s).length)
  out.push(dim(pad('all', 22) + totals.map(n => rpad(String(n), 5)).join('') + rpad(String(findings.length), 8)))
  return out
}

/** 合并相同的人工操作；来源超过一处时只列首个并注明其余数量。 */
function renderManualSteps(findings: Finding[], width: number): string[] {
  const steps = manualSteps(findings)
  if (steps.length === 0) return []
  const out = [bold('Manual steps')]
  steps.forEach((step, i) => {
    wrapText(step.text, width - 5).forEach((line, j) => out.push(`${dim(j === 0 ? rpad(String(i + 1), 3) : '   ')}  ${line}`))
    const more = step.locations.length > 1 ? ` +${step.locations.length - 1}` : ''
    out.push(`     ${dim(`${step.locations[0]}${more}`)}`)
  })
  return out
}

const EVIDENCE_LABEL: Record<NonNullable<Finding['evidence']>[number]['kind'], string> = {
  operation: 'operation',
  import: 'imports',
  'admin-client': 'admin client',
  'auth-helper': 'auth helper',
}

function renderFinding(f: Finding, width: number, verbose: boolean): string[] {
  const out: string[] = []
  const title = wrapText(f.title, width - DETAIL.length)
  const likely = f.confidence === 'likely' ? dim('  likely') : ''
  title.forEach((line, i) => out.push(i === 0
    // 整个文件的结果没有行号，行号列显示 file，避免看起来像缺失。
    ? `  ${severityColor(f.severity)(pad(f.severity, 4))}${dim(rpad(f.line !== null ? String(f.line) : f.file ? 'file' : '', 4))}  ${verbose ? bold(line) : line}${i === title.length - 1 ? likely : ''}`
    : `${DETAIL}${verbose ? bold(line) : line}${i === title.length - 1 ? likely : ''}`))
  if (!verbose) return out

  const text = (s: string, indent = DETAIL): string[] => wrapText(s, width - indent.length).map(line => line === '' ? '' : `${indent}${line}`)
  out.push(`${DETAIL}${dim(`${categoryOf(f.ruleId)} · ${f.ruleId}`)}`)
  if (f.excerpt) out.push('', `${DETAIL}${gray(f.excerpt)}`)
  out.push('', ...text(f.why.join('\n\n')))
  if (f.evidence?.length) {
    // 追踪只说明静态关系，不证明运行时数据流。
    out.push('', `${DETAIL}${dim('trace (static relationships)')}`)
    f.evidence.forEach((step, i) => {
      const marker = i === 0 ? red('●') : i === f.evidence!.length - 1 ? dim('○') : dim('│')
      out.push(`${DETAIL}${marker} ${dim(pad(EVIDENCE_LABEL[step.kind], 14))}${locationOf(step)}`)
    })
    if (f.evidenceTruncated) out.push(`${DETAIL}${dim('  additional dependency steps omitted')}`)
  }
  if (f.fix.length > 0) {
    out.push('', `${DETAIL}${dim('fix')}`)
    f.fix.forEach((step, i) => {
      wrapText(step, width - DETAIL.length - 3).forEach((line, j) => out.push(`${DETAIL}${j === 0 ? `${i + 1}. ` : '   '}${line}`))
    })
  }
  if (f.humanOnly?.length) {
    out.push('', `${DETAIL}${yellow('by hand')}`)
    for (const step of f.humanOnly) {
      wrapText(step, width - DETAIL.length - 2).forEach((line, j) => out.push(`${DETAIL}${j === 0 ? dim('· ') : '  '}${line}`))
    }
  }
  out.push('')
  return out
}

/** 页尾列出下一步命令及退出码原因。 */
function renderNext(opts: RenderOptions, width: number): string[] {
  const out: string[] = []
  const commands = [
    ...(opts.verbose ? [] : [`${dim('details')} canship --verbose`]),
    `${dim('report')} canship --report --open`,
    `${dim('fix prompt')} canship --fix-prompt`,
  ]
  out.push(...joinFitting(commands, '   ', width))
  if (opts.exitCode !== undefined) {
    const reason = {
      0: 'no findings',
      1: 'blocking findings present',
      2: 'findings present, none blocking',
      3: 'scan incomplete',
    }[opts.exitCode]
    out.push(dim(`exit ${opts.exitCode} · ${reason}`))
  }
  out.push('')
  return out
}

/** 无论有无新结果，都显示基线抑制信息。 */
function renderBaseline(opts: RenderOptions): string[] {
  const suppressed = opts.baselineSuppressed ?? 0
  const stale = opts.baselineStale ?? 0
  const out: string[] = []
  if (suppressed > 0) {
    const where = opts.baselinePath ? ` (${opts.baselinePath})` : ''
    out.push(yellow(`${suppressed} ${plural(suppressed, 'finding')} hidden by the baseline${where}`))
    out.push(dim('These problems still exist. Re-run without --baseline to see them.'))
  }
  if (stale > 0) {
    // 不规则复数单独处理。
    out.push(dim(`${stale} baseline ${stale === 1 ? 'entry' : 'entries'} no longer ${stale === 1 ? 'matches' : 'match'} anything — re-run --baseline-write to prune.`))
  }
  return out
}

function renderClean(result: ScanResult, opts: RenderOptions, width: number): string[] {
  const out: string[] = []
  const facts = joinFitting([`${dim('files scanned')} ${result.filesScanned}`, `${dim('coverage')} ${result.partial ? yellow('incomplete') : 'complete'}`,
    `${result.durationMs} ${dim('ms')}`], dim('  ·  '), width)

  // 零文件扫描使用独立提示。
  if (result.filesScanned === 0) {
    out.push(yellow(bold('No files were scanned — nothing was checked.')))
    for (const line of wrapText('canship found no files it could read here, so none of its checks ran. This is not a clean result — it is an empty one.', width)) out.push(dim(line))
    out.push('')
    out.push(dim('Most likely one of:'))
    out.push(dim('  · this is not the directory you meant to scan'))
    out.push(dim('  · everything here is gitignored, or is build output canship skips'))
    out.push(dim('  · the project lives in a subdirectory — try: npx canship ./app'))
    // 全部文件被主动忽略时说明具体原因。
    if (result.ignored.length > 0) {
      out.push(dim('  · every file here was excluded by canship-ignore-file'))
      out.push('', ...renderIgnored(result))
    }
    out.push('')
    if (result.partial) out.push(...renderIncomplete(result, width), '')
    return out
  }

  // 扫描未完成、存在隐藏或基线抑制时不得显示正常通过。
  if (result.partial) {
    out.push(yellow(bold(opts.hiddenLikely > 0
      ? `No certain findings — ${opts.hiddenLikely} lower-confidence ${plural(opts.hiddenLikely, 'finding')} hidden, and not everything was checked.`
      : 'No findings — but not everything was checked.')))
  } else if ((result.changeView?.hiddenFindings ?? 0) > 0) {
    out.push(yellow(bold('No visible findings in changed files — other findings still exist.')))
  } else if (opts.hiddenLikely > 0) {
    out.push(yellow(bold(`No certain findings — ${opts.hiddenLikely} lower-confidence ${plural(opts.hiddenLikely, 'finding')} hidden.`)))
  } else if ((opts.baselineSuppressed ?? 0) > 0) {
    const suppressed = opts.baselineSuppressed ?? 0
    out.push(yellow(bold(`No new findings — ${suppressed} ${plural(suppressed, 'finding')} accepted by the baseline.`)))
  } else {
    out.push(green(bold('No exposed credentials found.')))
  }
  out.push(...facts)
  if (result.changeView) for (const line of wrapText(changeViewNotice(result.changeView), width)) out.push(yellow(line))
  out.push('')
  const baseline = renderBaseline(opts)
  if (baseline.length > 0) out.push(...baseline, '')

  // 明确静态检查的能力边界。
  out.push(bold('Checked for'))
  for (const item of [
    'API keys hardcoded in source code',
    'Server-side secrets exposed to the browser via public env prefixes',
    'Supabase service_role keys reachable from the client',
    '.env files committed to git, including in history',
    'Supabase tables with no Row Level Security, or policies open to everyone',
    'Firebase rules left open to anyone',
    'API routes and server actions that query your database with no sign-in check',
    'CORS that lets other sites act as your signed-in visitors',
    'Request input in SQL, commands, outbound URLs, and redirects within supported handlers',
    'Unverified Supabase sessions and Stripe webhook events',
  ]) out.push(`${dim('  · ')}${item}`)
  out.push('')
  out.push(dim('Input analysis is bounded and handler-local; business authorisation, rate limiting and dependency vulnerabilities are not verified.'))
  // 结束语必须保留隐藏、忽略和筛选信息。
  if (opts.hiddenLikely > 0) {
    out.push(dim('This is not a finding-free result. Review the hidden items with --all.'))
  } else if (result.ignoredFindings.length > 0) {
    out.push(dim('This is not a finding-free result — some were silenced in the source. See below.'))
  } else {
    out.push(dim('A clean result means these checks passed — not that your app is secure.'))
  }
  const notes = [...renderIncomplete(result, width), ...renderIgnored(result)]
  if (opts.hiddenLikely > 0) {
    notes.push(dim(`${opts.hiddenLikely} lower-confidence ${plural(opts.hiddenLikely, 'finding')} hidden. Run with --all to see ${opts.hiddenLikely === 1 ? 'it' : 'them'}.`))
  }
  if (notes.length > 0) out.push('', ...notes)
  out.push('')
  out.push(dim('─'.repeat(width)))
  return out
}

/** 列出主动排除的文件，这些排除不影响完整性。 */
function renderIgnored(result: ScanResult): string[] {
  const out: string[] = []
  if (result.ignored.length > 0) {
    const shown = result.ignored.slice(0, 3).join(', ')
    const more = result.ignored.length > 3 ? `, and ${result.ignored.length - 3} more` : ''
    out.push(dim(`${result.ignored.length} ${plural(result.ignored.length, 'file')} excluded by canship-ignore-file: ${shown}${more}`))
  }
  // 披露被排除的规则范围。
  if (result.ruleSelection !== null) {
    const { only, skip, removed } = result.ruleSelection
    const which = only.length > 0 ? `only ${only.join(', ')}` : `everything except ${skip.join(', ')}`
    const cost = removed > 0 ? `, hiding ${removed} ${plural(removed, 'finding')}` : ''
    out.push(dim(`Rule selection in force: ${which}${cost}`))
  }
  // 逐条列出忽略标记对应的位置及规则。
  if (result.ignoredFindings.length > 0) {
    const n = result.ignoredFindings.length
    const shown = result.ignoredFindings.slice(0, 3).map((f) => `${f.file}:${f.line} (${f.ruleId})`).join(', ')
    const more = n > 3 ? `, and ${n - 3} more` : ''
    out.push(dim(`${n} ${plural(n, 'finding')} silenced by canship-ignore-next-line: ${shown}${more}`))
  }
  // 披露工具默认排除的第三方目录数量。
  if (result.vendored > 0) {
    out.push(dim(`${result.vendored} ${plural(result.vendored, 'file')} skipped inside dependency directories (node_modules, vendor, Pods, .yarn, .pnpm-store)`))
  }
  return out
}

/** 列出未完成的检查和跳过原因。 */
function renderIncomplete(result: ScanResult, width: number): string[] {
  if (!result.partial) return []
  const out: string[] = [yellow(bold('Not everything was checked'))]
  const item = (text: string): void => {
    wrapText(text, width - 4).forEach((line, i) => out.push(`${i === 0 ? dim('  · ') : '    '}${line}`))
  }

  // 零工作区文件仍可能存在历史扫描结果。
  if (result.filesScanned === 0) item('no files could be read at this path, so every file-based check was skipped')
  for (const err of result.errors.slice(0, 5)) {
    const where = err.file ? ` on ${err.file}` : ''
    // 区分规则异常与规则达到资源上限。
    const verb = err.kind === 'incomplete' ? 'did not finish' : 'failed'
    item(`the ${err.ruleId} check ${verb}${where} — ${err.message}`)
  }
  if (result.errors.length > 5) out.push(dim(`  · and ${result.errors.length - 5} more`))

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
    item(`${paths.length} ${plural(paths.length, noun)} ${because}: ${shown}${more}`)
  }
  out.push(dim('Anything could be in what was skipped. Re-run once it is readable.'))
  return out
}

/** 按宽度换行，保留显式段落分隔；超长单词单独成行。 */
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
