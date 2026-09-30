/** 各报告共用的结论、位置和跳过原因。 */

import type { ChangeView, Finding, Severity, SkipReason } from '../types.js'
import { BLOCKING } from '../types.js'

/** 各输出格式统一披露变更视图隐藏的结果和完整扫描结论。 */
export function changeViewNotice(view: ChangeView): string {
  return `Changed-file view: ${view.changedFiles} changed files; ${view.hiddenFindings} findings hidden. ` +
    `Full scan: ${view.totalFindings} findings, ${view.totalBlocking} blocking. Scan scope and exit status are unchanged.`
}

/** 按数量选择英文单复数。 */
export function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`
}

/** 格式化结果位置；无文件时显示仓库级位置。 */
export function locationOf(f: Pick<Finding, 'file' | 'line'>): string {
  if (!f.file) return 'the repository'
  return f.line ? `${f.file}:${f.line}` : f.file
}

/** 按严重度和置信度汇总结论。 */
export interface Verdict {
  /** 导致退出码为 1 的确定严重问题数。 */
  blocking: number
  /** 确定但不阻断发布的问题数。 */
  minor: number
  /** 疑似结果数。 */
  unsure: number
}

/** 严重度决定影响，置信度决定证据强度。 */
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

/** 跳过原因对应的展示文本。 */
export const SKIP_LABEL: Record<SkipReason, { noun: string; because: string }> = {
  'too-large': { noun: 'file', because: 'too large to read' },
  unreadable: { noun: 'file', because: 'could not be opened' },
  'directory-unreadable': { noun: 'directory', because: 'could not be listed' },
  binary: { noun: 'file', because: 'not readable as text' },
  symlink: { noun: 'symbolic link', because: 'was not followed' },
  'nested-repository': { noun: 'nested repository', because: 'must be scanned separately' },
}

/** 将跳过原因转为短语。 */
export function skipPhrase(reason: SkipReason): string {
  return SKIP_LABEL[reason].because
}

/** 报告中的问题类别，按规则命名空间划分。 */
export type Category = 'Credentials' | 'API access' | 'Database rules' | 'CORS' | 'Code' | 'Other'
export const CATEGORIES: readonly Category[] = ['Credentials', 'API access', 'Database rules', 'CORS', 'Code', 'Other']
export const SEVERITIES: readonly Severity[] = ['P0', 'P1', 'P2']

/** 未知命名空间归入 Other，新规则不会因此从汇总中消失。 */
export function categoryOf(ruleId: string): Category {
  const namespace = ruleId.split('/')[0]
  if (namespace === 'secrets' || namespace === 'exposure' || namespace === 'gitleak') return 'Credentials'
  if (namespace === 'api') return 'API access'
  if (namespace === 'supabase' || namespace === 'firebase') return 'Database rules'
  if (namespace === 'cors') return 'CORS'
  if (namespace === 'injection' || namespace === 'ssrf' || namespace === 'redirect') return 'Code'
  return 'Other'
}

/** 类别与严重度计数；只含实际出现的类别。 */
export function categoryCounts(findings: Finding[]): Array<{ category: Category; counts: Record<Severity, number>; total: number }> {
  return CATEGORIES.map(category => {
    const counts: Record<Severity, number> = { P0: 0, P1: 0, P2: 0 }
    for (const f of findings) if (categoryOf(f.ruleId) === category) counts[f.severity]++
    return { category, counts, total: counts.P0 + counts.P1 + counts.P2 }
  }).filter(row => row.total > 0)
}

export interface FileGroup {
  /** 仓库级结果为 null。 */
  file: string | null
  findings: Finding[]
}

/** 最严重的文件在前，同级按结果数量；文件内按行号，便于逐个文件修复。 */
export function groupByFile(findings: Finding[]): FileGroup[] {
  const groups = new Map<string | null, Finding[]>()
  for (const f of findings) {
    const list = groups.get(f.file) ?? []
    list.push(f)
    groups.set(f.file, list)
  }
  const rank = (list: Finding[]): number => Math.min(...list.map(f => SEVERITIES.indexOf(f.severity)))
  return [...groups].map(([file, list]) => ({
    file,
    findings: [...list].sort((a, b) => (a.line ?? 0) - (b.line ?? 0) ||
      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)),
  })).sort((a, b) => rank(a.findings) - rank(b.findings) || b.findings.length - a.findings.length ||
    (a.file ?? '').localeCompare(b.file ?? ''))
}

export interface ManualStep {
  /** 人工操作的首句，完整说明保留在各条结果中。 */
  text: string
  /** 来源位置，按首次出现顺序去重。 */
  locations: string[]
  severity: Severity
}

/** 取首句：句号或破折号之后的内容多为解释，展开结果时仍可看到全文。 */
function firstSentence(text: string): string {
  const cut = /\.\s+(?=[A-Z"'(])|\s+—\s+/.exec(text)
  const sentence = cut ? text.slice(0, cut.index + (cut[0].startsWith('.') ? 1 : 0)) : text
  return sentence.trim().replace(/\.$/, '')
}

/** 合并各结果中相同的人工操作；严重结果的操作排在前面。 */
export function manualSteps(findings: Finding[]): ManualStep[] {
  const steps = new Map<string, ManualStep>()
  for (const f of findings) {
    for (const item of f.humanOnly ?? []) {
      const text = firstSentence(item)
      if (!text) continue
      const step = steps.get(text) ?? { text, locations: [], severity: f.severity }
      const location = locationOf(f)
      if (!step.locations.includes(location)) step.locations.push(location)
      if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(step.severity)) step.severity = f.severity
      steps.set(text, step)
    }
  }
  return [...steps.values()].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
}
