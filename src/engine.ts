/** 扫描引擎：调度规则、去重、抑制、限额及输出清理。 */

import type {
  Finding,
  IgnoredFinding,
  ScanContext,
  ScanError,
  ScanFile,
  ScanOptions,
  ScanResult,
  RuleSelection,
  SkippedFile,
} from './types.js'
import { FILE_RULES, PROJECT_RULES, ruleMatches, shouldRunRule } from './rules/index.js'
import { MAX_FINDINGS_PER_FILE } from './rules/limits.js'
import { collectFiles, detectGitRepo, ignoredLinesOf } from './walker.js'
import type { IgnoredLines } from './walker.js'
import { resolveGitExecutable } from './git.js'
import { redactAll, truncate } from './redact.js'
import { createHash } from 'node:crypto'

const SEVERITY_ORDER: Record<Finding['severity'], number> = { P0: 0, P1: 1, P2: 2 }
const CONFIDENCE_ORDER: Record<Finding['confidence'], number> = { certain: 0, likely: 1 }

/** 按规则、文件、行号、摘录和标题去重，保留同位置的不同问题。 */
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>()
  const out: Finding[] = []
  for (const f of findings) {
    const key = `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.excerpt ?? ''}|${f.title}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(f)
  }
  return out
}

/** 移除终端控制字符，避免路径或内容改变报告显示。 */
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g

/** 显式标记双向和不可见格式字符；保留具有文字语义的连接字符。 */
const DECEPTIVE_CHARS = /[\u061c\u200b\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g

/** 将不可见字符转换为可读的码位标记。 */
function nameOf(ch: string): string {
  return `<U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}>`
}

/** 统一输出清理：脱敏后移除控制字符并标记格式字符。 */
function clean(text: string): string {
  return redactAll(text)
    // 制表符替换为空格，避免相邻代码被合并。
    .replace(/\t/g, ' ')
    .replace(CONTROL_CHARS, '')
    .replace(DECEPTIVE_CHARS, nameOf)
}

/** 清理 CLI 在扫描后添加的展示文本。 */
export function cleanForOutput(text: string): string {
  return clean(text)
}

function sanitize(findings: Finding[], files: ScanFile[]): Finding[] {
  const byPath = new Map(files.map(file => [file.path, file]))
  const sourceIdentity = (f: Finding): Pick<Finding, 'sourceFingerprint'> => {
    // Git 历史规则提供的是历史内容摘要，不能用当前工作区的内容覆盖。
    if (f.sourceFingerprint !== undefined) return { sourceFingerprint: f.sourceFingerprint }
    const file = f.file === null ? undefined : byPath.get(f.file)
    const source = f.line === null ? file?.content : file?.lines[f.line - 1]
    return source === undefined ? {} : {
      sourceFingerprint: createHash('sha256').update(source.trim(), 'utf8').digest('hex'),
    }
  }
  return findings.map((f) => ({
    ...f,
    // 仅输出摘要；原始行不进入报告，移动行号不改变身份。
    ...sourceIdentity(f),
    title: clean(f.title),
    // 按段落清理，保留段落之间的结构。
    why: f.why.map(clean),
    // 文件路径也必须经过输出清理。
    file: f.file === null ? null : clean(f.file),
    // 先脱敏再截断，避免截断导致凭据特征失效。
    excerpt: f.excerpt === null ? null : truncate(clean(f.excerpt)),
    fix: f.fix.map(clean),
    ...(f.humanOnly ? { humanOnly: f.humanOnly.map(clean) } : {}),
  }))
}

/** 清理跳过记录中的路径及异常详情。 */
export function sanitizeSkippedForOutput(items: SkippedFile[]): SkippedFile[] {
  return items.map((item) => ({
    ...item,
    path: clean(item.path),
    ...(item.detail === undefined ? {} : { detail: clean(item.detail) }),
  }))
}

/** 测试与示例中的结果统一降为疑似，不直接丢弃。 */
function downgradeExampleContext(findings: Finding[], files: ScanFile[]): Finding[] {
  const examples = new Set(files.filter((f) => f.isExampleContext).map((f) => f.path))
  return findings.map((f) =>
    f.file !== null && examples.has(f.file) ? { ...f, confidence: 'likely' as const } : f,
  )
}

/** 应用逐行忽略标记并记录被抑制的位置。 */
function suppressIgnoredLines(
  findings: Finding[],
  files: ScanFile[],
): { kept: Finding[]; ignored: IgnoredFinding[] } {
  const byPath = new Map(files.map((f) => [f.path, f]))
  /** 仅为有结果的文件解析标记，每个文件解析一次。 */
  const markers = new Map<string, IgnoredLines>()

  const kept: Finding[] = []
  const ignored: IgnoredFinding[] = []
  for (const f of findings) {
    if (f.file === null || f.line === null) {
      kept.push(f)
      continue
    }
    let lines = markers.get(f.file)
    if (lines === undefined) {
      const file = byPath.get(f.file)
      lines = file === undefined ? new Map() : ignoredLinesOf(file.lines)
      markers.set(f.file, lines)
    }
    if (!lines.has(f.line)) {
      kept.push(f)
      continue
    }
    const rules = lines.get(f.line)
    // 空值表示忽略该行所有规则。
    if (rules !== null && rules !== undefined && !rules.has(f.ruleId)) {
      kept.push(f)
      continue
    }
    ignored.push({ file: f.file, line: f.line, ruleId: f.ruleId })
  }
  return { kept, ignored }
}

/** 过滤已执行规则中的细分结果；整体规则筛选在执行前完成。 */
function applyRuleSelection(
  findings: Finding[],
  options: ScanOptions,
): { kept: Finding[]; selection: RuleSelection | null } {
  const only = options.only ?? []
  const skip = options.skip ?? []
  if (only.length === 0 && skip.length === 0) return { kept: findings, selection: null }

  const kept = findings.filter((f) => {
    if (only.length > 0) return only.some((s) => ruleMatches(s, f.ruleId))
    return !skip.some((s) => ruleMatches(s, f.ruleId))
  })
  return { kept, selection: { only, skip, removed: findings.length - kept.length } }
}

/** 按严重度、置信度和位置排序。 */
function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    if (bySeverity !== 0) return bySeverity
    const byConfidence = CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence]
    if (byConfidence !== 0) return byConfidence
    return (a.file ?? '').localeCompare(b.file ?? '') || (a.line ?? 0) - (b.line ?? 0)
  })
}

/** 返回选定规则的全部置信度结果，展示过滤由调用方负责。 */
export async function scan(root: string, options: ScanOptions = {}): Promise<ScanResult> {
  const started = Date.now()

  const gitExecutable = resolveGitExecutable(root)
  const git = detectGitRepo(root, gitExecutable)
  const honorIgnoreMarkers = options.honorIgnoreMarkers !== false
  const { files, skipped, ignored, vendored } =
    collectFiles(root, git === 'repo', gitExecutable, {}, honorIgnoreMarkers)

  const findings: Finding[] = []
  const errors: ScanError[] = []
  const fileRules = FILE_RULES.filter(rule => shouldRunRule(rule.id, options.only ?? [], options.skip ?? []))
  const projectRules = PROJECT_RULES.filter(rule => shouldRunRule(rule.id, options.only ?? [], options.skip ?? []))
  /** 按规则和消息去重不完整记录。 */
  const incompleteSeen = new Set<string>()

  // 规则失败或达到上限均意味着扫描未完成。
  const ctx: ScanContext = {
    root,
    files,
    git,
    gitExecutable,
    // 统一记录不完整状态，避免重复提示。
    reportIncomplete: (ruleId, message) => {
      if (incompleteSeen.has(`${ruleId} ${message}`)) return
      incompleteSeen.add(`${ruleId} ${message}`)
      errors.push({ ruleId, file: null, message, kind: 'incomplete' })
    },
  }

  // 执行单文件规则。
  for (const file of files) {
    for (const rule of fileRules) {
      try {
        if (!rule.appliesTo(file)) continue
        findings.push(...rule.check(file, ctx))
      } catch (err) {
        // 规则异常不阻止其他规则，但必须记录扫描缺口。
        errors.push({ ruleId: rule.id, file: file.path, message: messageOf(err), kind: 'crashed' })
      }
    }
  }

  // 执行跨文件规则。
  for (const rule of projectRules) {
    try {
      findings.push(...(await rule.check(ctx)))
    } catch (err) {
      errors.push({ ruleId: rule.id, file: null, message: messageOf(err), kind: 'crashed' })
    }
  }

  // 去重后应用忽略标记，再清理输出文本；关闭标记时保留全部结果。
  const deduped = dedupe(downgradeExampleContext(findings, files))
  const { kept, ignored: ignoredFindings } = honorIgnoreMarkers
    ? suppressIgnoredLines(deduped, files)
    : { kept: deduped, ignored: [] }
  // 统计已执行规则中被选择器过滤的结果。
  const selected = applyRuleSelection(kept, options)

  // 跨规则共享单文件上限，优先保留高严重度、高置信度结果。
  const counts = new Map<string | null, number>()
  const bounded = sortFindings(selected.kept).filter(finding => {
    const count = (counts.get(finding.file) ?? 0) + 1
    counts.set(finding.file, count)
    if (count <= MAX_FINDINGS_PER_FILE) return true
    if (count === MAX_FINDINGS_PER_FILE + 1) ctx.reportIncomplete('engine/findings-limit',
      `${finding.file ?? 'project'} has more than ${MAX_FINDINGS_PER_FILE} findings; remaining findings were not reported`)
    return false
  })

  return {
    findings: sanitize(bounded, files),
    filesScanned: files.length,
    durationMs: Date.now() - started,
    errors: errors.map((e) => ({
      ...e,
      file: e.file === null ? null : clean(e.file),
      message: clean(e.message),
    })),
    skipped: sanitizeSkippedForOutput(skipped),
    ignored: ignored.map(clean),
    // 清理被忽略结果的路径。
    ignoredFindings: ignoredFindings.map((f) => ({ ...f, file: clean(f.file) })),
    // 选择器来自外部输入，输出前也需清理。
    ruleSelection:
      selected.selection === null
        ? null
        : {
            only: selected.selection.only.map(clean),
            skip: selected.selection.skip.map(clean),
            removed: selected.selection.removed,
          },
    vendored,
    // 主动忽略不影响完整性；错误、跳过或零文件扫描均标记为未完成。
    partial: errors.length > 0 || skipped.length > 0 || files.length === 0,
  }
}

/** 将异常转换为可读消息。 */
function messageOf(err: unknown): string {
  if (err instanceof Error) return err.message
  return String(err)
}
