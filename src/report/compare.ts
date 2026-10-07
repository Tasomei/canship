/** 比较已保存报告的结果身份；不读取报告引用的项目文件。 */
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { resolve } from 'node:path'
import { fingerprintOf } from '../baseline.js'
import { cleanForOutput } from '../engine.js'
import type { Finding, Severity, Confidence } from '../types.js'

export const MAX_COMPARE_BYTES = 10 * 1024 * 1024
const MAX_FINDINGS = 50_000
const HASH = /^[a-f0-9]{64}$/
const REVISION = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/

export class ComparisonError extends Error {}
type ObjectValue = Record<string, unknown>
const object = (value: unknown): value is ObjectValue => value !== null && typeof value === 'object' && !Array.isArray(value)
const count = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(item => typeof item === 'string')
const nullableString = (value: unknown) => value === null || typeof value === 'string'
const lineNumber = (value: unknown) => value === null || (count(value) && value > 0)

function requireField(valid: boolean, field: string): asserts valid {
  if (!valid) throw new ComparisonError(`Invalid scan report field: ${field}.`)
}

interface ComparisonInput {
  root: string
  version: string
  build: { revision: string | null; dirty: boolean | null; channel: string } | null
  findings: Finding[]
  filesScanned: number
  partial: boolean
  errors: number
  skipped: number
  hiddenLikely: number
  baselineSuppressed: number
  baselineStale: number
  baselineExpired: number
  restricted: boolean
  changedView: boolean
}

/** 仅校验并保留比较所需字段；错误不回显输入内容或路径。 */
export function parseComparisonInput(text: string): ComparisonInput {
  if (Buffer.byteLength(text, 'utf8') > MAX_COMPARE_BYTES) throw new ComparisonError('Scan report exceeds the 10 MiB comparison limit.')
  let raw: unknown
  try { raw = JSON.parse(text.replace(/^\ufeff/, '')) } catch { throw new ComparisonError('Scan report is not valid JSON.') }
  requireField(object(raw) && raw['schemaVersion'] === 1 && raw['kind'] === undefined, 'schemaVersion')
  requireField(typeof raw['root'] === 'string' && raw['root'].length > 0, 'root')
  requireField(typeof raw['version'] === 'string' && raw['version'].length > 0, 'version')
  requireField(typeof raw['partial'] === 'boolean', 'partial')
  for (const key of ['filesScanned', 'vendored', 'hiddenLikely', 'baselineSuppressed', 'baselineStale']) requireField(count(raw[key]), key)
  requireField(typeof raw['durationMs'] === 'number' && Number.isFinite(raw['durationMs']) && raw['durationMs'] >= 0, 'durationMs')
  requireField(raw['baselineExpired'] === undefined || count(raw['baselineExpired']), 'baselineExpired')
  requireField(raw['excerptsOmitted'] === undefined || typeof raw['excerptsOmitted'] === 'boolean', 'excerptsOmitted')
  requireField(strings(raw['ignored']), 'ignored')
  const errors = raw['errors'], skipped = raw['skipped'], ignored = raw['ignoredFindings']
  requireField(Array.isArray(errors) && errors.every(e => object(e) && typeof e['ruleId'] === 'string' && nullableString(e['file']) &&
    typeof e['message'] === 'string' && (e['kind'] === 'crashed' || e['kind'] === 'incomplete')), 'errors')
  requireField(Array.isArray(skipped) && skipped.every(e => object(e) && typeof e['path'] === 'string' && typeof e['reason'] === 'string'), 'skipped')
  requireField(Array.isArray(ignored) && ignored.every(e => object(e) && typeof e['file'] === 'string' && count(e['line']) && e['line'] > 0 && typeof e['ruleId'] === 'string'), 'ignoredFindings')
  const selection = raw['ruleSelection']
  requireField(selection === null || (object(selection) && strings(selection['only']) && strings(selection['skip']) && count(selection['removed'])), 'ruleSelection')
  const exclusions = raw['exclusions']
  requireField(exclusions === undefined || (object(exclusions) && strings(exclusions['requested']) && strings(exclusions['matched'])), 'exclusions')
  const changeView = raw['changeView']
  requireField(changeView === undefined || (object(changeView) && typeof changeView['baseCommit'] === 'string' && typeof changeView['mergeBase'] === 'string' &&
    ['changedFiles', 'hiddenFindings', 'totalFindings', 'totalBlocking', 'totalLikely'].every(key => count(changeView[key]))), 'changeView')
  let build: ComparisonInput['build'] = null
  if (raw['build'] !== undefined) {
    const b = raw['build']
    requireField(object(b) && b['version'] === raw['version'] && (b['channel'] === 'development' || b['channel'] === 'prerelease' || b['channel'] === 'release') &&
      (b['revision'] === null || (typeof b['revision'] === 'string' && REVISION.test(b['revision']))) &&
      (b['dirty'] === null || typeof b['dirty'] === 'boolean'), 'build')
    build = { revision: b['revision'] as string | null, dirty: b['dirty'] as boolean | null, channel: b['channel'] as string }
  }
  const findings = raw['findings']
  requireField(Array.isArray(findings) && findings.length <= MAX_FINDINGS, 'findings (maximum 50000)')
  const parsed = findings.map((f): Finding => {
    requireField(object(f) && typeof f['ruleId'] === 'string' && f['ruleId'].length > 0 &&
      (f['severity'] === 'P0' || f['severity'] === 'P1' || f['severity'] === 'P2') && (f['confidence'] === 'certain' || f['confidence'] === 'likely') &&
      typeof f['title'] === 'string' && nullableString(f['file']) && lineNumber(f['line']) && nullableString(f['excerpt']) &&
      strings(f['why']) && strings(f['fix']) && (f['sourceFingerprint'] === undefined || typeof f['sourceFingerprint'] === 'string'), 'findings[]')
    // 标题、摘录和说明不进入比较输出，也不用于身份回退。
    return { ruleId: f['ruleId'], file: f['file'] as string | null, line: f['line'] as number | null,
      severity: f['severity'] as Severity, confidence: f['confidence'] as Confidence,
      title: '', excerpt: null, why: [], fix: [],
      ...(typeof f['sourceFingerprint'] === 'string' ? { sourceFingerprint: f['sourceFingerprint'] } : {}) }
  })
  return { root: raw['root'], version: raw['version'], build, findings: parsed,
    filesScanned: raw['filesScanned'] as number, partial: raw['partial'], errors: errors.length, skipped: skipped.length,
    hiddenLikely: raw['hiddenLikely'] as number, baselineSuppressed: raw['baselineSuppressed'] as number,
    baselineStale: raw['baselineStale'] as number, baselineExpired: (raw['baselineExpired'] as number | undefined) ?? 0,
    restricted: selection !== null || raw['ignored'].length > 0 || ignored.length > 0 ||
      (object(exclusions) && (exclusions['requested'] as string[]).length > 0), changedView: changeView !== undefined }
}

/** 拒绝链接和特殊文件；读取过程中仍执行大小上限。 */
export function readComparisonInput(path: string): ComparisonInput {
  let fd: number | undefined
  let text: string
  try {
    const target = resolve(path)
    if (/^(?:\\\\|\/\/)/.test(target)) throw new ComparisonError('Expected a local regular JSON report file, not a network path.')
    const before = lstatSync(target)
    if (!before.isFile()) throw new ComparisonError('Expected a local regular JSON report file, not a link or device.')
    fd = openSync(target, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0))
    const info = fstatSync(fd)
    if (!info.isFile() || info.size > MAX_COMPARE_BYTES) throw new ComparisonError('Expected a regular JSON report file of at most 10 MiB.')
    if (before.dev !== info.dev || before.ino !== info.ino) throw new ComparisonError('The selected report changed while opening. Retry with a stable local copy.')
    const chunks: Buffer[] = []
    let total = 0
    while (total <= MAX_COMPARE_BYTES) {
      const chunk = Buffer.alloc(Math.min(64 * 1024, MAX_COMPARE_BYTES + 1 - total))
      const bytes = readSync(fd, chunk, 0, chunk.length, null)
      if (!bytes) break
      chunks.push(chunk.subarray(0, bytes)); total += bytes
    }
    if (total > MAX_COMPARE_BYTES) throw new ComparisonError('Scan report exceeds the 10 MiB comparison limit.')
    text = Buffer.concat(chunks).toString('utf8')
  } catch (err) {
    if (err instanceof ComparisonError) throw err
    throw new ComparisonError('Could not read the selected JSON report. Check the path and file permissions locally.')
  } finally { if (fd !== undefined) closeSync(fd) }
  return parseComparisonInput(text)
}

const NOTICE = 'Report differences are observations, not proof of remediation or project safety. Paths and rule IDs remain visible; review before sharing.'
const WARNINGS = {
  ROOT_CHANGED: 'Scan roots differ; confirm both reports describe the same project.',
  SCANNER_CHANGED: 'Scanner versions or source revisions differ; detection changes may explain the differences.',
  BUILD_UNVERIFIED: 'At least one scanner build is missing, dirty, or has no revision; matching detector implementations cannot be established.',
  INCOMPLETE: 'At least one scan was incomplete, had errors or skipped paths, or scanned no files.',
  HIDDEN_FINDINGS: 'Likely findings were omitted; generate both reports with --all for full comparison.',
  BASELINE_APPLIED: 'Baseline records suppressed findings or were unmatched/expired; compare reports without baselines for an unfiltered view.',
  RESTRICTED_SCOPE: 'Rules, paths, or source comments restricted at least one scan; absent records cannot establish remediation.',
  CHANGED_VIEW: 'A changed-file view was active; the reports do not contain the full scan results.',
  IDENTITY_MISSING: 'Some findings lack a valid source digest; they are listed as unpaired, not as new or removed findings.',
} as const

function reference(f: Finding) {
  return { ruleId: cleanForOutput(f.ruleId), file: f.file === null ? null : cleanForOutput(f.file), line: f.line,
    severity: f.severity, confidence: f.confidence }
}

function observations(findings: Finding[]) {
  const levels = new Map<string, { severity: Severity; confidence: Confidence; count: number }>()
  for (const f of findings) {
    const key = `${f.severity}/${f.confidence}`
    const entry = levels.get(key) ?? { severity: f.severity, confidence: f.confidence, count: 0 }
    entry.count++; levels.set(key, entry)
  }
  return { count: findings.length, firstLine: findings.reduce<number | null>((line, f) => f.line === null ? line : line === null ? f.line : Math.min(line, f.line), null),
    levels: [...levels.values()].sort((a, b) => a.severity.localeCompare(b.severity) || a.confidence.localeCompare(b.confidence)) }
}

/** 同一来源的重复发现保留数量，不按不稳定行号配对。 */
export function compareReports(before: ComparisonInput, after: ComparisonInput) {
  const codes = new Set<keyof typeof WARNINGS>()
  if (before.root !== after.root) codes.add('ROOT_CHANGED')
  if (before.version !== after.version || (before.build?.revision && after.build?.revision && before.build.revision !== after.build.revision)) codes.add('SCANNER_CHANGED')
  if ([before, after].some(r => !r.build?.revision || r.build.dirty !== false)) codes.add('BUILD_UNVERIFIED')
  for (const report of [before, after]) {
    if (report.partial || report.errors || report.skipped || !report.filesScanned) codes.add('INCOMPLETE')
    if (report.hiddenLikely) codes.add('HIDDEN_FINDINGS')
    if (report.baselineSuppressed || report.baselineStale || report.baselineExpired) codes.add('BASELINE_APPLIED')
    if (report.restricted) codes.add('RESTRICTED_SCOPE')
    if (report.changedView) codes.add('CHANGED_VIEW')
  }
  const groups = new Map<string, { before: Finding[]; after: Finding[] }>()
  const unpaired: { before: ReturnType<typeof reference>[]; after: ReturnType<typeof reference>[] } = { before: [], after: [] }
  for (const side of ['before', 'after'] as const) for (const f of (side === 'before' ? before : after).findings) {
    if (!f.sourceFingerprint || !HASH.test(f.sourceFingerprint)) { codes.add('IDENTITY_MISSING'); unpaired[side].push(reference(f)); continue }
    const id = fingerprintOf(f)
    const group = groups.get(id) ?? { before: [], after: [] }
    group[side].push(f); groups.set(id, group)
  }
  const entries = [...groups.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([fingerprint, group]) => {
    const f = group.after[0] ?? group.before[0]!
    return { fingerprint, ruleId: cleanForOutput(f.ruleId), file: f.file === null ? null : cleanForOutput(f.file),
      before: observations(group.before), after: observations(group.after),
      added: Math.max(0, group.after.length - group.before.length), persisting: Math.min(group.after.length, group.before.length),
      notObserved: Math.max(0, group.before.length - group.after.length) }
  })
  const warnings = [...codes].map(code => ({ code, message: WARNINGS[code] }))
  return { schemaVersion: 1, kind: 'report-comparison' as const, scanPerformed: false,
    limited: warnings.length > 0, exitCode: warnings.length ? 2 : 0, notice: NOTICE, warnings,
    counts: { before: before.findings.length, after: after.findings.length,
      added: entries.reduce((sum, item) => sum + item.added, 0), persisting: entries.reduce((sum, item) => sum + item.persisting, 0),
      notObserved: entries.reduce((sum, item) => sum + item.notObserved, 0), unpairedBefore: unpaired.before.length, unpairedAfter: unpaired.after.length },
    entries, unpaired }
}

export function renderComparison(report: ReturnType<typeof compareReports>): string {
  const c = report.counts
  const lines = ['canship report comparison — no scan performed', `${c.added} added · ${c.persisting} persisting · ${c.notObserved} not observed in the later report`,
    `${c.unpairedBefore} earlier / ${c.unpairedAfter} later findings could not be paired`, '', report.notice,
    ...report.warnings.map(warning => `[${warning.code}] ${warning.message}`)]
  for (const entry of report.entries) {
    const levels = (value: typeof entry.before) => value.levels.map(level => `${level.severity}/${level.confidence} x${level.count}`).join(', ') || 'none'
    lines.push('', `${entry.ruleId} — ${entry.file ?? '(project)'} [${entry.fingerprint.slice(0, 12)}]`,
      `  earlier: ${levels(entry.before)}${entry.before.firstLine === null ? '' : `; first line ${entry.before.firstLine}`}`,
      `  later:   ${levels(entry.after)}${entry.after.firstLine === null ? '' : `; first line ${entry.after.firstLine}`}`,
      `  added ${entry.added}; persisting ${entry.persisting}; not observed ${entry.notObserved}`)
  }
  for (const side of ['before', 'after'] as const) for (const f of report.unpaired[side]) lines.push(`Unpaired (${side}): ${f.ruleId} — ${f.file ?? '(project)'}${f.line === null ? '' : `:${f.line}`} ${f.severity}/${f.confidence}`)
  return [...lines, '', `exit ${report.exitCode} · ${report.limited ? 'comparison has limitations' : 'comparison completed; not a scan verdict'}`, ''].join('\n')
}
