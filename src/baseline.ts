/** 基线记录已接受的结果，仅报告新增问题；文件仍会披露路径、规则和标题。 */

import { createHash } from 'node:crypto'
import { readFileSync, statSync } from 'node:fs'
import { writeOutput } from './output.js'
import type { Finding } from './types.js'

/** 基线格式版本；拒绝读取未知版本。 */
export const BASELINE_VERSION = 4

/** 未指定路径时的基线文件名。 */
export const DEFAULT_BASELINE_PATH = 'canship-baseline.json'

/** 已接受的结果；仅指纹参与匹配，其他字段用于审阅。 */
export interface BaselineEntry {
  /** 标识字段的 SHA-256 摘要。 */
  fingerprint: string
  ruleId: string
  file: string | null
  title: string
  /** 该指纹的接受次数，防止新增重复问题被自动忽略。 */
  count: number
  /** 可选接受理由，不要求记录个人身份。 */
  reason?: string
  /** UTC 到期时刻；到期后不再提供接受额度。 */
  expiresAt?: string
}

/** 基线文件结构。 */
export interface BaselineFile {
  version: number
  generatedAt: string
  entries: BaselineEntry[]
}

/** 旧指纹仅用于兼容 v2；迁移时采用旧条目标题验证原证据。 */
export function legacyFingerprintOf(f: Finding): string {
  return createHash('sha256').update([f.ruleId, f.file ?? '', f.title, f.sourceFingerprint ?? f.excerpt ?? ''].join('\u0000')).digest('hex')
}

/** v3 身份不依赖行号、标题或语言；同规则同来源的多个问题以计数区分。 */
export function fingerprintOf(f: Finding): string {
  // 摘录已经丢失密钥中间部分，不能再用于源文件结果的身份判断。
  const identity = ['v3', f.ruleId, f.file ?? '', f.sourceFingerprint ?? f.excerpt ?? ''].join('\u0000')
  return createHash('sha256').update(identity, 'utf8').digest('hex')
}

/** 记录全部置信度的结果并合并相同指纹。 */
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
  // 按稳定顺序输出条目，减少无关差异。
  const entries = [...byFingerprint.values()].sort(
    (a, b) =>
      (a.file ?? '').localeCompare(b.file ?? '') ||
      a.ruleId.localeCompare(b.ruleId) ||
      a.fingerprint.localeCompare(b.fingerprint),
  )
  return { version: BASELINE_VERSION, generatedAt: now.toISOString(), entries }
}

/** 序列化基线并保留末尾换行。 */
export function serializeBaseline(baseline: BaselineFile): string {
  return `${JSON.stringify(baseline, null, 2)}\n`
}

/** 写入基线；失败时抛出异常。 */
export function writeBaseline(path: string, baseline: BaselineFile): void {
  writeOutput(path, serializeBaseline(baseline), 'baseline')
}

/** 基线读取或校验错误。 */
export class BaselineError extends Error {}

export interface BaselinePolicy { reason?: string; expiresAt?: string }

/** 仅接受明确的 UTC 时间，不对无效日期自动进位。 */
function validExpiration(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value)) return false
  const time = Date.parse(value)
  const canonical = value.includes('.') ? value : value.replace(/Z$/, '.000Z')
  return Number.isFinite(time) && new Date(time).toISOString() === canonical
}

export function validateBaselinePolicy(policy: BaselinePolicy, now = new Date()): BaselinePolicy {
  if (!Number.isFinite(now.getTime())) throw new BaselineError('Invalid baseline evaluation time.')
  if (policy.reason !== undefined && (typeof policy.reason !== 'string' || !policy.reason.trim() ||
      policy.reason.length > 500 || /[\u0000-\u001f\u007f-\u009f]/.test(policy.reason))) throw new BaselineError('Acceptance reason must be 1–500 characters without control characters.')
  if (policy.expiresAt !== undefined && (!validExpiration(policy.expiresAt) || Date.parse(policy.expiresAt) <= now.getTime())) {
    throw new BaselineError('Acceptance expiry must be a future UTC timestamp, for example 2030-01-01T00:00:00Z.')
  }
  return { ...(policy.reason === undefined ? {} : { reason: policy.reason.trim() }),
    ...(policy.expiresAt === undefined ? {} : { expiresAt: new Date(policy.expiresAt).toISOString() }) }
}

/** 校验基线条目的字段和计数。 */
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
    Number.isSafeInteger(e['count']) &&
    e['count'] > 0 &&
    (e['reason'] === undefined || (typeof e['reason'] === 'string' && e['reason'].trim().length > 0 && e['reason'].length <= 500 && !/[\u0000-\u001f\u007f-\u009f]/.test(e['reason']))) &&
    (e['expiresAt'] === undefined || validExpiration(e['expiresAt']))
  )
}

/** 基线读取失败必须显式报告。 */
/** 限制基线大小，避免无界读取。 */
const MAX_BASELINE_BYTES = 10 * 1024 * 1024

export function readBaseline(path: string): BaselineFile {
  let text: string
  try {
    const size = statSync(path).size
    if (size > MAX_BASELINE_BYTES) {
      throw new BaselineError(
        `baseline ${path} is ${size} bytes, over the ${MAX_BASELINE_BYTES}-byte limit`,
      )
    }
    text = readFileSync(path, 'utf8')
  } catch (err) {
    // 保留大小限制错误，仅包装文件系统异常。
    if (err instanceof BaselineError) throw err
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
  if (version !== 2 && version !== 3 && version !== BASELINE_VERSION) {
    throw new BaselineError(
      `baseline ${path} has version ${String(version)}; this canship reads version ${BASELINE_VERSION}. ` +
        'Review the findings and regenerate the baseline with --baseline-write.',
    )
  }

  const rawEntries = obj['entries']
  if (!Array.isArray(rawEntries)) {
    throw new BaselineError(`baseline ${path} has no entries array`)
  }
  // 任一条目无效时拒绝整个文件。
  const entries: BaselineEntry[] = []
  for (const [i, raw] of rawEntries.entries()) {
    if (!isEntry(raw)) throw new BaselineError(`baseline ${path}: entry ${i} is malformed`)
    if (version < 4 && (raw.reason !== undefined || raw.expiresAt !== undefined)) throw new BaselineError('Reasons and expiry require baseline v4; older tools must not silently ignore them.')
    entries.push({
      fingerprint: raw.fingerprint,
      ruleId: raw.ruleId,
      file: raw.file,
      title: raw.title,
      count: raw.count,
      ...(raw.reason === undefined ? {} : { reason: raw.reason }),
      ...(raw.expiresAt === undefined ? {} : { expiresAt: raw.expiresAt }),
    })
  }

  const generatedAt = typeof obj['generatedAt'] === 'string' ? obj['generatedAt'] : ''
  return { version, generatedAt, entries }
}

/** 基线应用结果。 */
export interface BaselineApplication {
  /** 未被基线接受的结果。 */
  kept: Finding[]
  /** 基线抑制的结果数。 */
  suppressed: number
  /** 不再匹配的接受次数，可用于清理过期条目。 */
  stale: number
  /** 已到期的接受次数；不会抑制结果。 */
  expired: number
}

/** 每条接受记录独立计数，避免不同理由或有效期的额度互相覆盖。 */
function matchBaseline(findings: Finding[], baseline: BaselineFile, now = new Date()) {
  if (![2, 3, BASELINE_VERSION].includes(baseline.version)) throw new BaselineError('Unsupported baseline version.')
  if (!Number.isFinite(now.getTime())) throw new BaselineError('Invalid baseline evaluation time.')
  const buckets = new Map<string, number[]>()
  const remaining: number[] = []
  const expiredEntries: BaselineEntry[] = []
  for (const [index, entry] of baseline.entries.entries()) {
    if (!isEntry(entry) || (baseline.version < 4 && (entry.reason !== undefined || entry.expiresAt !== undefined))) throw new BaselineError('Invalid baseline entry or policy version.')
    const expired = entry.expiresAt !== undefined && Date.parse(entry.expiresAt) <= now.getTime()
    remaining.push(expired ? 0 : entry.count)
    if (expired) expiredEntries.push({ ...entry })
    else {
      const key = baseline.version === 2 ? JSON.stringify([entry.ruleId, entry.file]) : entry.fingerprint
      const indices = buckets.get(key) ?? []
      indices.push(index)
      buckets.set(key, indices)
    }
  }
  const kept: Finding[] = []
  let suppressed = 0
  const retained = new Map<number, BaselineEntry>()
  for (const f of findings) {
    const fingerprint = fingerprintOf(f)
    const key = baseline.version === 2 ? JSON.stringify([f.ruleId, f.file]) : fingerprint
    const index = buckets.get(key)?.find(index => remaining[index]! > 0 && (baseline.version !== 2 ||
      legacyFingerprintOf({ ...f, title: baseline.entries[index]!.title }) === baseline.entries[index]!.fingerprint))
    if (index !== undefined) {
      remaining[index] = remaining[index]! - 1
      suppressed++
      const existing = retained.get(index)
      if (existing) existing.count++
      else retained.set(index, { ...baseline.entries[index]!, fingerprint, ruleId: f.ruleId, file: f.file, title: f.title, count: 1 })
    } else kept.push(f)
  }
  const unmatched = baseline.entries.flatMap((entry, index) => remaining[index]! > 0 ? [{ ...entry, count: remaining[index]! }] : [])
  return { kept, suppressed, stale: remaining.reduce((a, b) => a + b, 0),
    expired: expiredEntries.reduce((sum, entry) => sum + entry.count, 0), expiredEntries,
    retained: [...retained.values()], unmatched }
}

export function applyBaseline(findings: Finding[], baseline: BaselineFile, now = new Date()): BaselineApplication {
  const { kept, suppressed, stale, expired } = matchBaseline(findings, baseline, now)
  return { kept, suppressed, stale, expired }
}

/** 迁移不接受新发现，也不静默删除未匹配或到期的决定。 */
export function migrateBaseline(findings: Finding[], baseline: BaselineFile): BaselineFile {
  const matched = matchBaseline(findings, baseline)
  if (matched.stale > 0) throw new BaselineError('Baseline migration requires all accepted entries to match. Review stale entries first; no output was written.')
  if (matched.expired > 0) throw new BaselineError('Migration cannot discard expired decisions. Review and prune first; no output was written.')
  return { version: BASELINE_VERSION, generatedAt: new Date().toISOString(), entries: matched.retained }
}

/** 按接受次数预览维护结果；未匹配不等于问题已修复。 */
export function reviewBaseline(findings: Finding[], baseline: BaselineFile, now = new Date()) {
  const matched = matchBaseline(findings, baseline, now)
  return {
    retained: matched.retained,
    unmatched: matched.unmatched,
    expired: matched.expiredEntries,
    unaccepted: buildBaseline(matched.kept).entries,
    counts: { retained: matched.suppressed, unmatched: matched.stale, unaccepted: matched.kept.length, expired: matched.expired },
  }
}

/** 只保留仍生效且匹配的接受额度及其理由、有效期。 */
export function pruneBaseline(findings: Finding[], baseline: BaselineFile, now = new Date()): BaselineFile {
  return { version: BASELINE_VERSION, generatedAt: now.toISOString(), entries: matchBaseline(findings, baseline, now).retained }
}

export interface BaselineAcceptance { fingerprint: string; count: number }

/** 新接受决定独立于旧策略，不延长旧记录的有效期或清理旧条目。 */
export function acceptBaseline(findings: Finding[], baseline: BaselineFile, selections: BaselineAcceptance[],
  policy: BaselinePolicy = {}, now = new Date()): BaselineFile {
  const metadata = validateBaselinePolicy(policy, now)
  const current = baseline.version === 2 ? migrateBaseline(findings, baseline) : baseline
  const remaining = buildBaseline(matchBaseline(findings, current, now).kept).entries
  const requested = new Map<string, number>()
  if (selections.length === 0) throw new BaselineError('Select at least one fingerprint from --baseline-review.')
  for (const selection of selections) {
    if (!/^[a-f0-9]{64}$/.test(selection.fingerprint) || !Number.isSafeInteger(selection.count) || selection.count < 1) {
      throw new BaselineError('Acceptance requires a full v3 fingerprint and a positive integer count.')
    }
    const count = (requested.get(selection.fingerprint) ?? 0) + selection.count
    if (!Number.isSafeInteger(count)) throw new BaselineError('Acceptance count is too large.')
    requested.set(selection.fingerprint, count)
  }
  const entries = current.entries.map(entry => ({ ...entry }))
  for (const [fingerprint, count] of requested) {
    const found = remaining.find(entry => entry.fingerprint === fingerprint)
    if (!found || count > found.count) throw new BaselineError('A selected fingerprint or count no longer matches unaccepted findings. Review again; no baseline was changed.')
    const existing = entries.find(entry => entry.fingerprint === fingerprint &&
      entry.reason === metadata.reason && entry.expiresAt === metadata.expiresAt)
    if (existing) existing.count += count
    else entries.push({ ...found, count, ...metadata })
  }
  return { version: BASELINE_VERSION, generatedAt: now.toISOString(), entries }
}
