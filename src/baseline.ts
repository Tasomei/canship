/** 基线记录已接受的结果，仅报告新增问题；文件仍会披露路径、规则和标题。 */

import { createHash } from 'node:crypto'
import { readFileSync, statSync, writeFileSync } from 'node:fs'
import type { Finding } from './types.js'

/** 基线格式版本；拒绝读取未知版本。 */
export const BASELINE_VERSION = 2

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
}

/** 基线文件结构。 */
export interface BaselineFile {
  version: number
  generatedAt: string
  entries: BaselineEntry[]
}

/** 按规则、路径、标题和原始来源摘要生成指纹；不包含行号，以空字符分隔字段。 */
export function fingerprintOf(f: Finding): string {
  // 摘录已经丢失密钥中间部分，不能再用于源文件结果的身份判断。
  const identity = [f.ruleId, f.file ?? '', f.title, f.sourceFingerprint ?? f.excerpt ?? ''].join('\u0000')
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
  writeFileSync(path, serializeBaseline(baseline), 'utf8')
}

/** 基线读取或校验错误。 */
export class BaselineError extends Error {}

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
    Number.isInteger(e['count']) &&
    e['count'] > 0
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
  if (version !== BASELINE_VERSION) {
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

/** 基线应用结果。 */
export interface BaselineApplication {
  /** 未被基线接受的结果。 */
  kept: Finding[]
  /** 基线抑制的结果数。 */
  suppressed: number
  /** 不再匹配的接受次数，可用于清理过期条目。 */
  stale: number
}

/** 按计数消耗指纹额度；超出额度的重复问题仍需报告。 */
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
