/** 各报告共用的结论、位置和跳过原因。 */

import type { Finding, SkipReason } from '../types.js'
import { BLOCKING } from '../types.js'

/** 按数量选择英文单复数。 */
export function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`
}

/** 格式化结果位置；无文件时显示仓库级位置。 */
export function locationOf(f: Finding): string {
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
