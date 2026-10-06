/** CLI 与公共 API 共享结果判定；展示过滤不改变完整扫描结论。 */
import type { ScanResult } from './types.js'
import { verdictOf } from './report/shared.js'

export interface ScanSummary {
  findings: number
  blocking: number
  likely: number
  partial: boolean
  exitCode: 0 | 1 | 2 | 3
}

export function summarize(result: ScanResult): ScanSummary {
  const verdict = verdictOf(result.findings)
  const findings = result.changeView?.totalFindings ?? result.findings.length
  const blocking = result.changeView?.totalBlocking ?? verdict.blocking
  const partial = result.partial || result.filesScanned === 0 || result.errors.length > 0 || result.skipped.length > 0
  return { findings, blocking, likely: result.changeView?.totalLikely ?? verdict.unsure, partial,
    exitCode: blocking > 0 ? 1 : findings > 0 ? 2 : partial ? 3 : 0 }
}

/** 接受不完整扫描仅放宽状态 3，不改变已有发现对应的状态。 */
export function scanExitCode(result: ScanResult, bestEffort = false): 0 | 1 | 2 | 3 {
  const code = summarize(result).exitCode
  return bestEffort && code === 3 ? 0 : code
}
