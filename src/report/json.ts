/** JSON 输出契约；结构版本独立于软件包版本。 */
import type { ScanResult } from '../types.js'
import type { BuildInfo } from '../build-info.js'

export interface JsonReport extends ScanResult {
  build?: BuildInfo
  schemaVersion: 1
  version: string
  root: string
  hiddenLikely: number
  baselineSuppressed: number
  baselineStale: number
  baselineExpired: number
  excerptsOmitted: boolean
}

export interface JsonOptions {
  build?: BuildInfo
  version: string
  /** 已清理的展示路径。 */
  root: string
  hiddenLikely: number
  baselineSuppressed: number
  baselineStale: number
  baselineExpired?: number
  excerptsOmitted?: boolean
}

/** 输入须经引擎脱敏及基线、可见性筛选。 */
export function createJsonReport(result: ScanResult, options: JsonOptions): JsonReport {
  // 显式列出公开字段，防止未来内部数据被自动写入报告。
  return {
    schemaVersion: 1,
    ...(options.build ? {build:options.build} : {}),
    version: options.version,
    root: options.root,
    filesScanned: result.filesScanned,
    durationMs: result.durationMs,
    partial: result.partial,
    errors: result.errors,
    skipped: result.skipped,
    ignored: result.ignored,
    ignoredFindings: result.ignoredFindings,
    ruleSelection: result.ruleSelection,
    vendored: result.vendored,
    hiddenLikely: options.hiddenLikely,
    baselineSuppressed: options.baselineSuppressed,
    baselineStale: options.baselineStale,
    baselineExpired: options.baselineExpired ?? 0,
    excerptsOmitted: options.excerptsOmitted ?? false,
    findings: result.findings,
    ...(result.changeView ? { changeView: result.changeView } : {}),
  }
}
