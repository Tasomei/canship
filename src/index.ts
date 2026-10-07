/** 公共 API：校验输入并复用扫描引擎，不加载配置、不写报告、不修改进程状态。 */
import { statSync } from 'node:fs'
import { resolve } from 'node:path'
import { scan as scanEngine } from './engine.js'
import { isKnownSelector } from './rules/index.js'
import { RULE_CATALOG } from './rules/catalog.js'
import type { RuleDescription } from './rules/catalog.js'
export { summarize } from './summary.js'
export type { ScanSummary } from './summary.js'
import type { ScanOptions as EngineOptions, ScanResult } from './types.js'
import { ScanInputError } from './diagnostics.js'
import { checkScanCancelled } from './scan-control.js'
import { isExclusionPath, MAX_EXCLUSIONS } from './exclusions.js'
export { ScanCancelledError, ScanProgressError } from './scan-control.js'
export type { ScanProgress } from './types.js'

export type { Finding, EvidenceStep, ChangeView, Severity, Confidence, ScanResult, ScanError, SkippedFile, RuleSelection } from './types.js'
export type { RuleDescription } from './rules/catalog.js'
export type { DiagnosticCode } from './diagnostics.js'
export { getBuildInfo, getCapabilities } from './build-info.js'
export type { BuildInfo } from './build-info.js'

export interface ScanOptions extends EngineOptions {
  /** 移除结果摘录；路径、标题及说明仍需在分享前审阅。 */
  noExcerpts?: boolean
}

/** 返回独立副本，避免调用方修改内部规则目录。 */
export function listRules(): RuleDescription[] {
  return RULE_CATALOG.map(rule => ({ ...rule }))
}

/** 扫描指定目录，返回全部置信度结果；不自动应用基线或项目配置。 */
export async function scan(root: string, options: ScanOptions = {}): Promise<ScanResult> {
  if (typeof root !== 'string' || root.length === 0) throw new ScanInputError('Scan root must be a non-empty path.')
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new ScanInputError('Scan options must be an object.')
  }
  const allowed = new Set(['only', 'skip', 'honorIgnoreMarkers', 'noExcerpts', 'signal', 'onProgress', 'exclude'])
  if (Object.keys(options).some(key => !allowed.has(key))) throw new ScanInputError('Unknown scan option.')
  if (options.signal !== undefined && (options.signal === null || typeof options.signal !== 'object' ||
      typeof options.signal.aborted !== 'boolean' || typeof options.signal.addEventListener !== 'function' ||
      typeof options.signal.removeEventListener !== 'function')) throw new ScanInputError('Expected an AbortSignal.')
  if (options.onProgress !== undefined && typeof options.onProgress !== 'function') throw new ScanInputError('Expected a progress callback.')
  if (options.exclude !== undefined && (!Array.isArray(options.exclude) || options.exclude.length > MAX_EXCLUSIONS ||
      !options.exclude.every(isExclusionPath))) throw new ScanInputError('Expected at most 64 literal relative exclusion paths.')
  for (const name of ['honorIgnoreMarkers', 'noExcerpts'] as const) {
    if (options[name] !== undefined && typeof options[name] !== 'boolean') throw new ScanInputError('Expected a boolean scan option.')
  }
  for (const name of ['only', 'skip'] as const) {
    const values = options[name]
    if (values !== undefined && (!Array.isArray(values) ||
        [...values].some(value => typeof value !== 'string' || !isKnownSelector(value)))) {
      throw new ScanInputError('Rule selectors must be an array of known IDs or namespaces.')
    }
  }
  if (options.only?.length && options.skip?.length) throw new ScanInputError('only and skip are mutually exclusive.')
  checkScanCancelled(options.signal)
  const directory = resolve(root)
  try {
    if (!statSync(directory).isDirectory()) throw new Error('not a directory')
  } catch {
    throw Object.assign(new Error('Scan root must be an accessible directory.'), {code:'SCAN_ROOT_UNAVAILABLE'})
  }
  // 固定调用时的隐私选项，进度回调不能撤销摘录省略。
  const omitExcerpts = options.noExcerpts === true
  const result = await scanEngine(directory, {
    only: [...(options.only ?? [])], skip: [...(options.skip ?? [])],
    honorIgnoreMarkers: options.honorIgnoreMarkers ?? true,
    exclude: [...(options.exclude ?? [])],
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(options.onProgress === undefined ? {} : { onProgress: options.onProgress }),
  })
  return omitExcerpts
    ? { ...result, findings: result.findings.map(finding => ({ ...finding, excerpt: null })) }
    : result
}
