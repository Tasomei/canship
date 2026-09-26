/** 公共 API：校验输入并复用扫描引擎，不加载配置、不写报告、不修改进程状态。 */
import { statSync } from 'node:fs'
import { resolve } from 'node:path'
import { scan as scanEngine } from './engine.js'
import { isKnownSelector } from './rules/index.js'
import { RULE_CATALOG } from './rules/catalog.js'
import type { RuleDescription } from './rules/catalog.js'
import { verdictOf } from './report/shared.js'
import type { ScanOptions as EngineOptions, ScanResult } from './types.js'

export type { Finding, EvidenceStep, Severity, Confidence, ScanResult, ScanError, SkippedFile, RuleSelection } from './types.js'
export type { RuleDescription } from './rules/catalog.js'

export interface ScanOptions extends EngineOptions {
  /** 移除结果摘录；路径、标题及说明仍需在分享前审阅。 */
  noExcerpts?: boolean
}

export interface ScanSummary {
  findings: number
  blocking: number
  likely: number
  partial: boolean
  /** 与 CLI 默认策略一致；不自动设置 process.exitCode。 */
  exitCode: 0 | 1 | 2 | 3
}

/** 返回独立副本，避免调用方修改内部规则目录。 */
export function listRules(): RuleDescription[] {
  return RULE_CATALOG.map(rule => ({ ...rule }))
}

/** 统计全部结果；结果退出码优先，完整性始终单独保留。 */
export function summarize(result: ScanResult): ScanSummary {
  const verdict = verdictOf(result.findings)
  const partial = result.partial || result.filesScanned === 0 || result.errors.length > 0 || result.skipped.length > 0
  return {
    findings: result.findings.length,
    blocking: verdict.blocking,
    likely: verdict.unsure,
    partial,
    exitCode: verdict.blocking > 0 ? 1 : result.findings.length > 0 ? 2 : partial ? 3 : 0,
  }
}

/** 扫描指定目录，返回全部置信度结果；不自动应用基线或项目配置。 */
export async function scan(root: string, options: ScanOptions = {}): Promise<ScanResult> {
  if (typeof root !== 'string' || root.length === 0) throw new TypeError('Scan root must be a non-empty path.')
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Scan options must be an object.')
  }
  const allowed = new Set(['only', 'skip', 'honorIgnoreMarkers', 'noExcerpts'])
  if (Object.keys(options).some(key => !allowed.has(key))) throw new TypeError('Unknown scan option.')
  for (const name of ['honorIgnoreMarkers', 'noExcerpts'] as const) {
    if (options[name] !== undefined && typeof options[name] !== 'boolean') throw new TypeError('Expected a boolean scan option.')
  }
  for (const name of ['only', 'skip'] as const) {
    const values = options[name]
    if (values !== undefined && (!Array.isArray(values) ||
        [...values].some(value => typeof value !== 'string' || !isKnownSelector(value)))) {
      throw new TypeError('Rule selectors must be an array of known IDs or namespaces.')
    }
  }
  if (options.only?.length && options.skip?.length) throw new TypeError('only and skip are mutually exclusive.')
  const directory = resolve(root)
  try {
    if (!statSync(directory).isDirectory()) throw new Error('not a directory')
  } catch {
    throw new Error('Scan root must be an accessible directory.')
  }
  const result = await scanEngine(directory, {
    only: [...(options.only ?? [])], skip: [...(options.skip ?? [])],
    honorIgnoreMarkers: options.honorIgnoreMarkers ?? true,
  })
  return options.noExcerpts
    ? { ...result, findings: result.findings.map(finding => ({ ...finding, excerpt: null })) }
    : result
}
