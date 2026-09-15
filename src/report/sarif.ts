/** 生成 SARIF 2.1.0 报告，用于代码扫描平台。 */

import type { Finding, ScanResult } from '../types.js'
import { fingerprintOf } from '../baseline.js'
import { BLOCKING } from '../types.js'

/** 工具项目地址。 */
const INFORMATION_URI = 'https://github.com/Tasomei/canship'

export interface SarifOptions {
  /** 工具版本。 */
  version: string
  /** 基线抑制的结果数。 */
  baselineSuppressed?: number
  /** 本次规则筛选说明。 */
  ruleSelection?: string | null
  /** 隐藏的疑似结果数。 */
  hiddenLikely?: number
}

/** 通过通知披露基线、忽略标记和规则筛选造成的结果隐藏。 */
function suppressionNotes(result: ScanResult, opts: SarifOptions): unknown[] {
  const notes: unknown[] = []
  const baseline = opts.baselineSuppressed ?? 0
  const hidden = opts.hiddenLikely ?? 0
  if (baseline > 0) {
    notes.push({
      level: 'warning',
      message: {
        text: `${baseline} finding${baseline === 1 ? '' : 's'} hidden by a baseline. Those problems still exist.`,
      },
    })
  }
  if (result.ignoredFindings.length > 0) {
    const where = result.ignoredFindings
      .map((f) => `${f.file}:${f.line} (${f.ruleId})`)
      .join(', ')
    notes.push({
      level: 'warning',
      message: {
        text: `${result.ignoredFindings.length} finding${result.ignoredFindings.length === 1 ? '' : 's'} silenced by canship-ignore-next-line: ${where}`,
      },
    })
  }
  if (result.ignored.length > 0) {
    notes.push({
      level: 'warning',
      message: {
        text: `${result.ignored.length} file${result.ignored.length === 1 ? '' : 's'} excluded by canship-ignore-file: ${result.ignored.join(', ')}`,
      },
    })
  }
  if (opts.ruleSelection) {
    notes.push({ level: 'warning', message: { text: `Rule selection in force: ${opts.ruleSelection}` } })
  }
  if (hidden > 0) {
    notes.push({
      level: 'warning',
      message: {
        text: `${hidden} lower-confidence finding${hidden === 1 ? '' : 's'} not included; re-run with --all.`,
      },
    })
  }
  return notes
}

/** 确定的严重问题映射为错误，其余映射为警告。 */
function levelOf(f: Finding): 'error' | 'warning' {
  return f.confidence === 'certain' && BLOCKING.has(f.severity) ? 'error' : 'warning'
}

/** 生成实际命中规则的元数据。 */
function rulesOf(findings: Finding[]): unknown[] {
  const seen = new Map<string, Finding>()
  for (const f of findings) if (!seen.has(f.ruleId)) seen.set(f.ruleId, f)
  return [...seen.entries()].map(([id, f]) => ({
    id,
    name: id,
    shortDescription: { text: f.title },
    fullDescription: { text: f.why.join(' ') },
    help: {
      text: [...f.why, ...(f.fix.length > 0 ? ['How to fix:', ...f.fix] : [])].join('\n'),
    },
    properties: {
      // 工具专属严重度和置信度保存在扩展属性中。
      'canship-severity': f.severity,
      'canship-confidence': f.confidence,
    },
    defaultConfiguration: { level: levelOf(f) },
  }))
}

/** 为结果生成位置及稳定指纹，复用基线身份算法。 */
function resultsOf(findings: Finding[]): unknown[] {
  return findings.map((f) => ({
    ruleId: f.ruleId,
    level: levelOf(f),
    message: { text: f.title },
    // 无可定位文件时不构造虚假位置。
    locations:
      f.file === null
        ? []
        : [
            {
              physicalLocation: {
                // 按路径段进行 URI 编码，保留目录分隔符。
                artifactLocation: { uri: f.file.split('/').map(part => encodeURIComponent(part)).join('/') },
                ...(f.line === null ? {} : { region: { startLine: f.line } }),
              },
            },
          ],
    partialFingerprints: { canshipFindingV2: fingerprintOf(f) },
  }))
}

/** 生成日志并通过调用记录披露扫描完整性。 */
export function renderSarif(result: ScanResult, opts: SarifOptions): string {
  const { findings } = result
  const notifications = [
    ...result.skipped.map(item => ({
      level: 'warning',
      message: { text: `${item.path}: ${item.reason}${item.detail ? ` — ${item.detail}` : ''}` },
    })),
    ...result.errors.map((e) => ({
      level: e.kind === 'crashed' ? 'error' : 'warning',
      message: { text: `${e.ruleId}: ${e.message}` },
    })),
    ...suppressionNotes(result, opts),
  ]
  const log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'canship',
            version: opts.version,
            informationUri: INFORMATION_URI,
            rules: rulesOf(findings),
          },
        },
        results: resultsOf(findings),
        invocations: [
          {
            // 该字段表示执行是否完整，与是否发现问题无关。
            executionSuccessful: !result.partial,
            ...(notifications.length > 0
              ? { toolExecutionNotifications: notifications }
              : {}),
          },
        ],
      },
    ],
  }
  return `${JSON.stringify(log, null, 2)}\n`
}
