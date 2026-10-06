/** 分享摘要仅采用明确列出的计数和布尔值，不复制项目文本或标识。 */
import { VERSION } from '../build-info.js'
import { summarize, scanExitCode } from '../summary.js'
import type { ScanResult } from '../types.js'

interface ShareOptions {
  bestEffort: boolean
  baselineApplied: boolean
  baselineSuppressed: number
  baselineStale: number
  baselineExpired: number
  configEnabled: boolean
  honorIgnoreMarkers: boolean
}

function count(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('Invalid summary count.')
  return value
}

export function createShareSummary(result: ScanResult, options: ShareOptions) {
  if (result.changeView) throw new TypeError('Share summaries require full-scan results.')
  const summary = summarize(result)
  return {
    schemaVersion: 1,
    kind: 'share-summary' as const,
    version: VERSION,
    partial: summary.partial,
    exitCode: scanExitCode(result, options.bestEffort),
    counts: {
      findings: count(summary.findings), blocking: count(summary.blocking), likely: count(summary.likely),
      P0: result.findings.filter(finding => finding.severity === 'P0').length,
      P1: result.findings.filter(finding => finding.severity === 'P1').length,
      P2: result.findings.filter(finding => finding.severity === 'P2').length,
      filesScanned: count(result.filesScanned), errors: result.errors.length, skipped: result.skipped.length,
      ignoredFiles: result.ignored.length, ignoredFindings: result.ignoredFindings.length,
      baselineSuppressed: count(options.baselineSuppressed), baselineStale: count(options.baselineStale),
      baselineExpired: count(options.baselineExpired),
    },
    scope: {
      rulesRestricted: result.ruleSelection !== null,
      baselineApplied: options.baselineApplied === true,
      configEnabled: options.configEnabled === true,
      honorIgnoreMarkers: options.honorIgnoreMarkers === true,
      bestEffort: options.bestEffort === true,
    },
    notice: 'Counts may still be sensitive. Review before sharing. Nothing was uploaded.',
  }
}

export function renderShareSummary(summary: ReturnType<typeof createShareSummary>): string {
  const c = summary.counts
  return ['canship share summary',
    `${c.findings} findings · ${c.blocking} blocking · ${c.likely} likely`,
    `P0 ${c.P0} · P1 ${c.P1} · P2 ${c.P2}`,
    `${c.filesScanned} files scanned · ${c.errors} errors · ${c.skipped} skipped paths`,
    `${c.ignoredFiles} ignored files · ${c.ignoredFindings} ignored findings`,
    `${c.baselineSuppressed} baseline-suppressed · ${c.baselineStale} unmatched · ${c.baselineExpired} expired`,
    `Coverage: ${summary.partial ? 'incomplete' : 'complete within selected scope'}`,
    `Scope: rules restricted=${summary.scope.rulesRestricted}; baseline=${summary.scope.baselineApplied}; config=${summary.scope.configEnabled}; ignore markers=${summary.scope.honorIgnoreMarkers}; best-effort=${summary.scope.bestEffort}`,
    `exit ${summary.exitCode}`, summary.notice, ''].join('\n')
}
