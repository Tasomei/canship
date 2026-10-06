/** 基线维护预览不包含源码摘录，明确区分未匹配与已修复。 */
import { cleanForOutput } from '../engine.js'
import { BASELINE_VERSION, reviewBaseline } from '../baseline.js'
import type { BaselineFile, BaselineEntry } from '../baseline.js'
import type { ScanResult } from '../types.js'

export function canPruneBaseline(result: ScanResult): boolean {
  return !result.partial && result.filesScanned > 0 && result.errors.length === 0 && result.skipped.length === 0 &&
    result.ruleSelection === null && result.ignored.length === 0 && result.ignoredFindings.length === 0
}

export function createBaselineReview(result: ScanResult, baseline: BaselineFile, baselinePresent = true) {
  const review = reviewBaseline(result.findings, baseline)
  const clean = (entry: BaselineEntry): BaselineEntry => ({
    ...entry, fingerprint: cleanForOutput(entry.fingerprint), ruleId: cleanForOutput(entry.ruleId),
    file: entry.file === null ? null : cleanForOutput(entry.file), title: cleanForOutput(entry.title),
  })
  return {
    schemaVersion: 1, kind: 'baseline-review' as const, baselineVersion: baseline.version, candidateVersion: BASELINE_VERSION, baselinePresent,
    canPrune: canPruneBaseline(result), partial: result.partial, filesScanned: result.filesScanned,
    ruleSelection: result.ruleSelection,
    ignoredFiles: result.ignored.length, ignoredFindings: result.ignoredFindings.length,
    errors: result.errors.length, skipped: result.skipped.length,
    counts: review.counts,
    retained: review.retained.map(clean), unmatched: review.unmatched.map(clean), unaccepted: review.unaccepted.map(clean),
    warnings: [
      'Unmatched entries are not proof of resolution; changed evidence or scan scope can cause a mismatch.',
      'Pruning accepts no new findings and leaves the original file unchanged. Review the candidate before saving it to a different file.',
      'Paths and titles remain visible. Review this output before sharing.',
    ],
  }
}

export function renderBaselineReview(report: ReturnType<typeof createBaselineReview>): string {
  return ['canship baseline review',
    `Source baseline: ${report.baselinePresent ? 'present' : 'not found; reviewing against empty acceptances'}`,
    `${report.counts.retained} retained · ${report.counts.unmatched} unmatched · ${report.counts.unaccepted} unaccepted`,
    `Prune eligible: ${report.canPrune ? 'yes' : 'no — requires complete, unfiltered coverage without source suppressions'}`, '',
    ...(['retained', 'unmatched', 'unaccepted'] as const).flatMap(group => [group + ':',
      ...report[group].map(entry => `  ${entry.count} × ${entry.ruleId} · ${entry.file ?? '(project)'}\n    ${entry.fingerprint}\n    ${entry.title}`)]),
    '', ...report.warnings, ''].join('\n')
}
