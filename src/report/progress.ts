/** 进度仅包含固定阶段名和计数，不使用项目路径或规则错误文本。 */
import type { ScanProgress } from '../types.js'

export function progressText(progress: Readonly<ScanProgress>, width = 80): string {
  const labels: Record<ScanProgress['phase'], string> = {
    discovery: 'Discovering files', files: 'Checking files', history: 'Checking local history',
    project: 'Checking project rules', finalize: 'Preparing results', complete: 'Analysis finished',
  }
  let text = `canship: ${labels[progress.phase]}`
  if (progress.filesTotal !== null) text += ` · files ${progress.filesCompleted}/${progress.filesTotal}`
  if (progress.projectRulesTotal !== null && ['history', 'project'].includes(progress.phase)) {
    text += ` · project checks ${progress.projectRulesCompleted}/${progress.projectRulesTotal}`
  }
  return text.slice(0, Math.max(1, width - 1))
}
