/** 稳定诊断代码独立于展示文本；跳过文件继续使用现有 reason 字段。 */
import type { ScanError } from './types.js'

export type DiagnosticCode = 'RULE_EXECUTION_FAILED' | 'ANALYSIS_INCOMPLETE' | 'GIT_CHECK_INCOMPLETE' | 'ROUTE_UNRESOLVED' | 'FINDINGS_LIMIT'
  | 'INVALID_ARGUMENT' | 'CONFIG_INVALID' | 'BASELINE_INVALID' | 'GIT_REFERENCE_INVALID' | 'SCAN_ROOT_UNAVAILABLE'
  | 'OUTPUT_WRITE_FAILED' | 'INTERNAL_ERROR' | 'SCAN_CANCELLED' | 'PROGRESS_CALLBACK_FAILED' | 'REPORT_COMPARISON_INVALID' | (string & {})

/** 保持 TypeError 兼容，同时提供不依赖英文文案的输入错误代码。 */
export class ScanInputError extends TypeError {
  readonly code = 'INVALID_ARGUMENT'
}

export function diagnosticCodeOf(error: Pick<ScanError, 'kind' | 'ruleId'>): DiagnosticCode {
  if (error.kind === 'crashed') return 'RULE_EXECUTION_FAILED'
  if (error.ruleId === 'engine/openapi-routes') return 'ROUTE_UNRESOLVED'
  if (error.ruleId === 'engine/findings-limit') return 'FINDINGS_LIMIT'
  if (error.ruleId.startsWith('gitleak/')) return 'GIT_CHECK_INCOMPLETE'
  return 'ANALYSIS_INCOMPLETE'
}
