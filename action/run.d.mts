/** Action 内部测试契约，不作为软件包公共 API。 */
export interface Assessment {
  findings: number
  blocking: number
  partial: boolean
  failed: boolean
}
export function assessReport(report: unknown, exitCode: number, failOn: string): Assessment
export function parseInputs(env: NodeJS.ProcessEnv): {
  root: string; baseline: string | null; version: string; useConfig: boolean; uploadSarif: boolean
}
export function rebaseSarif(log: unknown, prefix: string): any
export function runAction(env: NodeJS.ProcessEnv, dependencies?: {
  installScanner?: (...args: any[]) => string
  execute?: (...args: any[]) => any
}): Assessment
