/** 工作线程协议只传递扫描结果与计数，不传递环境变量或异常原文。 */
import type { scanConfiguredProject } from '../../../src/workspaces.js'
import type { ScanProgress } from '../../../src/types.js'
export interface ScanRequest { root: string; all: boolean; noConfig: boolean; noIgnoreMarkers: boolean }
export type ProjectScan = Awaited<ReturnType<typeof scanConfiguredProject>>
export type ScanMessage = { type: 'progress'; progress: Readonly<ScanProgress> }
  | { type: 'result'; result: ProjectScan; version: string; displayOmitted: number }
  | { type: 'error'; code: string }
