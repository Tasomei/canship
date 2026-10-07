/** 扫描器随插件打包；不解析工作区中的同名程序或依赖。 */
import { parentPort, workerData } from 'node:worker_threads'
import { scanConfiguredProject } from '../../../src/workspaces.js'
import { scan } from '../../../src/engine.js'
import { VERSION } from '../../../src/build-info.js'
import type { ScanRequest, ScanMessage } from './protocol.js'

async function main() {
  const request = workerData as ScanRequest
  if (!request || typeof request.root !== 'string' || typeof request.all !== 'boolean' || typeof request.noConfig !== 'boolean' || typeof request.noIgnoreMarkers !== 'boolean') throw new Error('Invalid request')
  const send = (message: ScanMessage) => parentPort?.postMessage(message)
  const result = await scanConfiguredProject(request.root, { all: request.all, noConfig: request.noConfig,
    noIgnoreMarkers: request.noIgnoreMarkers, noExcerpts: true, bestEffort: false, baselineDefault: false, only: [], skip: [], exclude: [] },
  (root, options) => scan(root, { ...options, onProgress: progress => send({ type: 'progress', progress }) }))
  const displayOmitted = Math.max(0, (result.report?.findings.length ?? 0) - 5000)
  if (result.report) result.report.findings = result.report.findings.slice(0, 5000)
  send({ type: 'result', result, version: VERSION, displayOmitted })
}
main().catch(() => parentPort?.postMessage({ type: 'error', code: 'EDITOR_SCAN_FAILED' } satisfies ScanMessage))
