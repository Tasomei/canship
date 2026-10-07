/** 工作线程超时、取消或异常均不产生成功结果。 */
import { Worker } from 'node:worker_threads'
import type { ScanMessage, ScanRequest } from './protocol.js'
import type { ScanProgress } from '../../../src/types.js'
export class EditorCancelled extends Error {}
export type WorkerResult = Extract<ScanMessage, { type: 'result' }>

export function startWorker(path: string, request: ScanRequest, version: string, progress: (value: Readonly<ScanProgress>) => void,
  timeoutMs = 300_000) {
  const worker = new Worker(path, { workerData: request, stdout: true, stderr: true,
    resourceLimits: { maxOldGenerationSizeMb: 512, maxYoungGenerationSizeMb: 64 } })
  let cancel = () => {}
  const promise = new Promise<WorkerResult>((resolve, reject) => {
    let finished = false
    const finish = (error: Error | null, result?: WorkerResult) => {
      if (finished) return
      finished = true; clearTimeout(timer)
      // 终止失败仍是错误，不能将可能继续运行的线程报告为成功。
      worker.terminate().then(() => error ? reject(error) : resolve(result!), () => reject(new Error('Editor worker cleanup failed.')))
    }
    const timer = setTimeout(() => finish(new Error('Editor scan timed out.')), timeoutMs)
    cancel = () => finish(new EditorCancelled('Editor scan cancelled.'))
    worker.on('message', (message: ScanMessage) => {
      if (finished) return
      try {
        if (message.type === 'progress') progress(message.progress)
        else if (message.type === 'result' && message.version === version) finish(null, message)
        else finish(new Error('Editor scanner failed or its bundled version did not match.'))
      } catch { finish(new Error('Editor scan progress failed.')) }
    })
    worker.on('error', () => finish(new Error('Editor scanner failed.')))
    worker.on('exit', () => { if (!finished) finish(new Error('Editor scanner exited without a result.')) })
    worker.stdout?.on('data', () => finish(new Error('Unexpected scanner output.')))
    worker.stderr?.on('data', () => finish(new Error('Unexpected scanner diagnostic output.')))
  })
  return { promise, cancel: () => cancel() }
}
