/** 扫描控制不包含路径或源码；取消原因不进入诊断文本。 */
import type { ScanOptions, ScanProgress } from './types.js'

export class ScanCancelledError extends Error {
  readonly code = 'SCAN_CANCELLED'
  constructor() { super('Scan cancelled.'); this.name = 'AbortError' }
}

export class ScanProgressError extends Error {
  readonly code = 'PROGRESS_CALLBACK_FAILED'
  constructor(cause: unknown) { super('Scan progress callback failed.', { cause }) }
}

export function checkScanCancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ScanCancelledError()
}

/** 等待调用方的异步回调时仍接受取消；晚到的回调异常不会成为未处理拒绝。 */
async function waitForProgress(value: void | Promise<void>, signal?: AbortSignal): Promise<void> {
  if (!signal) { await value; return }
  let onAbort: () => void = () => {}
  const aborted = new Promise<void>((_, reject) => {
    onAbort = () => reject(new ScanCancelledError())
    signal.addEventListener('abort', onAbort, { once: true })
    if (signal.aborted) onAbort()
  })
  try { await Promise.race([Promise.resolve(value), aborted]) }
  finally { signal.removeEventListener('abort', onAbort) }
}

export function createScanControl(options: ScanOptions) {
  const { signal, onProgress } = options
  return {
    active: signal !== undefined || onProgress !== undefined,
    check: () => checkScanCancelled(signal),
    async checkpoint(progress: ScanProgress) {
      checkScanCancelled(signal)
      // 让计时器和终端信号在同步分析批次之间得到处理。
      await new Promise<void>(resolve => setImmediate(resolve))
      checkScanCancelled(signal)
      if (onProgress) {
        try { await waitForProgress(onProgress(Object.freeze({ ...progress })), signal) }
        catch (error) {
          if (signal?.aborted || error instanceof ScanCancelledError) throw new ScanCancelledError()
          throw new ScanProgressError(error)
        }
      }
      checkScanCancelled(signal)
    },
  }
}
