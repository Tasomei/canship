/** 进度只披露计数；取消或回调失败不得伪装成扫描成功。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { getEventListeners } from 'node:events'
import { scan, ScanCancelledError, ScanProgressError } from '../src/index.js'
import type { ScanOptions, ScanProgress } from '../src/index.js'
import { progressText } from '../src/report/progress.js'

const root = mkdtempSync(join(tmpdir(), 'canship-control-'))
for (let i = 0; i < 70; i++) writeFileSync(join(root, `PRIVATE_FILE_${i}.ts`), 'export const ok=true;')
after(() => rmSync(root, { recursive: true, force: true }))

test('progress uses immutable snapshots, actual counts and no source paths', async () => {
  const events: Readonly<ScanProgress>[] = []
  const sigint = process.listenerCount('SIGINT'); const exitCode = process.exitCode
  const result = await scan(root, { onProgress: progress => { events.push(progress) } })
  assert.equal(result.filesScanned, 70)
  assert.equal(events[0]!.phase, 'discovery')
  assert.equal(events[0]!.filesTotal, null)
  assert.equal(events.at(-1)!.phase, 'complete')
  assert.equal(events.at(-1)!.filesCompleted, 70)
  assert.equal(events.at(-1)!.projectRulesCompleted, events.at(-1)!.projectRulesTotal)
  assert.ok(events.some(event => event.phase === 'history'))
  assert.ok(events.some(event => event.filesCompleted === 32))
  assert.ok(events.every(Object.isFrozen))
  assert.ok(!JSON.stringify(events).includes('PRIVATE_FILE'))
  assert.equal(process.listenerCount('SIGINT'), sigint)
  assert.equal(process.exitCode, exitCode)
  for (let i = 1; i < events.length; i++) assert.ok(events[i]!.filesCompleted >= events[i - 1]!.filesCompleted)
})

test('pre-cancelled requests reject before accessing the root and never echo the reason', async () => {
  const controller = new AbortController(); controller.abort('PRIVATE_ABORT_REASON')
  await assert.rejects(scan(join(root, 'missing'), { signal: controller.signal }), (error: unknown) => {
    assert.ok(error instanceof ScanCancelledError)
    assert.equal(error.name, 'AbortError')
    assert.equal(error.code, 'SCAN_CANCELLED')
    assert.ok(!error.message.includes('PRIVATE_ABORT_REASON'))
    return true
  })
})

test('cancelling after a file batch rejects rather than emitting a complete result', async () => {
  const controller = new AbortController(); const events: ScanProgress[] = []
  await assert.rejects(scan(root, { signal: controller.signal, onProgress: event => {
    events.push(event)
    if (event.filesCompleted >= 32) controller.abort()
  } }), ScanCancelledError)
  assert.ok(!events.some(event => event.phase === 'complete'))
  assert.equal(events.at(-1)!.filesCompleted, 32)
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
})

test('cancellation also interrupts waiting for an unfinished async progress callback', { timeout: 3000 }, async () => {
  const controller = new AbortController()
  await assert.rejects(scan(root, { signal: controller.signal, onProgress: () => new Promise<void>(() => {
    setImmediate(() => controller.abort())
  }) }), ScanCancelledError)
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0)
})

test('callback exceptions propagate with their cause instead of becoming rule warnings', async () => {
  const cause = new Error('PRIVATE_CALLBACK_DETAIL')
  for (const onProgress of [() => { throw cause }, async () => { throw cause }]) {
    await assert.rejects(scan(root, { onProgress }), (error: unknown) => {
      assert.ok(error instanceof ScanProgressError)
      assert.equal(error.cause, cause)
      assert.equal(error.code, 'PROGRESS_CALLBACK_FAILED')
      assert.ok(!error.message.includes('PRIVATE_CALLBACK_DETAIL'))
      return true
    })
  }
})

test('observing progress does not change scan findings or coverage', async () => {
  const plain = await scan(root, { only: ['firebase'] })
  const controlled = await scan(root, { only: ['firebase'], signal: new AbortController().signal, onProgress: async () => {} })
  assert.deepEqual({ ...controlled, durationMs: 0 }, { ...plain, durationMs: 0 })
  for (const options of [{ signal: {} }, { signal: true }, { onProgress: 'invalid' }]) {
    await assert.rejects(scan(root, options as unknown as ScanOptions), TypeError)
  }
})

test('CLI signal cancellation preserves existing report files and produces no success output', () => {
  const target = join(root, 'existing.html'); const original = '<!doctype html><html><head><title>canship report</title></head><body><script id="canship-data"></script></body></html>'
  writeFileSync(target, original)
  for (const signal of ['SIGINT', 'SIGTERM']) {
    const code = `
      process.argv=[process.execPath,'src/cli.ts',process.argv[1],'--json','--report='+process.argv[2]];
      process.on('newListener',name=>{if(name==='${signal}')setImmediate(()=>process.emit('${signal}'))});
      await import('./src/cli.ts');`
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code, root, target], { encoding: 'utf8', timeout: 30_000 })
    assert.equal(result.status, signal === 'SIGINT' ? 130 : 143, result.stderr)
    assert.equal(result.stdout, '')
    assert.match(result.stderr, /\[SCAN_CANCELLED\]/)
    assert.equal(readFileSync(target, 'utf8'), original)
  }
})

test('interactive progress stays on stderr and structured or disabled modes remain quiet', () => {
  const code = `
    Object.defineProperty(process.stderr,'isTTY',{value:true});Object.defineProperty(process.stdout,'isTTY',{value:true});
    process.argv=[process.execPath,'src/cli.ts',...process.argv.slice(1)];await import('./src/cli.ts');`
  for (const flags of [[], ['--json'], ['--share-summary'], ['--no-progress']]) {
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code, root, ...flags], { encoding: 'utf8', timeout: 30_000 })
    assert.equal(result.status, 0, result.stderr)
    if (flags.length === 0) {
      assert.match(result.stderr, /Discovering files/)
      assert.ok(!result.stderr.includes('PRIVATE_FILE'))
    } else assert.equal(result.stderr, '')
    if (flags[0] === '--json') assert.equal(JSON.parse(result.stdout).schemaVersion, 1)
  }
})

test('progress text fits narrow terminals without inventing percentages', () => {
  const event: ScanProgress = { phase: 'files', filesCompleted: 32, filesTotal: 70, projectRulesCompleted: 0, projectRulesTotal: 6 }
  assert.ok(progressText(event, 20).length <= 19)
  assert.match(progressText(event), /files 32\/70/)
  assert.ok(!progressText(event).includes('%'))
})

test('callbacks cannot change the original privacy and rule-selection snapshot', async () => {
  writeFileSync(join(root, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  const options: ScanOptions = { noExcerpts: true, only: ['firebase'] }
  options.onProgress = () => { options.noExcerpts = false; options.only!.push('cors') }
  const result = await scan(root, options)
  assert.ok(result.findings.length > 0)
  assert.ok(result.findings.every(finding => finding.excerpt === null))
  assert.deepEqual(result.ruleSelection?.only, ['firebase'])
})
