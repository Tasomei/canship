/** 验证真正打包的编辑器工作线程及失败边界，不把类型检查视为运行验收。 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { startWorker, EditorCancelled } from '../extensions/vscode/src/runner.js'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const root = mkdtempSync(join(tmpdir(), 'canship-editor-worker-'))
after(() => rmSync(root, { recursive: true, force: true }))
const version = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8')).version as string
const worker = join(repository, 'extensions/vscode/dist/worker.cjs')
const project = join(root, 'project'); mkdirSync(project)
const request = { root: project, all: true, noConfig: false, noIgnoreMarkers: false }
before(() => {
  for (const args of [[join(repository, 'node_modules/tsup/dist/cli-default.js')], [join(repository, 'scripts/build-extension.mjs')]]) {
    const built = spawnSync(process.execPath, args, { cwd: repository, encoding: 'utf8', timeout: 120_000, windowsHide: true })
    assert.equal(built.status, 0, built.stdout + built.stderr)
  }
})
test('bundled worker scans with no excerpts, reports counts and uses local configuration', async () => {
  writeFileSync(join(project, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  writeFileSync(join(project, 'DO_NOT_RUN.js'), 'throw new Error("PROJECT_CODE_EXECUTED");')
  const phases: string[] = []
  const result = await startWorker(worker, request, version, progress => { phases.push(progress.phase) }).promise
  assert.equal(result.result.summary?.blocking, 1)
  assert.equal(result.result.report?.findings[0]?.excerpt, null)
  assert.equal(result.displayOmitted, 0)
  assert.equal(result.version, version)
  assert.equal(phases[0], 'discovery')
  assert.equal(phases.at(-1), 'complete')
  writeFileSync(join(project, 'canship.config.json'), '{"only":["cors"]}')
  assert.equal((await startWorker(worker, request, version, () => {}).promise).result.exitCode, 0)
  assert.equal((await startWorker(worker, { ...request, noConfig: true }, version, () => {}).promise).result.exitCode, 1)
})
test('an invalid project configuration returns an explicit failure without private content', async () => {
  writeFileSync(join(project, 'canship.config.json'), '{"PRIVATE_CONFIG_FIELD":"PRIVATE_VALUE"}')
  const result = await startWorker(worker, request, version, () => {}).promise
  assert.equal(result.result.error?.code, 'CONFIG_INVALID')
  assert.equal(result.result.exitCode, 3)
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_CONFIG_FIELD|PRIVATE_VALUE/)
})
test('cancel, timeout, version mismatch and premature exit never return a clean result', async () => {
  const forever = join(root, 'forever.cjs'); writeFileSync(forever, 'setInterval(()=>{},1000);')
  const cancelled = startWorker(forever, request, version, () => {})
  cancelled.cancel()
  await assert.rejects(cancelled.promise, EditorCancelled)
  await assert.rejects(startWorker(forever, request, version, () => {}, 30).promise, /timed out/)
  const empty = join(root, 'empty.cjs'); writeFileSync(empty, '')
  await assert.rejects(startWorker(empty, request, version, () => {}).promise, /without a result/)
  await assert.rejects(startWorker(worker, { ...request, noConfig: true }, 'different-version', () => {}).promise, /did not match/)
})
test('worker errors and unexpected stdout never leak raw diagnostic data', async () => {
  for (const code of ["throw new Error('PRIVATE_WORKER_ERROR')", "console.log('PRIVATE_WORKER_OUTPUT')"]) {
    const bad = join(root, 'bad.cjs'); writeFileSync(bad, code)
    await assert.rejects(startWorker(bad, request, version, () => {}).promise, error => {
      assert.ok(error instanceof Error)
      assert.doesNotMatch(error.message, /PRIVATE_WORKER/)
      return true
    })
  }
  await assert.rejects(startWorker(worker, { ...request, noConfig: true }, version, () => { throw new Error('PRIVATE_CALLBACK') }).promise,
    error => error instanceof Error && error.message === 'Editor scan progress failed.')
})
