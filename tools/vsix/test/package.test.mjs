/** 验证真实 VSIX 清单、字节与包内线程，不发布、不访问编辑器用户配置。 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, rmSync, createWriteStream, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { pipeline } from 'node:stream/promises'
import { Worker } from 'node:worker_threads'
import { packageExtension } from '../../../scripts/package-extension.mjs'
import { repository, toolRequire, sourceFiles, archiveFiles, readVsix, inspectSources, verifyVsix } from '../../../scripts/vsix-support.mjs'

const root = mkdtempSync(join(tmpdir(), 'canship-vsix-check-'))
const source = join(root, 'source'), output = join(root, 'output')
let artifact, entries
before(async () => {
  for (const name of ['.vscodeignore', ...sourceFiles]) {
    const target = join(source, name); mkdirSync(dirname(target), { recursive: true })
    copyFileSync(join(repository, 'extensions/vscode', name), target)
  }
  // 白名单之外即使出现日志、环境文件及备份，也不得带入 VSIX。
  for (const name of ['.env', 'report.json', 'private.log', 'screenshot.png', 'src/source.ts', '_备份/package.json', 'dist/debug.map']) {
    const target = join(source, name); mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, 'SYNTHETIC_NOT_FOR_DISTRIBUTION')
  }
  artifact = await packageExtension(source, output)
  entries = await readVsix(artifact.path)
})
after(() => rmSync(root, { recursive: true, force: true }))

test('the official package contains only the allowlist and the current reviewed bytes', async () => {
  assert.deepEqual([...entries.keys()].sort(), archiveFiles)
  await verifyVsix(artifact.path, source)
  for (const bytes of entries.values()) assert.ok(!bytes.includes('SYNTHETIC_NOT_FOR_DISTRIBUTION'))
})

test('both language links target extension documentation, not the CLI README', () => {
  assert.match(entries.get('extension/readme.md').toString(), /blob\/main\/extensions\/vscode\/README-zh-CN\.md/)
  assert.match(entries.get('extension/README-zh-CN.md').toString(), /blob\/main\/extensions\/vscode\/README\.md/)
})

test('a second package does not overwrite an existing artifact', async () => {
  const previous = readFileSync(artifact.path)
  const next = await packageExtension(source, output)
  assert.notEqual(next.path, artifact.path)
  assert.deepEqual(readFileSync(artifact.path), previous)
})

test('unexpected package hooks and dependencies are rejected before packaging', () => {
  const path = join(source, 'package.json'), original = readFileSync(path)
  for (const fields of [{ scripts: { 'vscode:prepublish': 'should-not-run' } }, { dependencies: { synthetic: '*' } },
    { vsce: { allowPackageAllSecrets: true } }, { extensionPack: ['synthetic.other'] }]) {
    try { writeFileSync(path, JSON.stringify({ ...JSON.parse(original), ...fields })); assert.throws(() => inspectSources(source)) }
    finally { writeFileSync(path, original) }
  }
})

test('linked source roots and output directories are refused', async () => {
  const linkedSource = join(root, 'linked-source'), linkedOutput = join(root, 'linked-output')
  symlinkSync(source, linkedSource, process.platform === 'win32' ? 'junction' : 'dir')
  symlinkSync(output, linkedOutput, process.platform === 'win32' ? 'junction' : 'dir')
  assert.throws(() => inspectSources(linkedSource))
  await assert.rejects(packageExtension(source, linkedOutput))
})

async function archive(name, additions, replace) {
  const { ZipFile } = toolRequire('yazl')
  const zip = new ZipFile(), path = join(root, name)
  const done = pipeline(zip.outputStream, createWriteStream(path, { flags: 'wx' }))
  for (const [file, bytes] of entries) zip.addBuffer(file === replace ? Buffer.from('changed') : bytes, file)
  for (const [file, bytes, options] of additions) zip.addBuffer(bytes, file, options)
  zip.end(); await done; return path
}

test('unexpected or duplicated archive entries are rejected', async () => {
  await assert.rejects(readVsix(await archive('extra.vsix', [['extension/.env', Buffer.from('synthetic')]])))
  await assert.rejects(readVsix(await archive('duplicate.vsix', [['extension/package.json', Buffer.from('{}')]])))
})

test('a modified worker cannot pass byte verification', async () => {
  await assert.rejects(verifyVsix(await archive('changed.vsix', [], 'extension/dist/worker.cjs'), source))
})

test('the worker inside the VSIX scans without the development source tree', async () => {
  const workerFile = join(root, 'installed-worker.cjs'), project = join(root, 'project')
  writeFileSync(workerFile, entries.get('extension/dist/worker.cjs'))
  mkdirSync(project); writeFileSync(join(project, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  const response = await new Promise((resolve, reject) => {
    const worker = new Worker(workerFile, { execArgv: [], workerData: { root: project, all: true, noConfig: true, noIgnoreMarkers: true }, stdout: true, stderr: true })
    let finished = false
    const timer = setTimeout(() => finish(new Error('Packaged worker timed out')), 20000)
    const finish = (error, value) => {
      if (finished) return
      finished = true; clearTimeout(timer)
      worker.terminate().then(() => error ? reject(error) : resolve(value), reject)
    }
    worker.on('message', value => { if (value.type === 'result') finish(null, value); else if (value.type !== 'progress') finish(new Error('Packaged worker failed')) })
    worker.on('error', () => finish(new Error('Packaged worker failed')))
    worker.on('exit', () => { if (!finished) finish(new Error('Packaged worker exited early')) })
    worker.stdout.on('data', () => finish(new Error('Unexpected packaged worker output')))
    worker.stderr.on('data', () => finish(new Error('Unexpected packaged worker diagnostic')))
  })
  assert.equal(response.result.exitCode, 1)
  assert.equal(response.result.report.partial, false)
  assert.equal(response.result.report.findings[0].ruleId, 'firebase/open-rules')
  assert.equal(response.result.report.findings[0].excerpt, null)
})
