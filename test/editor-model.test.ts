/** 编辑器路径、抑制预览及版本失效逻辑不依赖图形宿主。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { findingPath, independentRoots, Revisions, suppressionPreview } from '../extensions/vscode/src/model.js'
import type { Finding } from '../src/types.js'
import { scanConfiguredProject } from '../src/workspaces.js'

const root = mkdtempSync(join(tmpdir(), 'canship-editor-model-'))
after(() => rmSync(root, { recursive: true, force: true }))
const source = 'const credential = value;'
const finding: Finding = { ruleId: 'secrets/hardcoded/openai', severity: 'P0', confidence: 'certain', title: 'Sample',
  file: 'file.ts', line: 2, excerpt: null, sourceFingerprint: createHash('sha256').update(source).digest('hex'), why: [], fix: [] }
test('diagnostic paths stay within regular files of the selected root', () => {
  mkdirSync(join(root, 'nested')); writeFileSync(join(root, 'nested', 'file.ts'), source)
  assert.equal(findingPath(root, 'nested/file.ts'), join(root, 'nested', 'file.ts'))
  for (const file of [null, '', '../outside', '/absolute', 'C:/absolute', 'nested/../file.ts', 'missing.ts', 'nested']) assert.equal(findingPath(root, file), null)
  symlinkSync(join(root, 'nested'), join(root, 'linked'), process.platform === 'win32' ? 'junction' : 'dir')
  assert.equal(findingPath(root, 'linked/file.ts'), null)
})
test('line suppression preserves indentation and line endings and never rewrites source', () => {
  const text = '\r\n  ' + source + '\r\n'
  assert.deepEqual(suppressionPreview('file.ts', text, finding), { line: 1, text: '  // canship-ignore-next-line secrets/hardcoded/openai\r\n' })
  assert.equal(text, '\r\n  ' + source + '\r\n')
  const sql = { ...finding, sourceFingerprint: createHash('sha256').update('CREATE TABLE notes(id int);').digest('hex') }
  assert.equal(suppressionPreview('file.sql', '\nCREATE TABLE notes(id int);', sql)?.text, '-- canship-ignore-next-line secrets/hardcoded/openai\n')
})
test('stale evidence, unsupported syntax and string/comment contexts cannot get automatic suppression', () => {
  for (const text of ['\nconst credential=changed;', 'const text = `\n' + source + '\n`;', '/*\n' + source + '\n*/']) assert.equal(suppressionPreview('file.ts', text, finding), null)
  for (const extension of ['json', 'tsx', 'jsx', 'vue', 'env']) assert.equal(suppressionPreview('file.' + extension, '\n' + source, finding), null)
  assert.equal(suppressionPreview('file.ts', '\n' + source, { ...finding, ruleId: 'rule\n*/' }), null)
  assert.equal(suppressionPreview('file.ts', '\n' + source, { ...finding, line: null }), null)
})
test('new requests invalidate old results independently for each workspace', () => {
  const versions = new Revisions(), first = versions.next('first'), second = versions.next('second')
  assert.equal(versions.current('first', first), true)
  versions.next('first')
  assert.equal(versions.current('first', first), false)
  assert.equal(versions.current('second', second), true)
  versions.clear(); assert.equal(versions.current('second', second), false)
})
test('overlapping, duplicate and unavailable workspace roots are rejected', () => {
  const first = join(root, 'root-a'), second = join(root, 'root-b')
  mkdirSync(first); mkdirSync(second)
  assert.equal(independentRoots([first, second]), true)
  assert.equal(independentRoots([root, first]), false)
  assert.equal(independentRoots([first, first]), false)
  assert.equal(independentRoots([join(root, 'missing')]), false)
  assert.equal(independentRoots([]), false)
})
test('configured editor scans reuse project selection without changing the low-level API', async () => {
  const project = join(root, 'project'); mkdirSync(project)
  writeFileSync(join(project, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  writeFileSync(join(project, 'canship.config.json'), JSON.stringify({ only: ['cors'] }))
  const options = { all: false, noConfig: false, noExcerpts: true, noIgnoreMarkers: false, bestEffort: false,
    baselineDefault: false, only: [], skip: [], exclude: [] }
  const configured = await scanConfiguredProject(project, options)
  assert.equal(configured.exitCode, 0)
  assert.equal(configured.config?.sources.rules, 'config')
  assert.equal((await scanConfiguredProject(project, { ...options, noConfig: true })).exitCode, 1)
})
test('extension manifest uses bundled code, opt-in saves and explicit trust boundaries', () => {
  const manifest = JSON.parse(readFileSync(new URL('../extensions/vscode/package.json', import.meta.url), 'utf8'))
  assert.equal(manifest.capabilities.untrustedWorkspaces.supported, false)
  assert.equal(manifest.capabilities.virtualWorkspaces.supported, false)
  assert.equal(manifest.contributes.configuration.properties['canship.scanOnSave'].default, false)
  assert.equal(manifest.main, './dist/extension.cjs')
  assert.equal(Object.keys(manifest.dependencies ?? {}).length, 0)
  assert.deepEqual(readFileSync(new URL('../extensions/vscode/LICENSE', import.meta.url)), readFileSync(new URL('../LICENSE', import.meta.url)))
})
