/** 验证公共 API 的输入、覆盖信息及隔离性；模拟项目不执行代码。 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { scan, summarize, listRules } from '../src/index.js'
import type { ScanOptions, ScanResult } from '../src/index.js'

const root = mkdtempSync(join(tmpdir(), 'canship-api-test-'))
after(() => rmSync(root, { recursive: true, force: true }))
function project(name: string, files: Record<string, string>): string {
  const dir = join(root, name)
  mkdirSync(dir)
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body)
  return dir
}
const open = project('open', { 'firestore.rules': 'match /items/{id} { allow write: if true; }' })
const clean = project('clean', { 'index.ts': 'export const ready = true;' })

test('scan returns results without changing the working directory or exit status', async () => {
  const cwd = process.cwd()
  const exit = process.exitCode
  const before = readFileSync(join(open, 'firestore.rules'), 'utf8')
  const result = await scan(open, { noExcerpts: true })
  assert.deepEqual(summarize(result), { findings: 1, blocking: 1, likely: 0, partial: false, exitCode: 1 })
  assert.equal(result.findings[0]!.excerpt, null)
  assert.equal(process.cwd(), cwd)
  assert.equal(process.exitCode, exit)
  assert.equal(readFileSync(join(open, 'firestore.rules'), 'utf8'), before)
})

test('the API does not load project config or an existing baseline', async () => {
  const dir = project('config', { 'canship.config.json': '{broken', 'canship-baseline.json': '{broken',
    'firestore.rules': 'match /items/{id} { allow write: if true; }' })
  assert.equal(summarize(await scan(dir)).exitCode, 1)
})

test('markers can be disabled independently of rule selection', async () => {
  const dir = project('ignored', { 'index.ts': 'export const ok = true;',
    'firestore.rules': '// canship-ignore-file\nmatch /items/{id} { allow write: if true; }' })
  assert.equal((await scan(dir)).findings.length, 0)
  assert.equal((await scan(dir, { honorIgnoreMarkers: false })).findings.length, 1)
  assert.equal((await scan(dir, { only: ['cors'], honorIgnoreMarkers: false })).findings.length, 0)
})

test('likely results remain visible and incomplete coverage never becomes clean', async () => {
  const dir = project('likely', { 'firestore.rules': 'match /items/{id} { allow read: if true; }' })
  assert.deepEqual(summarize(await scan(dir)), { findings: 1, blocking: 0, likely: 1, partial: false, exitCode: 2 })
  const empty = project('empty', {})
  assert.equal(summarize(await scan(empty)).exitCode, 3)
  const base = await scan(clean)
  assert.equal(summarize({ ...base, skipped: [{ path: 'a', reason: 'unreadable' }] }).exitCode, 3)
  assert.equal(summarize({ ...base, partial: true, findings: (await scan(open)).findings }).exitCode, 1)
})

test('invalid inputs are rejected without echoing their values', async () => {
  for (const options of [null, [], { only: 'firebase' }, { only: Array(1) }, { only: ['PRIVATE_SENTINEL'] },
    { only: ['firebase'], skip: ['cors'] }, { noExcerpts: 'yes' }, { honorIgnoreMarkers: 0 }, { PRIVATE_SENTINEL: true }]) {
    await assert.rejects(scan(clean, options as unknown as ScanOptions), error => {
      assert.ok(error instanceof Error)
      assert.doesNotMatch(error.message, /PRIVATE_SENTINEL/)
      return true
    })
  }
  for (const path of ['', join(root, 'missing'), join(open, 'firestore.rules')]) await assert.rejects(scan(path))
})

test('concurrent scans and catalog changes do not affect another caller', async () => {
  const rules = listRules()
  assert.ok(rules.length > 10)
  rules[0]!.id = 'changed'
  assert.notEqual(listRules()[0]!.id, 'changed')
  const results: ScanResult[] = await Promise.all([scan(open), scan(clean), scan(open, { skip: ['firebase'] })])
  assert.deepEqual(results.map(result => summarize(result).exitCode), [1, 0, 0])
})
