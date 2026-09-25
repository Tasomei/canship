/** 验证报告结构、省略摘录和基线身份的稳定性。
 * canship-ignore-file */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { Ajv } from 'ajv'
import { fingerprintOf } from '../src/baseline.js'
import type { Finding } from '../src/types.js'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const root = mkdtempSync(join(tmpdir(), 'canship-output-contract-'))
after(() => rmSync(root, { recursive: true, force: true }))
const schema = JSON.parse(readFileSync(join(repository, 'schemas/scan-report-v1.schema.json'), 'utf8'))
const validate = new Ajv({ allErrors: true }).compile(schema)
// 未知值仅用于验证摘录省略，不按有效凭据处理。
writeFileSync(join(root, 'cors.ts'), "const undisclosed='PRIVATE_EXCERPT_SENTINEL'; const options={origin:true,credentials:true}; app.use(cors(options));")
function cli(...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', join(repository, 'src/cli.ts'), root, ...args], {
    cwd: repository, encoding: 'utf8', timeout: 20_000,
  })
}
test('standard and excerpt-free JSON both match the versioned schema with unchanged finding identities', () => {
  const standard = cli('--json', '--all')
  const omitted = cli('--json', '--all', '--no-excerpts')
  assert.equal(standard.status, 1)
  assert.equal(omitted.status, standard.status)
  const a = JSON.parse(standard.stdout)
  const b = JSON.parse(omitted.stdout)
  assert.equal(validate(a), true, JSON.stringify(validate.errors))
  assert.equal(validate(b), true, JSON.stringify(validate.errors))
  assert.match(standard.stdout, /PRIVATE_EXCERPT_SENTINEL/)
  assert.doesNotMatch(omitted.stdout, /PRIVATE_EXCERPT_SENTINEL/)
  assert.equal(b.excerptsOmitted, true)
  assert.equal(b.findings[0].excerpt, null)
  assert.deepEqual(a.findings.map((f: Finding) => fingerprintOf(f)), b.findings.map((f: Finding) => fingerprintOf(f)))
})
test('terminal, fix prompt, HTML and SARIF carry no raw excerpts', () => {
  const html = join(root, 'report.html')
  const sarif = join(root, 'report.sarif')
  const terminal = cli('--no-excerpts', `--report=${html}`, `--sarif=${sarif}`)
  const prompt = cli('--no-excerpts', '--fix-prompt')
  assert.equal(terminal.status, 1)
  assert.equal(prompt.status, 1)
  for (const text of [terminal.stdout, prompt.stdout, readFileSync(html, 'utf8'), readFileSync(sarif, 'utf8')]) {
    assert.doesNotMatch(text, /PRIVATE_EXCERPT_SENTINEL/)
    assert.match(text, /cors\.ts/)
  }
})
test('omitting excerpts does not change existing baseline matches', () => {
  assert.equal(cli('--baseline-write').status, 0)
  const output = cli('--json', '--baseline', '--no-excerpts')
  assert.equal(output.status, 0)
  const report = JSON.parse(output.stdout)
  assert.equal(report.baselineSuppressed, 1)
  assert.deepEqual(report.findings, [])
  assert.equal(validate(report), true, JSON.stringify(validate.errors))
})
test('schema validation rejects corrupt fields and allows compatible additions', () => {
  const report = JSON.parse(cli('--json').stdout)
  assert.equal(validate({ ...report, futureField: { enabled: true } }), true)
  for (const change of [{ schemaVersion: 2 }, { partial: 'false' }, { filesScanned: -1 }, { findings: [{}] },
    { errors: [{ kind: 'hidden' }] }, { skipped: [{ path: 'x', reason: 'unknown' }] }]) {
    assert.equal(validate({ ...report, ...change }), false)
  }
})
