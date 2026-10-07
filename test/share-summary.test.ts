/** 分享输出只保留计数及范围标记，成功和失败路径均不得泄露项目文本。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createShareSummary, renderShareSummary } from '../src/report/share.js'
import type { Finding, ScanResult } from '../src/types.js'

const privateText = 'PRIVATE_CONTENT_DO_NOT_SHARE'
const finding: Finding = { ruleId: privateText, file: privateText, line: 42, title: privateText, excerpt: privateText,
  sourceFingerprint: privateText, severity: 'P1', confidence: 'likely', why: [privateText], fix: [privateText] }
const result: ScanResult = { findings: [finding], filesScanned: 1, durationMs: 123, partial: true,
  errors: [{ ruleId: privateText, file: privateText, message: privateText, kind: 'incomplete' }],
  skipped: [{ path: privateText, reason: 'unreadable' }], ignored: [privateText],
  ignoredFindings: [{ file: privateText, line: 42, ruleId: privateText }],
  ruleSelection: { only: [privateText], skip: [], removed: 1 }, vendored: 0 }
const options = { bestEffort: false, baselineApplied: true, baselineSuppressed: 2, baselineStale: 1,
  baselineExpired: 1, configEnabled: true, honorIgnoreMarkers: true }
const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
function project(): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-share-')); roots.push(root)
  writeFileSync(join(root, 'index.ts'), 'export const ok=true;')
  return root
}
function cli(root: string, ...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, ...args], { encoding: 'utf8', timeout: 30_000 })
}

test('the whitelist omits paths, titles, evidence, diagnostics, selectors and future fields', () => {
  const summary = createShareSummary({ ...result, internalData: privateText } as ScanResult, options)
  for (const text of [JSON.stringify(summary), renderShareSummary(summary)]) assert.ok(!text.includes(privateText))
  assert.equal(summary.kind, 'share-summary')
  assert.equal(summary.partial, true)
  assert.equal(summary.exitCode, 2)
  assert.deepEqual(summary.counts, { findings: 1, blocking: 0, likely: 1, P0: 0, P1: 1, P2: 0,
    filesScanned: 1, errors: 1, skipped: 1, ignoredFiles: 1, ignoredFindings: 1, excludedPaths: 0,
    baselineSuppressed: 2, baselineStale: 1, baselineExpired: 1 })
  assert.equal(summary.scope.rulesRestricted, true)
  assert.equal(summary.scope.baselineApplied, true)
  assert.ok(!('root' in summary) && !('findings' in summary))
})

test('summary status keeps blockers, hidden likely results and incomplete coverage distinct', () => {
  assert.equal(createShareSummary({ ...result, findings: [{ ...finding, confidence: 'certain' }] }, { ...options, bestEffort: true }).exitCode, 1)
  assert.equal(createShareSummary(result, { ...options, bestEffort: true }).exitCode, 2)
  assert.equal(createShareSummary({ ...result, findings: [] }, options).exitCode, 3)
  const accepted = createShareSummary({ ...result, findings: [] }, { ...options, bestEffort: true })
  assert.equal(accepted.exitCode, 0)
  assert.equal(accepted.partial, true)
  assert.equal(accepted.scope.bestEffort, true)
  assert.throws(() => createShareSummary(result, { ...options, baselineSuppressed: NaN }))
})

test('CLI counts likely results even when the normal view hides them', () => {
  const root = project()
  writeFileSync(join(root, `${privateText}.rules`), 'match /items/{id} { allow read: if true; }')
  const run = cli(root, '--share-summary', '--json')
  assert.equal(run.status, 2, run.stderr)
  const summary = JSON.parse(run.stdout)
  assert.equal(summary.counts.findings, 1)
  assert.equal(summary.counts.likely, 1)
  assert.equal(summary.partial, false)
  assert.ok(!run.stdout.includes(root) && !run.stdout.includes(privateText))
  assert.deepEqual(JSON.parse(cli(root, '--share-summary', '--json', '--all').stdout), summary)
  assert.match(cli(root, '--share-summary').stdout, /Counts may still be sensitive/)
})

test('baseline and rule exclusions remain disclosed without publishing their contents', () => {
  const root = project()
  writeFileSync(join(root, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  assert.equal(cli(root, '--baseline-write').status, 0)
  const baselinePath = join(root, 'canship-baseline.json'); const before = readFileSync(baselinePath, 'utf8')
  const accepted = cli(root, '--share-summary', '--json', '--baseline')
  assert.equal(accepted.status, 0)
  assert.equal(JSON.parse(accepted.stdout).counts.baselineSuppressed, 1)
  assert.equal(JSON.parse(accepted.stdout).scope.baselineApplied, true)
  const excluded = cli(root, '--share-summary', '--json', '--skip=firebase')
  assert.equal(excluded.status, 0)
  assert.equal(JSON.parse(excluded.stdout).scope.rulesRestricted, true)
  assert.equal(readFileSync(baselinePath, 'utf8'), before)
})

test('failure output never repeats invalid paths, config values or arguments', () => {
  const root = project()
  writeFileSync(join(root, 'canship.config.json'), JSON.stringify({ [privateText]: true }))
  for (const run of [cli(root, '--share-summary'), cli(join(root, privateText), '--share-summary'),
    cli(root, '--share-summary', `--unknown-${privateText}`),
    cli(root, '--share-summary', '--no-config', `--baseline=${join(root, privateText)}`)]) {
    assert.equal(run.status, 3)
    assert.equal(run.stdout, '')
    assert.match(run.stderr, /\[[A-Z_]+\]/)
    assert.ok(!run.stderr.includes(root) && !run.stderr.includes(privateText))
    assert.match(run.stderr, /Re-run without --share-summary locally/)
  }
})

test('detailed outputs and other operations cannot be combined with sharing', () => {
  const root = project()
  for (const flag of ['--report', '--sarif', '--fix-prompt', '--verbose', '--changed-since=HEAD', '--init',
    '--baseline-write', '--baseline-review', '--baseline-prune', '--baseline-migrate', '--doctor', '--build-info', '--explain-config']) {
    const run = cli(root, '--share-summary', flag)
    assert.equal(run.status, 3, flag)
    assert.equal(run.stdout, '')
  }
  assert.deepEqual(readdirSync(root), ['index.ts'])
})
