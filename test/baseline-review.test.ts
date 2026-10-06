/** 基线预览与清理不接受新问题；覆盖不足时禁止生成清理候选。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { applyBaseline, buildBaseline, legacyFingerprintOf, pruneBaseline, reviewBaseline } from '../src/baseline.js'
import { scan } from '../src/engine.js'
import { canPruneBaseline, createBaselineReview } from '../src/report/baseline-review.js'
import type { Finding, ScanResult } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
const finding = (source: string): Finding => ({ ruleId: 'firebase/open-rules', file: 'firestore.rules', line: 1,
  severity: 'P1', confidence: 'certain', title: 'Open rules', excerpt: null, sourceFingerprint: source, why: [], fix: [] })

test('review distinguishes retained, unmatched and unaccepted counts including duplicates', () => {
  const a = finding('a'); const b = finding('b'); const c = finding('c')
  const original = buildBaseline([a, a, b])
  const review = reviewBaseline([a, c, c], original)
  assert.deepEqual(review.counts, { retained: 1, unmatched: 2, unaccepted: 2 })
  assert.equal(review.retained[0]!.count, 1)
  assert.equal(review.unmatched.reduce((n, entry) => n + entry.count, 0), 2)
  assert.equal(review.unaccepted[0]!.count, 2)
  const pruned = pruneBaseline([a, c, c], original)
  assert.equal(pruned.entries.length, 1)
  assert.equal(applyBaseline([a, c, c], pruned).kept.length, 2)
  assert.equal(original.entries.reduce((n, entry) => n + entry.count, 0), 3)
})

test('pruning stale v2 records outputs v3 with only matched original allowances', () => {
  const a = finding('a'); const b = finding('b')
  const original = { version: 2, generatedAt: '', entries: [a, b].map(item => ({
    fingerprint: legacyFingerprintOf(item), ruleId: item.ruleId, file: item.file, title: item.title, count: 1,
  })) }
  const current = { ...a, title: 'Updated wording', line: 40 }
  const result = pruneBaseline([current, current], original)
  assert.equal(result.version, 3)
  assert.equal(result.entries[0]!.count, 1)
  assert.equal(applyBaseline([current, current], result).suppressed, 1)
  assert.deepEqual(reviewBaseline([current, current], original).counts, { retained: 1, unmatched: 1, unaccepted: 1 })
})

test('duplicate baseline entries do not inflate the unmatched total', () => {
  const built = buildBaseline([finding('a')])
  built.entries.push({ ...built.entries[0]! })
  const review = reviewBaseline([finding('a')], built)
  assert.equal(review.unmatched.reduce((n, entry) => n + entry.count, 0), review.counts.unmatched)
  assert.equal(review.counts.unmatched, 1)
})

function cli(root: string, ...flags: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, ...flags], { encoding: 'utf8', timeout: 30_000 })
}
async function project() {
  const root = mkdtempSync(join(tmpdir(), 'canship-baseline-review-')); roots.push(root)
  const source = 'match /items/{id} { allow write: if true; }'
  writeFileSync(join(root, 'firestore.rules'), source)
  const baseline = buildBaseline((await scan(root)).findings)
  const path = join(root, 'canship-baseline.json')
  const original = JSON.stringify(baseline)
  writeFileSync(path, original)
  return { root, source, path, original, baseline }
}

test('CLI review and prune preserve the input and never accept newly found problems', async () => {
  const { root, path, original } = await project()
  writeFileSync(join(root, 'storage.rules'), 'match /other/{id} { allow write: if true; }')
  const preview = cli(root, '--baseline-review', '--json')
  assert.equal(preview.status, 0, preview.stderr)
  const body = JSON.parse(preview.stdout)
  assert.equal(body.kind, 'baseline-review')
  assert.equal(body.canPrune, true)
  assert.deepEqual(body.counts, { retained: 1, unmatched: 0, unaccepted: 1 })
  const prune = cli(root, '--baseline-prune')
  assert.equal(prune.status, 0, prune.stderr)
  assert.equal(JSON.parse(prune.stdout).entries.length, 1)
  assert.match(prune.stderr, /no new findings accepted/)
  assert.equal(readFileSync(path, 'utf8'), original)
  assert.match(cli(root, '--baseline-review').stdout, /Unmatched entries are not proof of resolution/)
})

test('partial and selective scans can be reviewed but cannot prune', async () => {
  const { root } = await project()
  let review = cli(root, '--baseline-review', '--json', '--only=firebase')
  assert.equal(review.status, 0)
  assert.equal(JSON.parse(review.stdout).canPrune, false)
  assert.equal(cli(root, '--baseline-prune', '--only=firebase').status, 3)
  writeFileSync(join(root, 'large.ts'), ' '.repeat(2 * 1024 * 1024 + 1))
  review = cli(root, '--baseline-review', '--json')
  assert.equal(review.status, 3)
  assert.equal(JSON.parse(review.stdout).partial, true)
  const refused = cli(root, '--baseline-prune')
  assert.equal(refused.status, 3)
  assert.equal(refused.stdout, '')
})

test('source suppressions prevent pruning until the user explicitly disregards them', async () => {
  const { root, source } = await project()
  writeFileSync(join(root, 'firestore.rules'), '// canship-ignore-file\n' + source)
  writeFileSync(join(root, 'index.ts'), 'export const ok=true;')
  assert.equal(JSON.parse(cli(root, '--baseline-review', '--json').stdout).canPrune, false)
  assert.equal(cli(root, '--baseline-prune').status, 3)
  assert.equal(cli(root, '--baseline-prune', '--no-ignore-markers').status, 0)
})

test('guard checks independent error and skip fields, not only the partial flag', async () => {
  const { root, baseline } = await project()
  const result = await scan(root)
  assert.equal(canPruneBaseline(result), true)
  for (const changes of [
    { filesScanned: 0 }, { errors: [{ ruleId: 'x', file: null, message: 'test' }] },
    { skipped: [{ file: 'test', reason: 'unreadable' }] }, { ignoredFindings: [{ file: 'test', line: 1, ruleId: 'x' }] },
  ]) assert.equal(canPruneBaseline({ ...result, ...changes } as ScanResult), false)
  assert.equal(createBaselineReview(result, baseline).retained.some(entry => 'excerpt' in entry), false)
})

test('conflicting operations are rejected without output', async () => {
  const { root, path, original } = await project()
  for (const flag of ['--baseline-write', '--baseline-migrate', '--baseline-review', '--report', '--sarif',
    '--changed-since=HEAD', '--best-effort', '--doctor', '--explain-config', '--list-rules', '--build-info', '--fix-prompt']) {
    const result = cli(root, '--baseline-prune', flag)
    assert.equal(result.status, 3, flag)
    assert.equal(result.stdout, '')
  }
  assert.equal(readFileSync(path, 'utf8'), original)
})
