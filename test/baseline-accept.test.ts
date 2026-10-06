/** 选择性接受只增加指定指纹的额度，不删除旧条目或写回源文件。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { acceptBaseline, applyBaseline, buildBaseline, fingerprintOf, legacyFingerprintOf } from '../src/baseline.js'
import type { Finding } from '../src/types.js'

const finding = (source: string): Finding => ({ ruleId: 'firebase/open-rules', file: 'firestore.rules', line: 1,
  title: 'Open rule', severity: 'P1', confidence: 'certain', excerpt: null, sourceFingerprint: source, why: [], fix: [] })
const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

test('acceptance preserves stale entries and accepts only the requested duplicate count', () => {
  const a = finding('a'); const b = finding('b'); const old = finding('old')
  const original = buildBaseline([a, old]); const before = JSON.stringify(original)
  const candidate = acceptBaseline([a, a, a, b], original, [{ fingerprint: fingerprintOf(a), count: 1 }])
  assert.equal(candidate.entries.find(entry => entry.fingerprint === fingerprintOf(old))?.count, 1)
  assert.equal(applyBaseline([a, a, a, b], candidate).kept.length, 2)
  assert.equal(JSON.stringify(original), before)
})

test('repeated selections add counts and unknown or excessive selections fail atomically', () => {
  const a = finding('a'); const fingerprint = fingerprintOf(a); const empty = buildBaseline([])
  const accepted = acceptBaseline([a, a, a], empty, [{ fingerprint, count: 1 }, { fingerprint, count: 1 }])
  assert.equal(accepted.entries[0]!.count, 2)
  for (const selections of [[], [{ fingerprint, count: 0 }], [{ fingerprint, count: 0.5 }],
    [{ fingerprint, count: 4 }], [{ fingerprint: '0'.repeat(64), count: 1 }], [{ fingerprint, count: Number.MAX_SAFE_INTEGER + 1 }]]) {
    assert.throws(() => acceptBaseline([a, a, a], empty, selections))
    assert.deepEqual(empty.entries, [])
  }
})

test('legacy acceptance migrates only when no original acceptance is lost', () => {
  const a = finding('a'); const b = finding('b')
  const old = { version: 2, generatedAt: '', entries: [{ fingerprint: legacyFingerprintOf(a), ruleId: a.ruleId, file: a.file, title: a.title, count: 1 }] }
  const selected = [{ fingerprint: fingerprintOf(b), count: 1 }]
  assert.equal(acceptBaseline([a, b], old, selected).version, 3)
  assert.throws(() => acceptBaseline([b], old, selected), /all accepted entries to match/)
})

function project() {
  const root = mkdtempSync(join(tmpdir(), 'canship-baseline-accept-')); roots.push(root)
  writeFileSync(join(root, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  writeFileSync(join(root, 'storage.rules'), 'match /other/{id} { allow write: if true; }')
  return root
}
function cli(root: string, ...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, ...args], { encoding: 'utf8', timeout: 30_000 })
}

test('first-time review and selective acceptance work without silently creating a baseline', () => {
  const root = project()
  const review = cli(root, '--baseline-review', '--json')
  assert.equal(review.status, 0, review.stderr)
  const body = JSON.parse(review.stdout)
  assert.equal(body.counts.unaccepted, 2)
  const candidate = cli(root, `--baseline-accept=${body.unaccepted[0].fingerprint}`)
  assert.equal(candidate.status, 0, candidate.stderr)
  const accepted = JSON.parse(candidate.stdout)
  assert.equal(accepted.entries.length, 1)
  assert.equal(accepted.entries[0].count, 1)
  assert.equal(existsSync(join(root, 'canship-baseline.json')), false)
  assert.match(candidate.stderr, /only selected counts accepted/)
  const target = join(root, 'chosen.json'); writeFileSync(target, candidate.stdout)
  const remaining = cli(root, '--json', '--all', `--baseline=${target}`)
  assert.equal(remaining.status, 1)
  assert.equal(JSON.parse(remaining.stdout).findings.length, 1)
  assert.equal(readFileSync(target, 'utf8'), candidate.stdout)
})

test('explicit missing baselines never fall back to empty acceptance', () => {
  const root = project()
  for (const option of ['--baseline', '--baseline=missing.json']) {
    const result = cli(root, '--baseline-review', '--json', option)
    assert.equal(result.status, 3)
    assert.equal(result.stdout, '')
  }
})

test('CLI accepts comma-separated fingerprints but refuses malformed and incomplete requests', () => {
  const root = project()
  const ids = JSON.parse(cli(root, '--baseline-review', '--json').stdout).unaccepted.map((entry: {fingerprint: string}) => entry.fingerprint)
  const all = cli(root, `--baseline-accept=${ids.join(',')}`)
  assert.equal(all.status, 0, all.stderr)
  assert.equal(JSON.parse(all.stdout).entries.length, 2)
  for (const value of ['', 'PRIVATE_ARGUMENT', `${ids[0]}:0`, `${ids[0]}:1.5`, `${ids[0]}:2`, `${ids[0]},`]) {
    const rejected = cli(root, `--baseline-accept=${value}`)
    assert.equal(rejected.status, 3)
    assert.equal(rejected.stdout, '')
    assert.ok(!rejected.stderr.includes('PRIVATE_ARGUMENT'))
  }
  for (const flag of ['--baseline-review', '--baseline-prune', '--baseline-write', '--doctor', '--only=firebase']) {
    assert.equal(cli(root, `--baseline-accept=${ids[0]}`, flag).status, 3)
  }
  writeFileSync(join(root, 'large.ts'), ' '.repeat(2 * 1024 * 1024 + 1))
  const partial = cli(root, `--baseline-accept=${ids[0]}`)
  assert.equal(partial.status, 3)
  assert.equal(partial.stdout, '')
})
