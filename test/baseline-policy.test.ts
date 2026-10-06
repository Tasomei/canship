/** 接受理由与 UTC 有效期独立于指纹；到期记录不再抑制发现。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { acceptBaseline, applyBaseline, buildBaseline, fingerprintOf, migrateBaseline, pruneBaseline,
  readBaseline, reviewBaseline, validateBaselinePolicy } from '../src/baseline.js'
import { serializeBaselineCandidate } from '../src/report/baseline-review.js'
import type { Finding } from '../src/types.js'

const finding: Finding = { ruleId: 'firebase/open-rules', file: 'firestore.rules', line: 1, title: 'Open rules',
  severity: 'P1', confidence: 'certain', excerpt: null, sourceFingerprint: 'synthetic-source', why: [], fix: [] }
const start = new Date('2026-01-01T00:00:00.000Z')
const deadline = '2026-01-02T00:00:00.000Z'
const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
function project(): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-policy-')); roots.push(root)
  writeFileSync(join(root, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  return root
}
function cli(root: string, ...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, ...args], { encoding: 'utf8', timeout: 30_000 })
}

test('acceptance expires at the exact UTC boundary without changing finding identity', () => {
  const id = fingerprintOf(finding)
  const baseline = acceptBaseline([finding], buildBaseline([]), [{ fingerprint: id, count: 1 }],
    { reason: 'Temporary test endpoint', expiresAt: deadline }, start)
  assert.equal(baseline.version, 4)
  assert.equal(baseline.entries[0]!.fingerprint, id)
  assert.equal(applyBaseline([finding], baseline, new Date(Date.parse(deadline) - 1)).suppressed, 1)
  const expired = applyBaseline([finding], baseline, new Date(deadline))
  assert.equal(expired.suppressed, 0)
  assert.equal(expired.kept.length, 1)
  assert.equal(expired.expired, 1)
  assert.equal(expired.stale, 0)
})

test('different decisions on the same fingerprint keep independent counts and expiry', () => {
  const id = fingerprintOf(finding)
  const temporary = acceptBaseline([finding, finding], buildBaseline([]), [{ fingerprint: id, count: 1 }], { expiresAt: deadline }, start)
  const combined = acceptBaseline([finding, finding], temporary, [{ fingerprint: id, count: 1 }], { reason: 'Intentionally public fixture' }, start)
  assert.equal(combined.entries.length, 2)
  assert.equal(combined.entries[0]!.expiresAt, deadline)
  assert.equal(combined.entries[1]!.expiresAt, undefined)
  const afterExpiry = applyBaseline([finding, finding], combined, new Date(deadline))
  assert.equal(afterExpiry.suppressed, 1)
  assert.equal(afterExpiry.kept.length, 1)
  assert.equal(afterExpiry.expired, 1)
})

test('renewal accepts only requested counts and never revives the old allowance', () => {
  const id = fingerprintOf(finding)
  const old = buildBaseline([finding, finding]); old.entries[0]!.expiresAt = deadline
  const renewed = acceptBaseline([finding, finding], old, [{ fingerprint: id, count: 1 }],
    { reason: 'Reassessed', expiresAt: '2026-01-04T00:00:00Z' }, new Date(deadline))
  assert.equal(renewed.entries.length, 2)
  assert.equal(renewed.entries[0]!.count, 2)
  assert.equal(renewed.entries[0]!.expiresAt, deadline)
  assert.equal(applyBaseline([finding, finding], renewed, new Date(deadline)).suppressed, 1)
})

test('pruning preserves active policy metadata and explicitly removes expired decisions', () => {
  const baseline = buildBaseline([finding]); baseline.entries[0]!.reason = 'Test fixture'; baseline.entries[0]!.expiresAt = deadline
  const retained = pruneBaseline([finding], baseline, start)
  assert.equal(retained.entries[0]!.reason, 'Test fixture')
  assert.equal(retained.entries[0]!.expiresAt, deadline)
  const review = reviewBaseline([finding], baseline, new Date(deadline))
  assert.deepEqual(review.counts, { retained: 0, unmatched: 0, unaccepted: 1, expired: 1 })
  assert.equal(pruneBaseline([finding], baseline, new Date(deadline)).entries.length, 0)
})

test('legacy v3 remains readable but policy fields require v4', () => {
  const root = project(); const path = join(root, 'baseline.json')
  const old = { ...buildBaseline([finding]), version: 3 }
  writeFileSync(path, JSON.stringify(old))
  assert.equal(applyBaseline([finding], readBaseline(path)).suppressed, 1)
  assert.equal(migrateBaseline([finding], old).version, 4)
  for (const policy of [{ reason: 'Unexpected legacy metadata' }, { expiresAt: deadline }]) {
    writeFileSync(path, JSON.stringify({ ...old, entries: [{ ...old.entries[0], ...policy }] }))
    assert.throws(() => readBaseline(path), /require baseline v4/)
  }
})

test('invalid reason, calendar date, timezone or already expired policy is rejected', () => {
  for (const reason of ['', ' ', 'x'.repeat(501), 'line\nline', '\u0085']) {
    assert.throws(() => validateBaselinePolicy({ reason }, start))
  }
  for (const expiresAt of ['2026-01-01', '2026-02-30T00:00:00Z', '2026-01-02T00:00:00+08:00',
    '2025-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'not-a-date']) {
    assert.throws(() => validateBaselinePolicy({ expiresAt }, start))
  }
  assert.deepEqual(validateBaselinePolicy({ reason: '  Fixture  ', expiresAt: '2026-01-02T00:00:00Z' }, start),
    { reason: 'Fixture', expiresAt: deadline })
  assert.throws(() => validateBaselinePolicy({}, new Date('invalid')))
})

test('malformed on-disk policy fails closed instead of silently accepting forever', () => {
  const root = project(); const path = join(root, 'baseline.json'); const baseline = buildBaseline([finding])
  for (const change of [{ expiresAt: 'invalid' }, { expiresAt: null }, { reason: 3 }, { reason: '\u0085' }, { count: Number.MAX_SAFE_INTEGER + 1 }]) {
    writeFileSync(path, JSON.stringify({ ...baseline, entries: [{ ...baseline.entries[0], ...change }] }))
    assert.throws(() => readBaseline(path), /malformed/)
  }
})

test('candidate redaction covers reasons preserved by migration and pruning', () => {
  const token = ['sk', 'proj', 'Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s'].join('-')
  const baseline = buildBaseline([finding]); baseline.entries[0]!.reason = token
  for (const candidate of [migrateBaseline([finding], baseline), pruneBaseline([finding], baseline)]) {
    assert.ok(!serializeBaselineCandidate(candidate).includes(token))
  }
  assert.equal(baseline.entries[0]!.reason, token)
})

test('CLI records optional policies without mutating the source and expired findings return in every output', () => {
  const root = project(); const future = new Date(Date.now() + 86_400_000).toISOString()
  const id = JSON.parse(cli(root, '--baseline-review', '--json').stdout).unaccepted[0].fingerprint
  const acceptance = cli(root, `--baseline-accept=${id}`, '--baseline-reason=Temporary fixture', `--baseline-expires=${future}`)
  assert.equal(acceptance.status, 0, acceptance.stderr)
  const baseline = JSON.parse(acceptance.stdout)
  assert.equal(baseline.version, 4)
  assert.equal(baseline.entries[0].reason, 'Temporary fixture')
  assert.equal(baseline.entries[0].expiresAt, future)
  const path = join(root, 'accepted.json'); writeFileSync(path, acceptance.stdout)
  assert.equal(cli(root, '--json', `--baseline=${path}`).status, 0)
  baseline.entries[0].expiresAt = '2000-01-01T00:00:00Z'; writeFileSync(path, JSON.stringify(baseline))
  const original = readFileSync(path, 'utf8')
  const html = join(root, 'report.html'); const sarif = join(root, 'report.sarif')
  const report = cli(root, '--json', `--baseline=${path}`, `--report=${html}`, `--sarif=${sarif}`)
  assert.equal(report.status, 1, report.stderr)
  assert.equal(JSON.parse(report.stdout).baselineExpired, 1)
  assert.equal(JSON.parse(report.stdout).baselineSuppressed, 0)
  for (const text of [cli(root, `--baseline=${path}`).stdout, cli(root, `--baseline=${path}`, '--fix-prompt').stdout,
    readFileSync(html, 'utf8'), readFileSync(sarif, 'utf8')]) assert.match(text, /1 baseline acceptances expired/)
  const review = JSON.parse(cli(root, `--baseline=${path}`, '--baseline-review', '--json').stdout)
  assert.equal(review.expired[0].reason, 'Temporary fixture')
  assert.equal(review.counts.expired, 1)
  assert.equal(readFileSync(path, 'utf8'), original)
  for (const flags of [['--baseline-reason=Unused'], ['--baseline-expires=invalid'],
    [`--baseline-accept=${id}`, '--baseline-expires=invalid'], [`--baseline-accept=${id}`, '--baseline-reason=']]) {
    const refused = cli(root, ...flags)
    assert.equal(refused.status, 3)
    assert.equal(refused.stdout, '')
  }
})
