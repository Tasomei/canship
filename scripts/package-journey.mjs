/** 从实际安装包验收审阅、接受、迁移、修复与比较，不导入源码实现。 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

export function verifyPackageJourney({ cli, sample, root }) {
  const rules = 'match /items/{id} { allow write: if true; }'
  const project = sample('journey', { 'firestore.rules': rules, 'storage.rules': rules })
  const output = (args, status) => {
    const result = cli(args)
    assert.equal(result.status, status, result.stderr)
    return JSON.parse(result.stdout)
  }
  const scan = (...args) => output([project, '--json', '--all', '--no-excerpts', ...args], 1)
  const first = scan()
  assert.equal(first.partial, false)
  assert.equal(first.findings.length, 2)
  assert.ok(first.findings.every(finding => finding.excerpt === null))
  const review = output([project, '--baseline-review', '--json'], 0)
  assert.equal(review.counts.unaccepted, 2)
  const chosen = review.unaccepted.find(entry => entry.file === 'firestore.rules')
  assert.ok(chosen)
  const expires = new Date(Date.now() + 86_400_000).toISOString()
  const candidate = output([project, `--baseline-accept=${chosen.fingerprint}`,
    '--baseline-reason=Synthetic acceptance', `--baseline-expires=${expires}`], 0)
  assert.equal(candidate.entries.length, 1)
  assert.equal(candidate.entries[0].reason, 'Synthetic acceptance')
  assert.equal(candidate.entries[0].expiresAt, expires)
  assert.equal(existsSync(join(project, 'canship-baseline.json')), false)
  const baseline = join(root, 'journey-accepted.json')
  const acceptedBytes = JSON.stringify(candidate)
  writeFileSync(baseline, acceptedBytes)
  const accepted = scan(`--baseline=${baseline}`)
  assert.equal(accepted.baselineSuppressed, 1)
  assert.deepEqual(accepted.findings.map(finding => finding.file), ['storage.rules'])

  // v2 旧标题用于验证原指纹，v3/v4 接受记录不能因版本转换而扩大。
  const acceptedFinding = first.findings.find(finding => finding.file === 'firestore.rules')
  const oldTitle = 'Legacy synthetic wording'
  const oldFingerprint = createHash('sha256').update([acceptedFinding.ruleId, acceptedFinding.file,
    oldTitle, acceptedFinding.sourceFingerprint].join('\0')).digest('hex')
  const legacy = join(root, 'journey-v2.json')
  const legacyBytes = JSON.stringify({ version: 2, generatedAt: '', entries: [{ fingerprint: oldFingerprint,
    ruleId: acceptedFinding.ruleId, file: acceptedFinding.file, title: oldTitle, count: 1 }] })
  writeFileSync(legacy, legacyBytes)
  const migrated = output([project, `--baseline-migrate=${legacy}`], 0)
  assert.equal(migrated.version, 4)
  assert.equal(migrated.entries.length, 1)
  assert.equal(migrated.entries[0].fingerprint, chosen.fingerprint)
  assert.equal(readFileSync(legacy, 'utf8'), legacyBytes)
  for (const version of [3, 4]) {
    const path = join(root, `journey-v${version}.json`)
    writeFileSync(path, JSON.stringify({ ...migrated, version }))
    const remaining = scan(`--baseline=${path}`)
    assert.equal(remaining.baselineSuppressed, 1)
    assert.equal(remaining.findings.length, 1)
  }

  // 同一来源仅移动行号时，基线和 SARIF 身份均须保持稳定。
  const sarifBefore = join(root, 'journey-before.sarif')
  scan(`--sarif=${sarifBefore}`)
  writeFileSync(join(project, 'firestore.rules'), '\n\n' + rules)
  const moved = scan(`--baseline=${baseline}`)
  assert.equal(moved.baselineSuppressed, 1)
  const sarifAfter = join(root, 'journey-after.sarif')
  const after = scan(`--sarif=${sarifAfter}`)
  const results = path => JSON.parse(readFileSync(path, 'utf8')).runs[0].results
  const refs = path => results(path).map(item => [item.locations[0].physicalLocation.artifactLocation.uri, item.partialFingerprints])
  assert.deepEqual(refs(sarifAfter), refs(sarifBefore))
  assert.equal(after.findings.find(finding => finding.file === 'firestore.rules').line, acceptedFinding.line + 2)

  // 已接受的问题修复后成为未匹配记录；清理不能顺便接受剩余问题。
  writeFileSync(join(project, 'firestore.rules'), 'match /items/{id} { allow write: if false; }')
  const repaired = scan(`--baseline=${baseline}`)
  assert.equal(repaired.baselineSuppressed, 0)
  assert.equal(repaired.baselineStale, 1)
  const pruned = output([project, '--baseline-prune', `--baseline=${baseline}`], 0)
  assert.equal(pruned.entries.length, 0)
  assert.equal(readFileSync(baseline, 'utf8'), acceptedBytes)
  const beforePath = join(root, 'journey-before.json'), afterPath = join(root, 'journey-after.json')
  writeFileSync(beforePath, JSON.stringify(first))
  const current = scan()
  writeFileSync(afterPath, JSON.stringify(current))
  const comparison = cli([`--compare=${beforePath}`, `--with=${afterPath}`, '--json'])
  const compared = JSON.parse(comparison.stdout)
  assert.equal(comparison.status, first.build.revision && first.build.dirty === false ? 0 : 2)
  assert.equal(compared.counts.persisting, 1)
  assert.equal(compared.counts.notObserved, 1)
  assert.equal(compared.counts.added, 0)
  const shared = output([project, '--share-summary', '--json'], 1)
  assert.equal(shared.counts.findings, 1)
  for (const privateText of [project, 'firestore.rules', 'storage.rules', rules, oldTitle]) {
    assert.ok(!JSON.stringify(shared).includes(privateText))
  }
  writeFileSync(join(project, 'storage.rules'), 'match /items/{id} { allow write: if false; }')
  const clean = output([project, '--json', '--all', '--no-excerpts'], 0)
  assert.equal(clean.partial, false)
  assert.deepEqual(clean.findings, [])
}
