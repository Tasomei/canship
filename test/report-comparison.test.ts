/** 报告比较必须保留计数与覆盖限制，不回显原始证据或读取项目。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync, mkdirSync, symlinkSync } from 'node:fs'
import fs from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import type { Finding } from '../src/types.js'
import { fingerprintOf } from '../src/baseline.js'
import { ComparisonError, compareReports, MAX_COMPARE_BYTES, parseComparisonInput, readComparisonInput, renderComparison } from '../src/report/compare.js'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const root = mkdtempSync(join(tmpdir(), 'canship-comparison-'))
after(() => rmSync(root, { recursive: true, force: true }))
const digest = (value: string) => createHash('sha256').update(value).digest('hex')
function finding(over: Partial<Finding> = {}): Finding {
  return { ruleId: 'cors/reflected-origin', file: 'src/route.ts', line: 3, severity: 'P1', confidence: 'certain',
    sourceFingerprint: digest('synthetic source'), title: 'PRIVATE_TITLE', excerpt: 'PRIVATE_EXCERPT', why: ['PRIVATE_REASON'], fix: ['PRIVATE_FIX'], ...over }
}
function report(findings: Finding[] = [finding()], changes: Record<string, unknown> = {}) {
  return { schemaVersion: 1, version: '0.7.1', root: 'PRIVATE_SCAN_ROOT', filesScanned: 1, durationMs: 1, partial: false,
    errors: [], skipped: [], ignored: [], ignoredFindings: [], ruleSelection: null, vendored: 0, hiddenLikely: 0,
    baselineSuppressed: 0, baselineStale: 0, baselineExpired: 0,
    build: { version: '0.7.1', channel: 'release', revision: 'a'.repeat(40), dirty: false }, findings, ...changes }
}
const parse = (value: unknown) => parseComparisonInput(JSON.stringify(value))
const compare = (a: unknown, b: unknown) => compareReports(parse(a), parse(b))
function cli(...args: string[]) {
  return spawnSync(process.execPath, ['--import', new URL('../node_modules/tsx/dist/loader.mjs', import.meta.url).href,
    join(repository, 'src/cli.ts'), ...args], { cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024 })
}
function inputs(a: unknown = report(), b: unknown = report()) {
  const before = join(root, 'earlier.json'), after = join(root, 'later.json')
  writeFileSync(before, JSON.stringify(a)); writeFileSync(after, JSON.stringify(b))
  return [`--compare=${before}`, `--with=${after}`]
}

test('stable v3 identities survive title, line, excerpt and classification changes', () => {
  const a = finding(), b = finding({ title: 'Renamed', line: 91, excerpt: null, severity: 'P2', confidence: 'likely' })
  const result = compare(report([a]), report([b]))
  assert.equal(result.exitCode, 0)
  assert.equal(result.limited, false)
  assert.deepEqual(result.counts, { before: 1, after: 1, added: 0, persisting: 1, notObserved: 0, unpairedBefore: 0, unpairedAfter: 0 })
  assert.equal(result.entries[0]!.fingerprint, fingerprintOf(a))
  assert.equal(result.entries[0]!.before.firstLine, 3)
  assert.equal(result.entries[0]!.after.firstLine, 91)
  assert.deepEqual(result.entries[0]!.after.levels, [{ severity: 'P2', confidence: 'likely', count: 1 }])
  assert.match(renderComparison(result), /not a scan verdict/)
})

test('source, rule and path changes are distinct; no rename or remediation is inferred', () => {
  for (const change of [{ sourceFingerprint: digest('other source') }, { file: 'moved.ts' }, { ruleId: 'future/check' }]) {
    const result = compare(report(), report([finding(change)]))
    assert.equal(result.counts.added, 1)
    assert.equal(result.counts.notObserved, 1)
    assert.equal(result.counts.persisting, 0)
    assert.match(result.notice, /not proof of remediation/)
  }
})

test('duplicate identities retain multiplicity and classification counts independent of order', () => {
  const first = finding(), second = finding({ line: 7, confidence: 'likely' })
  const result = compare(report([first, second]), report([second, first, finding({ line: 11 })]))
  assert.equal(result.counts.persisting, 2)
  assert.equal(result.counts.added, 1)
  assert.deepEqual(result, compare(report([second, first]), report([first, finding({ line: 11 }), second])))
  const reverse = compare(report([first, first, second]), report([second]))
  assert.equal(reverse.counts.notObserved, 2)
  assert.equal(reverse.counts.persisting, 1)
})

test('empty valid reports compare without treating zero scanned files as success', () => {
  assert.equal(compare(report([]), report([])).exitCode, 0)
  const result = compare(report([]), report([], { filesScanned: 0 }))
  assert.equal(result.exitCode, 2)
  assert.ok(result.warnings.some(w => w.code === 'INCOMPLETE'))
})

test('every coverage restriction remains visible even when both inputs have the same restriction', () => {
  const cases: [Record<string, unknown>, string][] = [
    [{ partial: true }, 'INCOMPLETE'],
    [{ errors: [{ ruleId: 'test/check', file: null, message: 'PRIVATE_ERROR', kind: 'crashed' }] }, 'INCOMPLETE'],
    [{ skipped: [{ path: 'PRIVATE_SKIPPED', reason: 'unreadable' }] }, 'INCOMPLETE'],
    [{ hiddenLikely: 1 }, 'HIDDEN_FINDINGS'], [{ baselineSuppressed: 1 }, 'BASELINE_APPLIED'],
    [{ baselineStale: 1 }, 'BASELINE_APPLIED'], [{ baselineExpired: 1 }, 'BASELINE_APPLIED'],
    [{ ignored: ['PRIVATE_IGNORED'] }, 'RESTRICTED_SCOPE'],
    [{ ignoredFindings: [{ file: 'ignored.ts', line: 1, ruleId: 'test/check' }] }, 'RESTRICTED_SCOPE'],
    [{ ruleSelection: { only: ['cors'], skip: [], removed: 0 } }, 'RESTRICTED_SCOPE'],
    [{ exclusions: { requested: ['PRIVATE_EXCLUDED'], matched: [] } }, 'RESTRICTED_SCOPE'],
    [{ changeView: { baseCommit: 'a'.repeat(40), mergeBase: 'a'.repeat(40), changedFiles: 1, hiddenFindings: 0, totalFindings: 1, totalBlocking: 1, totalLikely: 0 } }, 'CHANGED_VIEW'],
  ]
  for (const [change, code] of cases) {
    const result = compare(report([finding()], change), report([finding()], change))
    assert.equal(result.exitCode, 2, code)
    assert.ok(result.warnings.some(w => w.code === code), code)
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_(?:ERROR|SKIPPED|IGNORED|EXCLUDED)/)
  }
})

test('cross-root, upgraded and unverifiable builds cannot appear fully comparable', () => {
  const cases: [Record<string, unknown>, string][] = [
    [{ root: 'OTHER_PRIVATE_ROOT' }, 'ROOT_CHANGED'],
    [{ version: '0.8.0', build: undefined }, 'SCANNER_CHANGED'],
    [{ build: { version: '0.7.1', channel: 'release', revision: 'b'.repeat(40), dirty: false } }, 'SCANNER_CHANGED'],
    [{ build: undefined }, 'BUILD_UNVERIFIED'],
    [{ build: { version: '0.7.1', channel: 'development', revision: null, dirty: null } }, 'BUILD_UNVERIFIED'],
    [{ build: { version: '0.7.1', channel: 'development', revision: 'a'.repeat(40), dirty: true } }, 'BUILD_UNVERIFIED'],
  ]
  for (const [change, code] of cases) {
    const result = compare(report(), report([], change))
    assert.equal(result.exitCode, 2)
    assert.ok(result.warnings.some(w => w.code === code), code)
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_ROOT/)
  }
})

test('missing or non-digest identities are unpaired, never collapsed through redacted excerpts', () => {
  const { sourceFingerprint: _omitted, ...old } = finding()
  for (const f of [old, finding({ sourceFingerprint: 'not-a-digest' })]) {
    const result = compare(report([f]), report([f]))
    assert.equal(result.entries.length, 0)
    assert.equal(result.counts.added, 0)
    assert.equal(result.counts.notObserved, 0)
    assert.equal(result.counts.unpairedBefore, 1)
    assert.equal(result.counts.unpairedAfter, 1)
    assert.ok(result.warnings.some(w => w.code === 'IDENTITY_MISSING'))
  }
})

test('comparison outputs whitelist fields and clean hostile terminal text', () => {
  const f = finding({ file: 'src/\u001b[31mroute.ts', ruleId: 'rule\u202etext', humanOnly: ['PRIVATE_ACTION'] })
  const result = compare(report([f], { futureField: 'PRIVATE_UNKNOWN' }), report([f]))
  for (const text of [JSON.stringify(result), renderComparison(result)]) {
    assert.doesNotMatch(text, /PRIVATE_|\u001b|\u202e/)
    assert.match(text, /<U\+202E>/)
  }
  assert.equal('root' in result, false)
})

test('malformed comparison fields fail closed without echoing their values', () => {
  const changes = [{ schemaVersion: 2 }, { kind: 'share-summary' }, { partial: 'false' }, { filesScanned: -1 },
    { hiddenLikely: '0' }, { baselineSuppressed: null }, { findings: [{}] }, { ruleSelection: {} },
    { exclusions: {} }, { errors: [{}] }, { skipped: [{}] }, { ignoredFindings: [{}] }, { ignored: [42] },
    { baselineExpired: -1 }, { changeView: {} }, { build: { version: '0.7.1', channel: ['release'], revision: null, dirty: null } },
    { findings: [{ ...finding(), severity: ['P1'] }] }, { findings: [{ ...finding(), confidence: ['certain'] }] },
    { findings: [{ ...finding(), line: 0 }] }, { findings: [{ ...finding(), sourceFingerprint: {} }] }]
  for (const change of changes) assert.throws(() => parse(report([finding()], change)), ComparisonError)
  for (const invalid of ['null', '[]', '{PRIVATE_CONTENT', '"PRIVATE_CONTENT"']) {
    assert.throws(() => parseComparisonInput(invalid), error => error instanceof ComparisonError && !error.message.includes('PRIVATE_CONTENT'))
  }
  assert.equal(parseComparisonInput('\ufeff' + JSON.stringify(report())).filesScanned, 1)
})

test('reader rejects missing, oversized and non-regular inputs without revealing paths', () => {
  assert.throws(() => readComparisonInput(join(root, 'PRIVATE_MISSING')), error => error instanceof ComparisonError && !error.message.includes('PRIVATE_MISSING'))
  assert.throws(() => readComparisonInput(root), ComparisonError)
  const huge = join(root, 'huge.json'); writeFileSync(huge, ' '.repeat(MAX_COMPARE_BYTES + 1))
  assert.throws(() => readComparisonInput(huge), ComparisonError)
  assert.throws(() => parseComparisonInput(' '.repeat(MAX_COMPARE_BYTES + 1)), ComparisonError)
  const directory = join(root, 'directory'); mkdirSync(directory)
  const link = join(root, 'linked'); symlinkSync(directory, link, process.platform === 'win32' ? 'junction' : 'dir')
  assert.throws(() => readComparisonInput(link), ComparisonError)
})

test('reader enforces the byte limit even if the input grows after stat', () => {
  const path = join(root, 'growing.json'); writeFileSync(path, JSON.stringify(report()))
  const original = fs.readSync
  let total = 0
  try {
    fs.readSync = ((_fd: number, buffer: Buffer, offset: number, length: number) => {
      buffer.fill(32, offset, offset + length); total += length; return length
    }) as typeof fs.readSync
    syncBuiltinESMExports()
    assert.throws(() => readComparisonInput(path), /10 MiB/)
    assert.equal(total, MAX_COMPARE_BYTES + 1)
  } finally { fs.readSync = original; syncBuiltinESMExports() }
})

test('finding count is bounded independently of input byte size', () => {
  const small = finding({ title: '', file: null, sourceFingerprint: '', excerpt: null, why: [], fix: [] })
  assert.throws(() => parse(report(Array(50_001).fill(small))), /maximum 50000/)
})

test('CLI reads only the explicit reports and preserves all input files', () => {
  writeFileSync(join(root, 'canship.config.json'), '{PRIVATE_INVALID_CONFIG')
  writeFileSync(join(root, 'project.ts'), 'throw new Error("PRIVATE_PROJECT_MUST_NOT_RUN")')
  const flags = inputs()
  const snapshot = () => readdirSync(root, { withFileTypes: true }).filter(e => e.isFile()).map(e => [e.name, digest(readFileSync(join(root, e.name), 'utf8'))])
  const before = snapshot()
  const output = cli(...flags, '--json')
  assert.equal(output.status, 0, output.stderr)
  assert.equal(output.stderr, '')
  assert.equal(JSON.parse(output.stdout).kind, 'report-comparison')
  assert.equal(JSON.parse(output.stdout).scanPerformed, false)
  assert.doesNotMatch(output.stdout, /PRIVATE_/)
  assert.deepEqual(snapshot(), before)
  assert.match(cli(...flags).stdout, /1 persisting/)
})

test('CLI separates limited comparisons, invalid files and incompatible operation modes', () => {
  const flags = inputs(report(), report([], { partial: true }))
  assert.equal(cli(...flags, '--json').status, 2)
  for (const option of ['--report', '--sarif', '--baseline-write', '--fix-prompt', '--share-summary', '--doctor', '--init', '--no-config', '--all', '.']) {
    const result = cli(...flags, option)
    assert.equal(result.status, 3, option)
    assert.equal(result.stdout, '', option)
    assert.match(result.stderr, /\[INVALID_ARGUMENT\]/)
  }
  for (const args of [['--compare='], ['--compare=x'], ['--with=x'], ['--compare=x', '--compare=y', '--with=z']]) assert.equal(cli(...args).status, 3)
  writeFileSync(join(root, 'later.json'), 'PRIVATE_BAD_JSON')
  const invalid = cli(...flags, '--json')
  assert.equal(invalid.status, 3)
  assert.equal(invalid.stdout, '')
  assert.match(invalid.stderr, /\[REPORT_COMPARISON_INVALID\]/)
  assert.doesNotMatch(invalid.stderr, /PRIVATE_|later.json/)
})

test('real CLI reports compare after a finding disappears, without claiming remediation', () => {
  const sample = join(root, 'sample'); mkdirSync(sample)
  const rule = join(sample, 'firestore.rules')
  writeFileSync(rule, 'match /items/{id} { allow write: if true; }')
  const before = cli(sample, '--no-config', '--all', '--json', '--no-excerpts')
  assert.equal(before.status, 1, before.stderr)
  writeFileSync(rule, 'match /items/{id} { allow write: if false; }')
  const after = cli(sample, '--no-config', '--all', '--json', '--no-excerpts')
  assert.equal(after.status, 0, after.stderr)
  const result = compare(JSON.parse(before.stdout), JSON.parse(after.stdout))
  assert.equal(result.counts.notObserved, 1)
  assert.equal(result.counts.added, 0)
  assert.equal(result.limited, true)
  assert.ok(result.warnings.some(w => w.code === 'BUILD_UNVERIFIED'))
  assert.match(renderComparison(result), /not proof of remediation/)
})
