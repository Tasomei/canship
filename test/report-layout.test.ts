/** 报告的归类、分组、人工步骤汇总与终端布局：汇总不能丢失结果，紧凑输出不能超出宽度。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { categoryCounts, categoryOf, groupByFile, manualSteps } from '../src/report/shared.js'
import { renderReport } from '../src/report/terminal.js'
import type { Finding, ScanResult } from '../src/types.js'

function finding(overrides: Partial<Finding>): Finding {
  return {
    ruleId: 'secrets/hardcoded/openai', severity: 'P0', confidence: 'certain', title: 'A finding',
    file: 'a.ts', line: 1, excerpt: null, why: ['Why it matters.'], fix: ['Fix it.'], ...overrides,
  }
}

function result(findings: Finding[], overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    findings, filesScanned: 3, durationMs: 5, errors: [], skipped: [], ignored: [], ignoredFindings: [],
    ruleSelection: null, vendored: 0, partial: false, ...overrides,
  } as ScanResult
}

// 去除颜色控制序列后按可见字符计算宽度。
const visible = (s: string): string => s.replace(new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g'), '')

test('rule namespaces map to report categories, with unknown namespaces kept visible', () => {
  assert.equal(categoryOf('secrets/hardcoded/openai'), 'Credentials')
  assert.equal(categoryOf('exposure/secret-in-public-env'), 'Credentials')
  assert.equal(categoryOf('gitleak/env-in-history'), 'Credentials')
  assert.equal(categoryOf('api/db-write-without-auth'), 'API access')
  assert.equal(categoryOf('supabase/rls-not-enabled'), 'Database rules')
  assert.equal(categoryOf('firebase/open-rules'), 'Database rules')
  assert.equal(categoryOf('cors/wildcard-with-credentials'), 'CORS')
  assert.equal(categoryOf('injection/sql'), 'Other')
  const rows = categoryCounts([finding({}), finding({ ruleId: 'injection/sql', severity: 'P2' })])
  assert.deepEqual(rows.map(row => [row.category, row.total]), [['Credentials', 1], ['Other', 1]])
  assert.equal(rows.reduce((sum, row) => sum + row.total, 0), 2, 'every finding is counted once')
})

test('file groups put the most severe file first, then larger groups, and sort lines within a file', () => {
  const groups = groupByFile([
    finding({ file: 'b.ts', severity: 'P1', line: 3 }),
    finding({ file: 'c.ts', severity: 'P0', line: 9 }),
    finding({ file: 'a.ts', severity: 'P1', line: 7 }),
    finding({ file: 'a.ts', severity: 'P1', line: 2 }),
    finding({ file: null, severity: 'P2', line: null }),
  ])
  assert.deepEqual(groups.map(g => g.file), ['c.ts', 'a.ts', 'b.ts', null])
  assert.deepEqual(groups[1]!.findings.map(f => f.line), [2, 7])
  assert.equal(groups.reduce((n, g) => n + g.findings.length, 0), 5, 'grouping must not drop findings')
})

test('manual steps merge identical first sentences and keep every source location', () => {
  const steps = manualSteps([
    finding({ file: 'p1.ts', severity: 'P1', humanOnly: ['Check the dashboard. It may differ.'] }),
    finding({ file: 'a.env', line: 3, humanOnly: ['Rotate this GitHub token at https://github.com/settings/tokens — the current one is public.'] }),
    finding({ file: 'b.ts', line: 5, humanOnly: ['Rotate this GitHub token at https://github.com/settings/tokens. Treat the old one as compromised.'] }),
    finding({ file: 'b.ts', line: 5, humanOnly: ['Rotate this GitHub token at https://github.com/settings/tokens. Again.'] }),
  ])
  assert.deepEqual(steps.map(s => [s.severity, s.text, s.locations]), [
    ['P0', 'Rotate this GitHub token at https://github.com/settings/tokens', ['a.env:3', 'b.ts:5']],
    ['P1', 'Check the dashboard', ['p1.ts:1']],
  ])
})

const findings = [
  finding({ file: '.env.local', line: 8, title: 'Admin key exposed', excerpt: 'SECRET_EXCERPT_LINE', why: ['WHY_PARAGRAPH'],
    fix: ['FIX_STEP'], humanOnly: ['Rotate the admin key. It is public.'] }),
  finding({ file: 'lib/cors.ts', ruleId: 'cors/reflected-origin-with-credentials', severity: 'P1', line: 4, title: 'CORS reflects origins' }),
  finding({ file: 'next.config.js', ruleId: 'cors/wildcard-with-credentials', severity: 'P2', line: 8, title: 'Wildcard origin' }),
]

test('the default terminal report summarises and lists titles without details', () => {
  const out = visible(renderReport(result(findings), { root: '/p', showingLikely: false, hiddenLikely: 2, exitCode: 1, width: 96 }))
  assert.match(out, /2 blocking findings\. Do not deploy yet\./)
  assert.match(out.replace(/\s+/g, ' '), /1 exposed credential must also be rotated in its provider/)
  assert.match(out, /By category/)
  assert.match(out, /Manual steps\n {2}1 {2}Rotate the admin key\n {5}\.env\.local:8/)
  assert.ok(out.indexOf('.env.local — 1') < out.indexOf('lib/cors.ts — 1'))
  assert.ok(out.indexOf('lib/cors.ts — 1') < out.indexOf('next.config.js — 1'))
  assert.match(out, /2 lower-confidence findings hidden/)
  assert.match(out, /exit 1 · blocking findings present/)
  for (const detail of ['SECRET_EXCERPT_LINE', 'WHY_PARAGRAPH', 'FIX_STEP']) assert.ok(!out.includes(detail), `${detail} leaked into the default view`)
})

test('--verbose expands the excerpt, explanation, fix steps and manual actions', () => {
  const out = visible(renderReport(result(findings), { root: '/p', showingLikely: true, hiddenLikely: 0, verbose: true, width: 96 }))
  for (const detail of ['SECRET_EXCERPT_LINE', 'WHY_PARAGRAPH', '1. FIX_STEP', 'Rotate the admin key. It is public.']) assert.ok(out.includes(detail), `${detail} is missing`)
  assert.ok(!out.includes('canship --verbose'), 'the verbose view should not suggest itself')
})

test('long titles and paths wrap within narrow terminals instead of overflowing', () => {
  const long = finding({ title: 'word '.repeat(40).trim(), humanOnly: [`Rotate ${'token '.repeat(30)}now`] })
  for (const width of [60, 80]) {
    const out = visible(renderReport(result([long]), { root: '/p', showingLikely: true, hiddenLikely: 0, width }))
    const overflow = out.split('\n').filter(line => line.length > width)
    assert.deepEqual(overflow, [], `lines exceed ${width} columns`)
    assert.equal((out.match(/word/g) ?? []).length, 40, 'wrapping must not drop words')
  }
})

test('whole-file findings show "file" in the line column instead of a blank', () => {
  const out = visible(renderReport(result([finding({ file: '.env.local', line: null, title: 'Committed env file' })]),
    { root: '/p', showingLikely: true, hiddenLikely: 0 }))
  assert.match(out, /^ {2}P0 {2}file {2}Committed env file$/m)
})

test('the verdict tracks the most severe certain finding', () => {
  const minor = visible(renderReport(result([finding({ severity: 'P2' })]), { root: '/p', showingLikely: false, hiddenLikely: 0 }))
  assert.match(minor, /1 finding to fix\. Nothing blocking\./)
  assert.doesNotMatch(minor, /Do not deploy/)
  const likely = visible(renderReport(result([finding({ confidence: 'likely' })]), { root: '/p', showingLikely: true, hiddenLikely: 0 }))
  assert.match(likely, /1 finding to review\./)
  assert.doesNotMatch(likely, /Do not deploy/)
})
