/** 示例展示不改变发现身份；可静态验证的关键前后例必须符合规则。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { scan, listRules } from '../src/index.js'
import { fixExampleFor } from '../src/rules/examples.js'
import { renderRuleCatalog } from '../src/rules/catalog.js'
import { renderHtml } from '../src/report/html.js'
import { renderReport } from '../src/report/terminal.js'
import { fingerprintOf } from '../src/baseline.js'
import type { Finding, ScanResult } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
function sample(path: string, content: string): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-fix-example-')); roots.push(root)
  mkdirSync(dirname(join(root, path)), { recursive: true }); writeFileSync(join(root, path), content)
  return root
}
test('reported credential formats and high-frequency checks have explicit examples and limitations', () => {
  const catalog = listRules()
  const examples = catalog.filter(rule => rule.example)
  assert.ok(examples.length >= 20)
  for (const item of examples) for (const text of Object.values(item.example!)) assert.ok(text.length > 0)
  for (const item of catalog.filter(rule => !rule.reportsFindings)) assert.equal(item.example, undefined)
  assert.equal(fixExampleFor('constructor'), null)
  assert.equal(fixExampleFor('__proto__'), null)
  assert.equal(fixExampleFor('secrets/hardcoded/unknown'), null)
})
test('API and helper callers cannot change later examples or report instructions', () => {
  const rules = listRules(), item = rules.find(rule => rule.id === 'injection/sql')!
  item.example!.after = 'PRIVATE_MUTATION'
  fixExampleFor('injection/sql')!.after = 'ANOTHER_MUTATION'
  assert.match(listRules().find(rule => rule.id === 'injection/sql')!.example!.after, /\$1/)
  assert.doesNotMatch(renderRuleCatalog(), /MUTATION/)
})
test('catalog and verbose reports show examples without changing findings or stable identities', () => {
  const finding: Finding = { ruleId: 'exposure/secret-in-public-env', severity: 'P0', confidence: 'certain', title: 'Sample finding',
    file: '.env', line: 1, excerpt: null, sourceFingerprint: 'synthetic-source', why: ['Example only'], fix: ['Use a server-only value'] }
  const result: ScanResult = { findings: [finding], filesScanned: 1, durationMs: 1, errors: [], skipped: [], ignored: [], ignoredFindings: [], ruleSelection: null, vendored: 0, partial: false }
  const original = JSON.stringify(result), fingerprint = fingerprintOf(finding)
  const options = { root: 'sample', showingLikely: true, hiddenLikely: 0 }
  assert.doesNotMatch(renderReport(result, options), /Illustrative example/)
  const terminal = renderReport(result, { ...options, verbose: true })
  assert.match(terminal, /Illustrative example/)
  assert.match(terminal, /Before:/)
  assert.match(terminal, /After:/)
  assert.match(terminal, /renaming does not revoke/)
  const html = renderHtml(result, { root: 'sample', generatedAt: '' })
  assert.match(html, /&lt;private value&gt;/)
  assert.doesNotMatch(html, /<private value>/)
  assert.match(html, /Adaptation required:/)
  assert.equal(JSON.stringify(result), original)
  assert.equal(fingerprintOf(finding), fingerprint)
})
test('CORS and Firestore examples remove the illustrated finding, not merely its output', async () => {
  for (const [id, path] of [['cors/reflected-origin-with-credentials', 'server.ts'], ['cors/wildcard-with-credentials', 'server.ts'],
    ['firebase/open-rules', 'firestore.rules'], ['firebase/test-mode-rules', 'firestore.rules']] as const) {
    const example = fixExampleFor(id)!
    assert.ok((await scan(sample(path, example.before))).findings.some(f => f.ruleId === id), id)
    assert.ok(!(await scan(sample(path, example.after))).findings.some(f => f.ruleId === id), id)
  }
})
test('RLS and parameterized PostgreSQL examples exercise the before and after paths', async () => {
  const rls = fixExampleFor('supabase/rls-not-enabled')!
  assert.ok((await scan(sample('supabase/migrations/001.sql', rls.before))).findings.some(f => f.ruleId === 'supabase/rls-not-enabled'))
  assert.ok(!(await scan(sample('supabase/migrations/001.sql', rls.before + '\n' + rls.after))).findings.some(f => f.ruleId === 'supabase/rls-not-enabled'))
  const sql = fixExampleFor('injection/sql')!
  const route = (body: string) => `export async function GET(req){const id=new URL(req.url).searchParams.get('id');${body}return new Response('ok');}`
  assert.ok((await scan(sample('app/api/items/route.ts', route(sql.before)))).findings.some(f => f.ruleId === 'injection/sql'))
  assert.ok(!(await scan(sample('app/api/items/route.ts', route(sql.after)))).findings.some(f => f.ruleId === 'injection/sql'))
})
