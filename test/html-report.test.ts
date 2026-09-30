/** HTML 报告：离线自包含、仓库内容全部转义、无脚本时内容完整，脚本受哈希约束。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { renderHtml } from '../src/report/html.js'
import type { Finding, ScanResult } from '../src/types.js'

function finding(overrides: Partial<Finding>): Finding {
  return {
    ruleId: 'secrets/hardcoded/openai', severity: 'P0', confidence: 'certain', title: 'A finding',
    file: 'a.ts', line: 1, excerpt: null, why: ['Why it matters.'], fix: ['Fix it.'], ...overrides,
  }
}

function result(findings: Finding[]): ScanResult {
  return {
    findings, filesScanned: 3, durationMs: 5, errors: [], skipped: [], ignored: [], ignoredFindings: [],
    ruleSelection: null, vendored: 0, partial: false,
  } as ScanResult
}

const hostile = '</script><script>alert(1)</script><img src=x onerror=alert(2)>'
const findings = [
  finding({ title: `Title ${hostile}`, file: `src/${hostile}.ts`, excerpt: `const x = "${hostile}"`,
    why: [`Why ${hostile}`, 'Second paragraph.'], fix: [`Fix ${hostile}`], humanOnly: [`Rotate ${hostile}. Then check.`],
    evidence: [{ kind: 'operation', file: `src/${hostile}.ts`, line: 1, description: `Step ${hostile}` }] }),
  finding({ file: 'lib/cors.ts', ruleId: 'cors/reflected-origin-with-credentials', severity: 'P1', line: 4, title: 'CORS reflects origins' }),
]
const html = renderHtml(result(findings), { root: `/p/${hostile}`, generatedAt: '2026-09-30T01:02:03.000Z', version: '9.9.9' })

test('the report loads nothing from outside and restricts scripts with a hash-based policy', () => {
  const policy = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1]
  assert.ok(policy, 'missing Content-Security-Policy')
  assert.match(policy, /default-src 'none'/)
  assert.doesNotMatch(policy, /script-src[^;]*'unsafe-inline'/)
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]!)
  assert.equal(scripts.length, 1, 'exactly one executable inline script')
  const hash = createHash('sha256').update(scripts[0]!, 'utf8').digest('base64')
  assert.ok(policy.includes(`'sha256-${hash}'`), 'the policy hash must match the inline script')
  // 转义后的仓库文本可以包含 src=；先清空属性值（其中不会有未转义引号），再检查真实标签属性。
  const markup = html.replace(/="[^"]*"/g, '=""')
  assert.doesNotMatch(markup, /<link\b|@import|url\(|<[a-z][^>]*\ssrc=/i, 'no external or embedded resource references')
})

test('repository-controlled text is escaped everywhere, including the embedded data block', () => {
  assert.ok(!html.includes('<script>alert'), 'a hostile script tag reached the page')
  assert.ok(!html.includes('<img src=x'), 'a hostile img tag reached the page')
  assert.ok(html.includes('&lt;img src=x onerror=alert(2)&gt;'), 'expected escaping, not stripping')
  const block = /<script type="application\/json" id="canship-data">([\s\S]*?)<\/script>/.exec(html)?.[1]
  assert.ok(block, 'missing data block')
  assert.ok(!block.includes('<'), 'the data block must not contain a raw angle bracket')
  const data = JSON.parse(block)
  assert.ok(String(data.prompts['1']).includes(hostile), 'the prompt data must round-trip exactly')
  assert.equal(html.match(/<\/script>/g)!.length, 2, 'no hostile value closed a script element')
})

test('every finding is fully present without JavaScript', () => {
  assert.equal(html.match(/<details class="f"/g)!.length, findings.length)
  for (const text of ['Why ', 'Second paragraph.', 'Fix ', 'Step ', 'Trace (static relationships)', 'By hand', 'CORS reflects origins']) {
    assert.ok(html.includes(text), `${text} is missing from the static page`)
  }
  assert.ok(html.includes('</p><p>'), 'paragraphs must stay separate')
  assert.match(html, /class="controls"/)
  assert.match(html, /\.controls\{display:none/, 'filter controls stay hidden until the script runs')
})

test('the summary, manual steps and file groups match the terminal layout', () => {
  assert.match(html, /<h1 class="verdict bad"><span class="n">2 blocking findings\.<\/span><br>Do not deploy yet\.<\/h1>/)
  assert.match(html, /<h2>By category<\/h2>/)
  assert.match(html, /<h2>Manual steps<\/h2>/)
  assert.ok(html.indexOf(`src/${hostile.replace(/</g, '&lt;').replace(/>/g, '&gt;')}`) > 0)
  assert.ok(html.indexOf('lib/cors.ts</span> — 1') > html.indexOf('<span class="gk">src/'), 'the most severe file comes first')
  assert.match(html, /canship<\/b> 9\.9\.9/)
  assert.match(html, /2026-09-30 01:02 UTC/)
})

test('a clean scan keeps the scope disclosure and the clean verdict marker', () => {
  const clean = renderHtml(result([]), { root: '/p', generatedAt: '' })
  assert.match(clean, /<h1 class="verdict clean">No exposed credentials found\.<\/h1>/)
  assert.match(clean, /not that your app is secure/)
  assert.doesNotMatch(clean, /<details class="f"/)
})
