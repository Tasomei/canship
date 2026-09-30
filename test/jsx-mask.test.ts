/** JSX 文本、属性和结束标签不能让后续代码错位；TSX 泛型不能被当作元素。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { maskJsComments, maskJsNoise } from '../src/mask.js'
import { apiAuthRule } from '../src/rules/apiauth.js'

const jsx = { jsx: true }
const tail = '\nconst quoted = "SECRET_TEXT"; export const marker = 1;\n'

/** 尾部代码必须保留，其中的字符串必须被屏蔽。 */
function assertTailIntact(masked: string, source: string): void {
  assert.equal(masked.length, source.length)
  assert.equal(masked.split('\n').length, source.split('\n').length)
  assert.ok(masked.includes('export const marker = 1;'), masked)
  assert.ok(!masked.includes('SECRET_TEXT'), masked)
}

for (const element of [
  "const a = <p>Don't stop</p>;",
  'const a = <nav><a href="/a">A</a> | <a href="/b">B</a></nav>;',
  'const a = <><Item label="it\'s" /><b>{value}</b></>;',
  'const a = <Button icon=<Icon /> title="x">Go</Button>;',
  "const a = cond ? <p>isn't</p> : <span>won't</span>;",
  'const a = <div /* note */ data-x="1">{/* "q */}text</div>;',
  "function A() { return (\n  <ul>\n    <li>Don't</li>\n  </ul>\n) }",
]) {
  test(`JSX text and attributes do not desynchronize later code: ${element.slice(0, 40)}`, () => {
    const source = element + tail
    assertTailIntact(maskJsNoise(source, jsx), source)
  })
}

test('JSX expression containers remain code; text and attribute strings are masked', () => {
  const source = '<p title="ATTR_TEXT">BODY_TEXT {requireAuth()}</p>'
  const masked = maskJsNoise(source, jsx)
  assert.ok(masked.includes('requireAuth()'))
  assert.ok(!masked.includes('ATTR_TEXT'))
  assert.ok(!masked.includes('BODY_TEXT'))
  // 仅屏蔽注释的模式保留 JSX 文本和属性字符串。
  const comments = maskJsComments(source, jsx)
  assert.ok(comments.includes('ATTR_TEXT') && comments.includes('BODY_TEXT'))
})

for (const generic of [
  'const identity = <T,>(value: T) => value;',
  'const identity = <T extends object>(value: T) => value;',
  'const identity = <T = string>(value: T) => value;',
  'type Fn = <T>(value: T) => T;',
  'const size = count < limit ? count : limit;',
]) {
  test(`TSX generics and comparisons are not treated as JSX: ${generic}`, () => {
    const source = generic + tail
    assertTailIntact(maskJsNoise(source, jsx), source)
  })
}

test('HTML closing tags outside JSX files are not read as regular expressions', () => {
  const source = '<a href="/a">A</a> | <a href="/b">B</a>' + tail
  assertTailIntact(maskJsNoise(source), source)
})

test('a regex after a less-than comparison does not hide the following handler', async () => {
  for (const prefix of ['const check = 0 < /"/.source.length;', 'const check = 0</a>"/.source.length;']) {
    for (const path of ['app/api/items/route.ts', 'app/api/items/route.js', 'app/api/items/route.tsx']) {
      const content = prefix + '\n' + admin +
        '\nexport async function POST() { await admin.from("records").delete(); }'
      assert.ok(maskJsNoise(content).includes('export async function POST'))
      const file = { path, content, lines: content.split('\n'), isExampleContext: false }
      const hits = await apiAuthRule.check({ root: '.', files: [file], git: 'not-a-repo', gitExecutable: null,
        reportIncomplete() { assert.fail('unexpected incomplete scan') } })
      assert.equal(hits[0]?.ruleId, 'api/admin-db-access-without-auth')
    }
  }
})

test('deep or unterminated JSX stays linear and does not exhaust the stack', () => {
  for (const source of ['const a = ' + '<a>'.repeat(100_000), 'const a = ' + '<p>{'.repeat(100_000)]) {
    const started = performance.now()
    assert.equal(maskJsNoise(source, jsx).length, source.length)
    assert.ok(performance.now() - started < 5000)
  }
})

const admin = "import { createClient } from '@supabase/supabase-js'; export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);"
for (const markup of [
  '<nav><a href="/a">A</a> | <a href="/b">B</a></nav>',
  "<p>Don't forget: it's permanent.</p>",
]) {
  test(`JSX before an inline Server Action does not hide its admin operation: ${markup}`, async () => {
    const page = "import { admin } from '../lib/admin';\n" +
      `export default function Page() {\n  return ${markup}\n}\n` +
      "export async function remove() {\n  'use server'\n  await admin.from('records').delete().eq('id', 1)\n}\n"
    const files = [{ path: 'app/page.tsx', content: page }, { path: 'lib/admin.ts', content: admin }]
      .map(file => ({ ...file, lines: file.content.split('\n'), isExampleContext: false }))
    const findings = await apiAuthRule.check({ root: '.', files, git: 'not-a-repo', gitExecutable: null,
      reportIncomplete() { assert.fail('unexpected incomplete scan') } })
    assert.deepEqual(findings.map(f => [f.ruleId, f.line]), [['api/admin-db-access-without-auth', 7]])
  })
}
