// canship-ignore-file
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { maskJsComments, maskJsNoise } from '../src/mask.js'
import { corsRule } from '../src/rules/cors.js'
import { apiAuthRule } from '../src/rules/apiauth.js'

const tick = String.fromCharCode(96)
const interpolation = '${'
const cors = 'const options = { origin: true, credentials: true };'

for (const comment of ["/* 注释中的引号 ' 和括号 } */", "// 注释中的引号 ' 和括号 }\n"]) {
  test('comments inside interpolations do not affect comments or code after the template', () => {
    const prefix = `const value = ${tick}text ${interpolation}${comment} 1}${tick};\n`
    const source = prefix + '// ' + cors + '\n' + cors
    const masked = maskJsComments(source)
    assert.equal(masked.length, source.length)
    assert.equal(masked.split('\n').length, source.split('\n').length)
    assert.equal(masked.includes(comment.trim()), false)
    assert.equal(masked.indexOf(cors), source.lastIndexOf(cors))
    const findings = corsRule.check({
      path: 'cors.ts', content: source, lines: source.split('\n'), isExampleContext: false,
    }, { root: '.', files: [], git: 'not-a-repo', gitExecutable: null, reportIncomplete() {} })
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.line, source.split('\n').length)
  })
}

test('nested templates keep URLs, escapes and code inside interpolations', () => {
  const source = `const value = ${tick}outer ${interpolation}${tick}https://example.invalid/${interpolation}user.id}${tick}} tail${tick};\n// 已停用\n`
  const comments = maskJsComments(source)
  assert.ok(comments.includes('https://example.invalid/'))
  assert.ok(comments.includes('user.id'))
  assert.equal(comments.includes('已停用'), false)
  const noise = maskJsNoise(source)
  assert.equal(noise.length, source.length)
  assert.ok(noise.includes('user.id'))
  assert.equal(noise.includes('https://'), false)
  assert.equal(noise.includes('outer'), false)
  assert.equal(noise.includes('tail'), false)
  const escaped = tick + 'a\\' + tick + 'b\\${literal}' + tick
  assert.equal(maskJsComments(escaped), escaped)
  assert.equal(maskJsNoise(escaped), tick + ' '.repeat(escaped.length - 2) + tick)
})

test('both maskers handle deep nesting and keep code after the template', () => {
  const depth = 10_000
  const source = (tick + interpolation).repeat(depth) + 'user.id' + ('}' + tick).repeat(depth) + '\n' + cors
  for (const mask of [maskJsComments, maskJsNoise]) {
    const result = mask(source)
    assert.equal(result.length, source.length)
    assert.ok(result.includes('user.id'))
    assert.ok(result.endsWith(cors))
  }
})

test('unterminated templates and comments end within bounds and keep line numbers', () => {
  for (const source of [tick + 'abc\n', tick + interpolation + '/* 注释', tick + interpolation + '// 注释\n']) {
    for (const mask of [maskJsComments, maskJsNoise]) {
      const result = mask(source)
      assert.equal(result.length, source.length)
      assert.equal(result.split('\n').length, source.split('\n').length)
    }
  }
})

for (const prefix of [
  'const pattern = /"/;',
  "const pattern = /'/;",
  'const pattern = /[\\/"\']/g;',
  'const pattern = /https?:\\/\\//i;',
  'if (enabled) /"/.test(value);',
  'while (enabled) /"/.test(value);',
  'const pattern = (() => /"/)();',
  'const pattern = call(/"/);',
  'const pattern = { test: /"/ };',
  `const rendered = ${tick}value ${interpolation}/["']/g.test(value)}${tick};`,
  'const ratio = numerator / denominator / other;',
  'const ratio = (numerator + 1) / denominator;',
  'const ratio = object.return / denominator / other;',
  'const ratio = object.if(value) / denominator;',
]) {
  test(`regular expressions and division do not hide subsequent route operations: ${prefix}`, async () => {
    const content = "import { admin } from '../../../lib/admin';\n" + prefix + '\n' +
      'export async function GET() { return Response.json(await admin.from("records").select("*")); }'
    const admin = "import { createClient } from '@supabase/supabase-js'; export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);"
    const files = [{ path: 'app/api/records/route.ts', content }, { path: 'lib/admin.ts', content: admin }]
      .map(file => ({ ...file, lines: file.content.split('\n'), isExampleContext: false }))
    const findings = await apiAuthRule.check({ root: '.', files, git: 'not-a-repo', gitExecutable: null,
      reportIncomplete() { assert.fail('unexpected incomplete scan') } })
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.ruleId, 'api/admin-db-access-without-auth')
    assert.equal(findings[0]!.line, 3)
  })
}

test('regex contents do not become auth or CORS code, and real comments remain masked', () => {
  const source = 'const pattern = /requireAuth\\(\\)["\']/; // COMMENT_SENTINEL\n' + cors
  const comments = maskJsComments(source)
  const noise = maskJsNoise(source)
  assert.equal(comments.length, source.length)
  assert.equal(noise.length, source.length)
  assert.ok(comments.includes('requireAuth'))
  assert.ok(!comments.includes('COMMENT_SENTINEL'))
  assert.ok(!noise.includes('requireAuth'))
  assert.ok(noise.endsWith(cors))
})

test('unterminated regex character classes do not cause repeated suffix scans', () => {
  const source = 'const pattern = /[' + '/['.repeat(100_000)
  const started = performance.now()
  assert.equal(maskJsNoise(source).length, source.length)
  assert.ok(performance.now() - started < 5000)
})
