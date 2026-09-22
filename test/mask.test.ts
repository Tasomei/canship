// canship-ignore-file
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { maskJsComments, maskJsNoise } from '../src/mask.js'
import { corsRule } from '../src/rules/cors.js'

const tick = String.fromCharCode(96)
const interpolation = '${'
const cors = 'const options = { origin: true, credentials: true };'

for (const comment of ["/* 注释中的引号 ' 和括号 } */", "// 注释中的引号 ' 和括号 }\n"]) {
  test('插值注释不影响模板后的注释与真实代码', () => {
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

test('嵌套模板保留 URL、转义及插值中的代码', () => {
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

test('两种掩码均支持深层嵌套且保留模板后的代码', () => {
  const depth = 10_000
  const source = (tick + interpolation).repeat(depth) + 'user.id' + ('}' + tick).repeat(depth) + '\n' + cors
  for (const mask of [maskJsComments, maskJsNoise]) {
    const result = mask(source)
    assert.equal(result.length, source.length)
    assert.ok(result.includes('user.id'))
    assert.ok(result.endsWith(cors))
  }
})

test('未闭合的模板及注释有界结束并保留行号', () => {
  for (const source of [tick + 'abc\n', tick + interpolation + '/* 注释', tick + interpolation + '// 注释\n']) {
    for (const mask of [maskJsComments, maskJsNoise]) {
      const result = mask(source)
      assert.equal(result.length, source.length)
      assert.equal(result.split('\n').length, source.split('\n').length)
    }
  }
})
