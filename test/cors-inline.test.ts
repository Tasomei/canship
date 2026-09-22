/** 验证同行 CORS 值边界，保留条件判断与未知表达式。
 * canship-ignore-file */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { corsRule } from '../src/rules/cors.js'

function check(content: string) {
  return corsRule.check({ path: 'server.ts', content, lines: content.split('\n'), isExampleContext: false }, {
    root: '', files: [], git: 'not-a-repo', gitExecutable: null, reportIncomplete: () => {},
  })
}

for (const content of [
  "const headers = { 'Access-Control-Allow-Origin': req.headers.get('origin'), 'Access-Control-Allow-Credentials': 'true' };",
  "const headers = { 'Access-Control-Allow-Credentials': 'true', 'Access-Control-Allow-Origin': req.headers.get('origin') };",
  "headers.set('Access-Control-Allow-Origin', request.headers.get('origin')); headers.set('Access-Control-Allow-Credentials', 'true');",
  "const headers = [{ key: 'Access-Control-Allow-Origin', value: req.headers.origin }, { key: 'Access-Control-Allow-Credentials', value: 'true' }];",
  "const headers = { 'Access-Control-Allow-Origin': `${origin}`, 'Access-Control-Allow-Credentials': 'true' };",
  "const headers = { 'Access-Control-Allow-Origin': request.headers.get('origin') || 'https://app.example.com', 'Access-Control-Allow-Credentials': 'true' };",
]) {
  test(`同行回显仍应检出：${content.slice(0, 65)}`, () => {
    const findings = check(content)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]?.ruleId, 'cors/reflected-origin-with-credentials')
    assert.equal(findings[0]?.confidence, 'certain')
    assert.equal(findings[0]?.line, 1)
  })
}
for (const expression of [
  "'https://app.example.com'",
  "ALLOWED.includes(origin) ? origin : 'https://app.example.com'",
  "origin === 'https://app.example.com' ? origin : ''",
  "resolveOrigin(origin, 'https://app.example.com')",
  "lookup['a,b']",
  "(unknown, origin)",
]) {
  test(`不将受控或未知来源误报为直接回显：${expression}`, () => {
    assert.deepEqual(check(`const headers = { 'Access-Control-Allow-Origin': ${expression}, 'Access-Control-Allow-Credentials': 'true' };`), [])
  })
}
test('同行通配符保持 P2 分类', () => {
  const findings = check("const headers = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' };")
  assert.equal(findings[0]?.ruleId, 'cors/wildcard-with-credentials')
  assert.equal(findings[0]?.severity, 'P2')
})

test('长表达式中的重复响应头字样不会反复遍历剩余全文', () => {
  const content = "'Access-Control-Allow-Credentials': 'true';" + "'Access-Control-Allow-Origin': (".repeat(20_000)
  const started = performance.now()
  assert.deepEqual(check(content), [])
  assert.ok(performance.now() - started < 5000)
})

for (const fixed of ["'https://app.example.com'", 'false', 'ALLOWED', '[\'https://app.example.com\']']) {
  test(`其他对象的通配符不能与当前配置的凭据配对：${fixed}`, () => {
    assert.deepEqual(check(`const privateOptions = { origin: ${fixed}, credentials: true }; const publicOptions = { origin: '*' }; app.use(cors(privateOptions));`), [])
  })
}
test('同一行的独立配置不会互相隐藏真实回显', () => {
  const findings = check("app.use(cors({origin: true, credentials: true})); app.use(cors({origin: 'https://app.example.com'}));")
  assert.equal(findings.length, 1)
  assert.equal(findings[0]?.ruleId, 'cors/reflected-origin-with-credentials')
})
test('对象方法回调与同一对象的凭据仍可配对', () => {
  const findings = check("app.use(cors({origin(value, cb) { cb(null, true) }, credentials: true}));")
  assert.equal(findings[0]?.ruleId, 'cors/reflected-origin-with-credentials')
})
test('受控回调不借用其他对象中的通配符', () => {
  assert.deepEqual(check("app.use(cors({origin(value, cb) { if (ALLOWED.includes(value)) cb(null, true) }, credentials: true})); const publicOptions = {origin:'*'};"), [])
})

test('源码生成器中的字符串不是生效的 CORS 配置', () => {
  assert.deepEqual(check(`const source = "app.use(cors({origin:true,credentials:true}));";`), [])
  assert.deepEqual(check(`const source = "app.use(cors({origin(value, cb){cb(null,true)},credentials:true}));";`), [])
  assert.deepEqual(check(`const source = "{'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true'}";`), [])
})
test('示例字符串不能为真实代码提供凭据设置', () => {
  assert.deepEqual(check(`app.use(cors({origin:true})); const documentation = 'credentials:true';`), [])
})
test('同文件包含字符串示例时，真实回显仍会检出', () => {
  const findings = check(`const source = "app.use(cors({origin:'https://app.example.com',credentials:true}));";\napp.use(cors({origin:true,credentials:true}));`)
  assert.equal(findings.length, 1)
  assert.equal(findings[0]?.line, 2)
})
