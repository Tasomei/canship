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
  test(`a same-line reflection is still detected: ${content.slice(0, 65)}`, () => {
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
  test(`a controlled or unknown origin is not reported as a direct reflection: ${expression}`, () => {
    assert.deepEqual(check(`const headers = { 'Access-Control-Allow-Origin': ${expression}, 'Access-Control-Allow-Credentials': 'true' };`), [])
  })
}
test('a same-line wildcard stays P2', () => {
  const findings = check("const headers = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' };")
  assert.equal(findings[0]?.ruleId, 'cors/wildcard-with-credentials')
  assert.equal(findings[0]?.severity, 'P2')
})

test('repeated header names in a long expression do not rescan the rest of the text', () => {
  const content = "'Access-Control-Allow-Credentials': 'true';" + "'Access-Control-Allow-Origin': (".repeat(20_000)
  const started = performance.now()
  assert.deepEqual(check(content), [])
  assert.ok(performance.now() - started < 5000)
})

test('a long run of whitespace after an origin callback is scanned in linear time', () => {
  // 修复前回调识别与结尾标点去除各自二次回溯，150KB 空白使一次扫描耗时约 83 秒。
  const content = 'app.use(cors({ credentials: true, origin: function' + ' '.repeat(150_000) + 'x }))'
  const started = performance.now()
  check(content)
  const took = performance.now() - started
  assert.ok(took < 5000, `took ${Math.round(took)}ms`)
})

for (const fixed of ["'https://app.example.com'", 'false', 'ALLOWED', '[\'https://app.example.com\']']) {
  test(`a wildcard in another object is not paired with this config's credentials: ${fixed}`, () => {
    assert.deepEqual(check(`const privateOptions = { origin: ${fixed}, credentials: true }; const publicOptions = { origin: '*' }; app.use(cors(privateOptions));`), [])
  })
}
test('separate configs on one line do not hide a real reflection', () => {
  const findings = check("app.use(cors({origin: true, credentials: true})); app.use(cors({origin: 'https://app.example.com'}));")
  assert.equal(findings.length, 1)
  assert.equal(findings[0]?.ruleId, 'cors/reflected-origin-with-credentials')
})
test('an object-method callback still pairs with credentials in the same object', () => {
  const findings = check("app.use(cors({origin(value, cb) { cb(null, true) }, credentials: true}));")
  assert.equal(findings[0]?.ruleId, 'cors/reflected-origin-with-credentials')
})
test('a controlled callback does not borrow a wildcard from another object', () => {
  assert.deepEqual(check("app.use(cors({origin(value, cb) { if (ALLOWED.includes(value)) cb(null, true) }, credentials: true})); const publicOptions = {origin:'*'};"), [])
})

test('strings in a source generator are not a live CORS config', () => {
  assert.deepEqual(check(`const source = "app.use(cors({origin:true,credentials:true}));";`), [])
  assert.deepEqual(check(`const source = "app.use(cors({origin(value, cb){cb(null,true)},credentials:true}));";`), [])
  assert.deepEqual(check(`const source = "{'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true'}";`), [])
})
test('an example string cannot supply credentials to real code', () => {
  assert.deepEqual(check(`app.use(cors({origin:true})); const documentation = 'credentials:true';`), [])
})
test('a real reflection is still detected in a file that also has string examples', () => {
  const findings = check(`const source = "app.use(cors({origin:'https://app.example.com',credentials:true}));";\napp.use(cors({origin:true,credentials:true}));`)
  assert.equal(findings.length, 1)
  assert.equal(findings[0]?.line, 2)
})
