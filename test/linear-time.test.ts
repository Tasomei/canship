/** 验证 Firebase 与 CORS 规则在被扫描项目构造的输入上保持线性耗时，且改写不改变识别结果。
 * canship-ignore-file */
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { firebaseRulesRule } from '../src/rules/firebase.js'
import { corsRule } from '../src/rules/cors.js'
import type { Finding, Rule, ScanContext } from '../src/types.js'

const ctx: ScanContext = { root: '', files: [], git: 'not-a-repo', gitExecutable: null, reportIncomplete: () => {} }

function run(rule: Rule, path: string, content: string): Finding[] {
  return rule.check({ path, content, lines: content.split('\n'), isExampleContext: false }, ctx)
}

/** 返回结果与耗时；上限远高于线性实现的实测值，只捕捉二次或更高阶的回退。 */
function timed(rule: Rule, path: string, content: string): { findings: Finding[]; ms: number } {
  const started = performance.now()
  const findings = run(rule, path, content)
  return { findings, ms: performance.now() - started }
}

const rules = (body: string): Finding[] => run(firebaseRulesRule, 'firestore.rules', `service cloud.firestore {\n${body}\n}`)

describe('Firebase rules keep their meaning', () => {
  test('a public read beside a write denial in the same block is not reported', () => {
    assert.deepEqual(rules('match /a/{id} { allow read: if true; allow write: if false; }'), [])
  })

  test('a write denial in a child block does not make the parent read-only', () => {
    const findings = rules('match /a/{id} { allow read: if true; match /b/{x} { allow write: if false; } }')
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, 'likely')
  })

  test('a write denial in the parent block does not cover a child block', () => {
    const findings = rules('match /a/{id} { allow write: if false; match /b/{x} { allow read: if true; } }')
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.line, 2)
  })

  // 旧实现按语句前最后一个 match 关键字定位所属块，子块闭合后的语句会被归入子块。
  test('a statement after a closed child block belongs to the parent, not the child', () => {
    assert.equal(rules('match /a/{id} { match /b/{x} { allow write: if false; } allow read: if true; }').length, 1)
    assert.deepEqual(rules('match /a/{id} { allow write: if false; match /b/{x} { } allow read: if true; }'), [])
  })

  test('a denial in a sibling block does not cover this one', () => {
    assert.equal(rules('match /a/{id} { allow write: if false; }\nmatch /b/{id} { allow read: if true; }').length, 1)
  })

  test('operation lists with spaces and line breaks are still read', () => {
    const findings = rules('match /a/{id} {\n  allow get ,\n    list , create : if true ;\n}')
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, 'certain')
    assert.match(findings[0]!.title, /get and list and create/)
  })

  test('a recursive wildcard does not break block pairing', () => {
    assert.deepEqual(rules('match /a/{doc=**} { allow read: if true; allow update: if false; }'), [])
  })

  test('test-mode rules are still dated', () => {
    const findings = rules('match /{d=**} { allow read, write: if request.time < timestamp.date(2031, 2, 3); }')
    assert.equal(findings[0]?.ruleId, 'firebase/test-mode-rules')
    assert.match(findings[0]!.title, /2031-02-03/)
  })
})

describe('Firebase rules are scanned in linear time', () => {
  // 修复前操作列表的正则为立方级：allow 后接 1 万个空格约需 106 秒。
  test('a long run of whitespace after allow', () => {
    const { ms } = timed(firebaseRulesRule, 'firestore.rules', 'match /a { allow ' + ' '.repeat(1_000_000) + 'x }')
    assert.ok(ms < 5000, `took ${Math.round(ms)}ms`)
  })

  // 修复前每条只读语句都回扫文件并逐字符重试正则：168KB 约需 77 秒。
  test('many public reads in a block that denies writes', () => {
    const content = 'match /a { allow write: if false;' + ' allow read: if true;'.repeat(60_000) + ' }'
    const { findings, ms } = timed(firebaseRulesRule, 'firestore.rules', content)
    assert.deepEqual(findings, [])
    assert.ok(ms < 5000, `took ${Math.round(ms)}ms`)
  })

  test('a long run of whitespace inside a match block', () => {
    const content = 'match /a {' + ' '.repeat(1_000_000) + 'allow read: if true; allow write: if false; }'
    const { findings, ms } = timed(firebaseRulesRule, 'firestore.rules', content)
    assert.deepEqual(findings, [])
    assert.ok(ms < 5000, `took ${Math.round(ms)}ms`)
  })

  test('allow repeated as its own operation name', () => {
    const { ms } = timed(firebaseRulesRule, 'firestore.rules', 'match /a {' + ' allow allow,'.repeat(100_000) + ' }')
    assert.ok(ms < 5000, `took ${Math.round(ms)}ms`)
  })
})

describe('CORS pairing is linear in the number of configurations', () => {
  // 修复前每个凭据配置都遍历全部来源声明：1.17MB 约需 10 秒。
  test('many option objects', () => {
    const content = 'app.use(cors({}))\n' + 'const o = {origin:"https://a.example.com",credentials:true}\n'.repeat(34_000)
    const { findings, ms } = timed(corsRule, 'server.ts', content)
    assert.deepEqual(findings, [])
    assert.ok(ms < 5000, `took ${Math.round(ms)}ms`)
  })

  test('many header pairs on one line', () => {
    const pair = "h.set('Access-Control-Allow-Origin', 'https://a.example.com'); h.set('Access-Control-Allow-Credentials', 'true'); "
    const { findings, ms } = timed(corsRule, 'server.ts', pair.repeat(15_000))
    assert.deepEqual(findings, [])
    assert.ok(ms < 5000, `took ${Math.round(ms)}ms`)
  })

  test('a reflection among many fixed configurations is still found', () => {
    const fixed = 'const o = {origin:"https://a.example.com",credentials:true}\n'.repeat(10_000)
    const content = 'app.use(cors({}))\n' + fixed + 'app.use(cors({origin:true,credentials:true}))\n' + fixed
    const findings = run(corsRule, 'server.ts', content)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.ruleId, 'cors/reflected-origin-with-credentials')
    assert.equal(findings[0]!.line, 10_002)
  })
})
