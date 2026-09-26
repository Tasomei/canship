/** 验证 Firebase Realtime Database 的 JSON 规则：无条件开放、级联路径、注释及只读设计。
 * canship-ignore-file */
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { firebaseRulesRule } from '../src/rules/firebase.js'
import { scan } from '../src/engine.js'
import type { Finding, ScanContext, ScanFile } from '../src/types.js'

const ctx: ScanContext = { root: '', files: [], git: 'not-a-repo', gitExecutable: null, reportIncomplete: () => {} }

function file(content: string, path = 'database.rules.json'): ScanFile {
  return { path, content, lines: content.split('\n'), isExampleContext: false }
}

function check(content: string, path?: string): Finding[] {
  const target = file(content, path)
  return firebaseRulesRule.appliesTo(target) ? firebaseRulesRule.check(target, ctx) : []
}

describe('Realtime Database rules', () => {
  // 官方“不安全规则”页面中的示例，带行注释。
  test('the documented open ruleset is reported once, as read and write', () => {
    const findings = check('{\n  // Allow read/write access to all users under any conditions\n  "rules": {\n    ".read": true,\n    ".write": true\n  }\n}\n')
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.ruleId, 'firebase/open-rules')
    assert.equal(findings[0]!.confidence, 'certain')
    assert.match(findings[0]!.title, /read and write your entire database/)
    assert.equal(findings[0]!.line, 5)
  })

  test('a string "true" is as open as a boolean', () => {
    const findings = check('{ "rules": { "posts": { ".write": "true" } } }')
    assert.equal(findings.length, 1)
    assert.match(findings[0]!.title, /write \/posts/)
  })

  test('an open write deep in the tree names its path', () => {
    const findings = check('{ "rules": { "users": { "$uid": { ".read": "auth.uid === $uid", ".write": true } } } }')
    assert.equal(findings.length, 1)
    assert.match(findings[0]!.title, /\/users\/\$uid/)
    assert.equal(findings[0]!.confidence, 'certain')
  })

  test('a public read is reported at lower confidence', () => {
    const findings = check('{ "rules": { "some_path/$uid": { ".read": true, ".write": "auth.uid === $uid" } } }')
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, 'likely')
    assert.match(findings[0]!.title, /\/some_path\/\$uid publicly readable/)
  })

  test('a public read beside an explicit write denial is a read-only design', () => {
    assert.deepEqual(check('{ "rules": { "catalog": { ".read": true, ".write": false } } }'), [])
  })

  test('authenticated and locked rules are not reported', () => {
    assert.deepEqual(check('{ "rules": { ".read": "auth.uid !== null", ".write": "auth.uid !== null" } }'), [])
    assert.deepEqual(check('{ "rules": { ".read": false, ".write": false } }'), [])
  })

  test('a rule inside a comment is not a rule', () => {
    assert.deepEqual(check('{ "rules": {\n  /* ".write": true */\n  // ".read": true\n  ".read": "auth != null"\n} }'), [])
  })

  test('JSON that is not a rules file is left alone', () => {
    assert.deepEqual(check('{ "name": "x", "config": { ".read": true } }', 'package.json'), [])
    assert.deepEqual(check('{ "database": { "rules": "database.rules.json" } }', 'firebase.json'), [])
  })

  test('a renamed rules file is still recognised by its contents', () => {
    assert.equal(check('{ "rules": { ".write": true } }', 'config/rtdb.json').length, 1)
  })
  test('Realtime JSON in a .rules file is not parsed as Firestore syntax', () => {
    assert.equal(check('{ "rules": { ".write": true } }', 'database.rules').length, 1)
  })
  for (const value of [' true ', '(true)', '(( true ))', 'tr\\u0075e']) {
    test(`constant rule strings are decoded: ${value}`, () => {
      assert.equal(check(`{ "rules": { ".write": "${value}" } }`).length, 1)
    })
  }
  test('malformed rule JSON reports incomplete coverage without leaking parser input', () => {
    const gaps: string[] = []
    const target = file('{ "rules": { ".write": true, PRIVATE_SENTINEL } }')
    firebaseRulesRule.check(target, { ...ctx, reportIncomplete: (_, message) => gaps.push(message) })
    assert.equal(gaps.length, 1)
    assert.doesNotMatch(gaps.join(' '), /PRIVATE_SENTINEL/)
  })

  test('an unterminated key does not crash the rule', () => {
    assert.doesNotThrow(() => check('{ "rules": { "a\\'))
  })

  test('a large rules file is read in linear time', () => {
    const nodes = Array.from({ length: 40_000 }, (_, i) => `"n${i}": { ".read": "auth != null", ".write": false }`).join(',\n')
    const started = performance.now()
    assert.deepEqual(check(`{ "rules": {\n${nodes}\n} }`), [])
    assert.ok(performance.now() - started < 5000)
  })

  test('a project scan picks up database.rules.json', async () => {
    const root = mkdtempSync(join(tmpdir(), 'canship-rtdb-'))
    try {
      writeFileSync(join(root, 'database.rules.json'), '{ "rules": { ".read": true, ".write": true } }\n')
      const result = await scan(root)
      assert.deepEqual(result.findings.map((f) => `${f.ruleId} ${f.confidence}`), ['firebase/open-rules certain'])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
