/** 配置 Schema 与运行时接受范围一致；诊断定位不回显配置值。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { Ajv } from 'ajv'
import { ConfigError, parseConfig } from '../src/config.js'
import { RULE_IDS } from '../src/rules/index.js'

const schema = JSON.parse(readFileSync(new URL('../schemas/config-v1.schema.json', import.meta.url), 'utf8'))
const validate = new Ajv({ allErrors: true }).compile(schema)
const path = 'canship.config.json'

test('schema selectors include exactly the registered IDs and full namespaces', () => {
  const selectors = [...new Set(RULE_IDS.flatMap(id => {
    const parts = id.split('/')
    return parts.map((_, index) => parts.slice(0, index + 1).join('/'))
  }))].sort()
  assert.deepEqual(schema.definitions.selector.enum, selectors)
  for (const selector of selectors) {
    assert.equal(validate({ only: [selector] }), true, selector)
    assert.deepEqual(parseConfig(JSON.stringify({ only: [selector] }), path), { only: [selector] })
  }
})

const validCases = [
  {}, { all: true }, { all: false }, { baseline: 'review.json' }, { only: [] }, { skip: [] },
  { only: ['firebase', 'firebase'] }, { skip: ['cors'], all: true },
  { $schema: './local-schema.json' }, { $schema: 'https://example.invalid/schema.json', only: ['api'] },
]
for (const [index, value] of validCases.entries()) {
  test(`schema and runtime accept valid configuration ${index}`, () => {
    assert.equal(validate(value), true, JSON.stringify(validate.errors))
    assert.doesNotThrow(() => parseConfig(JSON.stringify(value), path))
  })
}

const invalidCases = [
  null, [], false, 'text', 1, { all: 'true' }, { all: null }, { baseline: '' }, { baseline: false },
  { only: 'api' }, { skip: [0] }, { only: [null] }, { only: [{}] }, { skip: [''] },
  { only: ['api/typo'] }, { only: ['api/admin'] }, { only: [], skip: [] },
  { only: ['api'], skip: ['cors'] }, { $schema: '' }, { $schema: 3 },
  { bestEffort: true }, { noExcerpts: true }, { include: [] }, { typo: true },
]
for (const [index, value] of invalidCases.entries()) {
  test(`schema and runtime reject invalid configuration ${index}`, () => {
    assert.equal(validate(value), false)
    assert.throws(() => parseConfig(JSON.stringify(value), path), ConfigError)
  })
}

test('schema references are metadata, never runtime options or content to load', () => {
  for (const reference of ['./missing.json', 'https://example.invalid/schema.json', 'file:///missing.json']) {
    assert.deepEqual(parseConfig(JSON.stringify({ $schema: reference, all: true }), path), { all: true })
  }
})

function expectLocation(text: string, marker: string, pointer: string, last = false): ConfigError {
  const offset = last ? text.lastIndexOf(marker) : text.indexOf(marker)
  assert.ok(offset >= 0)
  const preceding = text.slice(0, offset).split(/\r\n|\r|\n/)
  const line = preceding.length
  const column = preceding[preceding.length - 1]!.length + 1
  let caught: ConfigError | undefined
  assert.throws(() => parseConfig(text, path), (error: unknown) => {
    assert.ok(error instanceof ConfigError)
    caught = error
    assert.deepEqual(error.location, { line, column, pointer })
    assert.ok(error.message.includes(`${path}:${line}:${column}:`))
    assert.ok(error.message.includes(`(${pointer})`))
    return true
  })
  return caught!
}

test('wrong types, unknown fields, and selector items report exact field positions', () => {
  expectLocation('{\n  "all": "wrong"\n}', '"all"', '/all')
  expectLocation('{\n  "typo": true\n}', '"typo"', '/typo')
  expectLocation('{\n "only": [\n "firebase",\n "unknown"\n ]\n}', '"unknown"', '/only/1')
  expectLocation('{"skip": false}', '"skip"', '/skip')
  expectLocation('{"baseline":null}', '"baseline"', '/baseline')
  expectLocation('{"$schema":false}', '"$schema"', '/$schema')
  expectLocation('{"only":[],"skip":[]}', '"skip"', '/skip')
  expectLocation('{"bestEffort":true}', '"bestEffort"', '/bestEffort')
})

test('escaped keys, string punctuation, Unicode and line endings do not shift locations', () => {
  expectLocation('{"baseline":"contains \\"all\\": false", "all":0}', '"all":0', '/all')
  expectLocation('{"\\u0061ll":0}', '"\\u0061ll"', '/all')
  expectLocation('{"x~/":0}', '"x~/"', '/x~0~1')
  for (const newline of ['\n', '\r\n', '\r']) {
    expectLocation(`{${newline} "baseline":"中文路径",${newline} "all":0}`, '"all"', '/all')
  }
})

test('duplicate keys point to the last value used by JSON.parse', () => {
  expectLocation('{"all":true, "all":0}', '"all"', '/all', true)
  expectLocation('{"only":["unknown"], "only":["firebase", "unknown"]}', '"unknown"', '/only/1', true)
  assert.deepEqual(parseConfig('{"all":0,"all":true}', path), { all: true })
})

test('nested invalid selector items point to the item rather than its inner fields', () => {
  expectLocation('{"only":["firebase", {"all":true}]}', '{"all"', '/only/1')
  expectLocation('{"only":["firebase", ["bad"]]}', '["bad"]', '/only/1')
})

test('diagnostics omit invalid values and native parser source excerpts', () => {
  const marker = 'PRIVATE_VALUE_NOT_FOR_OUTPUT'
  const error = expectLocation(JSON.stringify({ only: ['firebase', marker] }), `"${marker}"`, '/only/1')
  assert.ok(!error.message.includes(marker))
  for (const text of [`{"all": ${marker}}`, `{"baseline":"${marker}",}`, '{"all":']) {
    assert.throws(() => parseConfig(text, path), (caught: unknown) => {
      assert.ok(caught instanceof ConfigError)
      assert.match(caught.message, /is not valid JSON/)
      assert.ok(!caught.message.includes(marker))
      if (caught.location) {
        assert.ok(caught.location.line >= 1 && caught.location.column >= 1)
        assert.equal(caught.location.pointer, null)
      }
      return true
    })
  }
})

test('deep invalid values do not require recursive location parsing', () => {
  const text = '{"only":[\n' + '['.repeat(3000) + '0' + ']'.repeat(3000) + ']}'
  expectLocation(text, '[[', '/only/0')
})

test('source text cannot masquerade as a native parser position', () => {
  assert.throws(() => parseConfig('position 3', path), (error: unknown) => {
    assert.ok(error instanceof ConfigError)
    // 旧版解析器可能定位首字符；不提供位置的版本保持未知。
    if (error.location !== null) assert.deepEqual(error.location, { line: 1, column: 1, pointer: null })
    return true
  })
})
