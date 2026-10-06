/** 验证规则目录与实际注册表一致，且查询不读取项目配置。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { RULE_CATALOG, renderRuleCatalog } from '../src/rules/catalog.js'
import { RULE_IDS } from '../src/rules/index.js'

const root = mkdtempSync(join(tmpdir(), 'canship-catalog-'))
const repository = dirname(dirname(fileURLToPath(import.meta.url)))
after(() => rmSync(root, { recursive: true, force: true }))
function cli(...args: string[]) {
  return spawnSync(process.execPath, ['--import', new URL('../node_modules/tsx/dist/loader.mjs', import.meta.url).href,
    join(repository, 'src/cli.ts'), ...args], { cwd: root, encoding: 'utf8' })
}
test('the catalog covers exactly the rule registry, with no empty descriptions', () => {
  assert.deepEqual(RULE_CATALOG.map(item => item.id).sort(), [...RULE_IDS].sort())
  for (const item of RULE_CATALOG) assert.ok(item.name && item.scope && item.limitation)
  assert.equal(new Set(RULE_CATALOG.map(item => item.id)).size, RULE_CATALOG.length)
})
test('public Google identifiers are not described as reportable secrets', () => {
  assert.equal(RULE_CATALOG.find(item => item.id === 'secrets/hardcoded/google-api-key')?.reportsFindings, false)
  assert.match(renderRuleCatalog(), /Public identifier; not reported/)
})
test('listing rules neither scans nor loads config, and has its own JSON kind', () => {
  writeFileSync(join(root, 'canship.config.json'), '{broken')
  const result = cli('--list-rules', '--json')
  assert.equal(result.status, 0, result.stderr)
  const body = JSON.parse(result.stdout)
  assert.equal(body.kind, 'rule-catalog')
  assert.equal(body.rules.length, RULE_IDS.length)
  assert.equal(body.findings, undefined)
})
test('the rule catalog refuses scan options instead of silently ignoring write requests', () => {
  for (const arg of ['--report', '--baseline-write', '--all', '.']) {
    assert.equal(cli('--list-rules', arg).status, 3)
  }
})

test('the catalog filters an exact rule without reading project configuration', () => {
  writeFileSync(join(root, 'canship.config.json'), '{broken')
  const result = cli('--list-rules', '--only=injection/sql', '--json')
  assert.equal(result.status, 0, result.stderr)
  const body = JSON.parse(result.stdout)
  assert.equal(body.kind, 'rule-catalog')
  assert.deepEqual(body.rules.map((rule: {id: string}) => rule.id), ['injection/sql'])
  assert.equal(body.findings, undefined)
})

test('namespace, comma-separated and repeated catalog selectors are deduplicated', () => {
  const result = cli('--list-rules', '--only=injection,redirect', '--only=injection/sql', '--json')
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(JSON.parse(result.stdout).rules.map((rule: {id: string}) => rule.id), ['injection/command', 'injection/sql', 'redirect/open'])
})

test('catalog exclusions use the same namespace boundaries as scanning', () => {
  const result = cli('--list-rules', '--skip=secrets', '--skip=cors', '--json')
  assert.equal(result.status, 0, result.stderr)
  const rules = JSON.parse(result.stdout).rules as Array<{id: string}>
  assert.ok(rules.length > 0)
  assert.ok(rules.every(rule => !rule.id.startsWith('secrets/') && !rule.id.startsWith('cors/')))
  assert.ok(rules.some(rule => rule.id === 'injection/sql'))
})

test('filtered terminal output contains only the selected descriptions', () => {
  const result = cli('--list-rules', '--only=redirect/open')
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /^redirect\/open$/m)
  assert.doesNotMatch(result.stdout, /^injection\/|^api\//m)
  assert.match(result.stdout, /Scope:/)
  assert.match(result.stdout, /Limit:/)
})

for (const args of [
  ['--only=unknown'], ['--skip=injection/sql-extra'], ['--only=,,,'], ['--skip= , '],
  ['--only=api', '--skip=secrets'], ['--only=api', '--report'], ['--skip=cors', '.'],
]) {
  test(`invalid catalog selection is rejected: ${args.join(' ')}`, () => {
    const result = cli('--list-rules', ...args)
    assert.equal(result.status, 3)
    assert.equal(result.stdout, '')
  })
}
