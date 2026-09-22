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
test('目录精确覆盖规则注册表，说明不可为空', () => {
  assert.deepEqual(RULE_CATALOG.map(item => item.id).sort(), [...RULE_IDS].sort())
  for (const item of RULE_CATALOG) assert.ok(item.name && item.scope && item.limitation)
  assert.equal(new Set(RULE_CATALOG.map(item => item.id)).size, RULE_CATALOG.length)
})
test('公开 Google 标识符不被描述为会报告的秘密', () => {
  assert.equal(RULE_CATALOG.find(item => item.id === 'secrets/hardcoded/google-api-key')?.reportsFindings, false)
  assert.match(renderRuleCatalog(), /Public identifier; not reported/)
})
test('规则查询不扫描项目或加载配置，支持独立 JSON 类型', () => {
  writeFileSync(join(root, 'canship.config.json'), '{broken')
  const result = cli('--list-rules', '--json')
  assert.equal(result.status, 0, result.stderr)
  const body = JSON.parse(result.stdout)
  assert.equal(body.kind, 'rule-catalog')
  assert.equal(body.rules.length, RULE_IDS.length)
  assert.equal(body.findings, undefined)
})
test('规则目录拒绝扫描参数，不能悄悄忽略写入请求', () => {
  for (const arg of ['--report', '--baseline-write', '--all', '.']) {
    assert.equal(cli('--list-rules', arg).status, 3)
  }
})
