/** 初始化模板可直接解析，但不读取配置、不扫描、不修改原文件。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { Ajv } from 'ajv'
import { parseConfig } from '../src/config.js'
import { renderInit } from '../src/init.js'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const root = mkdtempSync(join(tmpdir(), 'canship-init-'))
after(() => rmSync(root, { recursive: true, force: true }))
function cli(...args: string[]) {
  return spawnSync(process.execPath, ['--import', new URL('../node_modules/tsx/dist/loader.mjs', import.meta.url).href,
    join(repository, 'src/cli.ts'), ...args], { cwd: root, encoding: 'utf8', timeout: 30_000 })
}

test('minimal config preview matches both the schema and runtime without narrowing checks', () => {
  const text = renderInit('config', '0.0.0-dev')
  const validate = new Ajv().compile(JSON.parse(readFileSync(join(repository, 'schemas/config-v1.schema.json'), 'utf8')))
  assert.equal(validate(JSON.parse(text)), true)
  assert.deepEqual(parseConfig(text, 'preview'), { all: false })
})

test('CI preview pins implementations, uses minimal permissions and leaves uploading disabled', () => {
  const text = renderInit('ci', '0.7.1')
  assert.match(text, /on: \[push, pull_request\]/)
  assert.match(text, /permissions:\n  contents: read/)
  assert.match(text, /fetch-depth: 0/)
  assert.match(text, /persist-credentials: false/)
  assert.match(text, /version: '0.7.1'/)
  assert.match(text, /honor-ignore-markers: false/)
  assert.match(text, /use-config: false/)
  assert.match(text, /upload-sarif: false/)
  assert.doesNotMatch(text, /pull_request_target|secrets\.|npm install|npm ci/)
  const readme = readFileSync(join(repository, 'README.md'), 'utf8')
  for (const match of text.matchAll(/uses: ([^\s]+@[a-f0-9]{40})/g)) assert.ok(readme.includes(match[1]!))
  assert.throws(() => renderInit('ci', 'injected\nstep'))
})

test('preview preserves an invalid existing config and emits content only on stdout', () => {
  writeFileSync(join(root, 'canship.config.json'), 'PRIVATE_EXISTING_CONFIG')
  writeFileSync(join(root, 'app.ts'), 'throw new Error("DO_NOT_EXECUTE");')
  const before = readdirSync(root).map(name => [name, readFileSync(join(root, name), 'utf8')])
  const config = cli('--init')
  assert.equal(config.status, 0, config.stderr)
  assert.deepEqual(JSON.parse(config.stdout), { all: false })
  assert.match(config.stderr, /preview only/)
  const ci = cli('--init=ci')
  assert.equal(ci.status, 0, ci.stderr)
  assert.match(ci.stdout, /^name: canship/)
  assert.match(ci.stderr, /verify that the scanner version is published/)
  assert.deepEqual(readdirSync(root).map(name => [name, readFileSync(join(root, name), 'utf8')]), before)
})

test('workspace CI preview isolates jobs and categories without enabling upload or project config', () => {
  const text = renderInit('ci-workspaces', '0.7.1')
  assert.match(text, /scan:\n    strategy:\n      fail-fast: false/)
  assert.match(text, /- \{ name: web, path: apps\/web \}/)
  assert.match(text, /- \{ name: admin, path: apps\/admin \}/)
  assert.match(text, /path: \$\{\{ matrix.project.path \}\}/)
  assert.match(text, /category: canship-\$\{\{ matrix.project.name \}\}/)
  assert.match(text, /upload-sarif: false/)
  assert.match(text, /use-config: false/)
  assert.match(text, /contents: read/)
  assert.doesNotMatch(text, /secrets\.|pull_request_target|security-events: write/)
  const output = cli('--init=ci-workspaces')
  assert.equal(output.status, 0, output.stderr)
  assert.match(output.stdout, /matrix:/)
  assert.match(output.stderr, /Review project paths/)
})

test('preview refuses ambiguous combinations and unsupported template names', () => {
  for (const flags of [['--init=unknown'], ['--init', '--init'], ['--init', '.'], ['--init', '--json'],
    ['--init', '--report'], ['--init', '--doctor'], ['--init', '--baseline-write']]) {
    const result = cli(...flags)
    assert.equal(result.status, 3)
    assert.equal(result.stdout, '')
  }
})
