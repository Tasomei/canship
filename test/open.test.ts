/** --open 只在交互式终端中启动系统程序，路径作为独立参数传入，失败不影响退出码。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canOpen, openerFor } from '../src/open.js'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))

test('each platform uses its own opener with the path as a separate argument', () => {
  const path = 'C:\\reports\\a b & c.html'
  assert.deepEqual(openerFor('win32', path), { command: 'explorer.exe', args: [path] })
  assert.deepEqual(openerFor('darwin', '/tmp/r.html'), { command: 'open', args: ['/tmp/r.html'] })
  assert.deepEqual(openerFor('linux', '/tmp/r.html'), { command: 'xdg-open', args: ['/tmp/r.html'] })
})

test('the report is never opened in CI or without an interactive terminal', () => {
  assert.equal(canOpen({}, true), true)
  assert.equal(canOpen({ CI: 'true' }, true), false)
  assert.equal(canOpen({}, false), false)
})

function cli(...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', join(repository, 'src/cli.ts'), ...args], {
    cwd: repository, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' }, timeout: 60_000,
  })
}

test('--open requires --report', () => {
  const root = mkdtempSync(join(tmpdir(), 'canship-open-'))
  try {
    writeFileSync(join(root, 'index.ts'), 'export const ok = true\n')
    const result = cli(root, '--open')
    assert.equal(result.status, 3)
    assert.match(result.stderr, /--open requires --report/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('a non-interactive run writes the report, explains why it was not opened, and keeps the exit code', () => {
  const root = mkdtempSync(join(tmpdir(), 'canship-open-'))
  try {
    writeFileSync(join(root, 'index.ts'), 'export const ok = true\n')
    const report = join(root, 'out.html')
    const result = cli(root, `--report=${report}`, '--open', '--json')
    assert.equal(result.status, 0)
    assert.ok(existsSync(report))
    assert.match(result.stderr, /not opening the report in CI or a non-interactive session/)
    assert.doesNotThrow(() => JSON.parse(result.stdout), 'the notice must not corrupt JSON output')
  } finally { rmSync(root, { recursive: true, force: true }) }
})
