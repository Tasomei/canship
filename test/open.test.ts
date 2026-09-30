/** --open 只在交互式终端中启动系统程序，路径作为独立参数传入，失败不影响退出码。 */
import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import childProcess, { spawnSync, type SpawnOptions } from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canOpen, openerFor, openerEnvironment, openReport } from '../src/open.js'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))

test('each platform uses its own opener with the path as a separate argument', () => {
  const path = 'C:\\reports\\a b & c.html'
  assert.deepEqual(openerFor('win32', path, { SystemRoot: 'C:\\Windows' }), { command: 'C:\\Windows\\explorer.exe', args: [path] })
  assert.deepEqual(openerFor('darwin', '/tmp/r.html'), { command: '/usr/bin/open', args: ['/tmp/r.html'] })
  assert.deepEqual(openerFor('linux', '/tmp/r.html'), { command: '/usr/bin/xdg-open', args: ['/tmp/r.html'] })
})

test('opener resolution ignores project programs and refuses an unsafe system directory', () => {
  for (const SystemRoot of [undefined, '', '.', 'Windows', '\\\\server\\share']) {
    assert.throws(() => openerFor('win32', 'report.html', { SystemRoot }), /system directory/)
  }
  assert.equal(openerFor('win32', 'r.html', { SYSTEMROOT: 'D:\\OS', PATH: '.;node_modules/.bin' }).command, 'D:\\OS\\explorer.exe')
  assert.deepEqual(openerEnvironment('win32', 'C:\\Windows\\explorer.exe', { Path: '.;node_modules/.bin' }),
    { PATH: 'C:\\Windows;C:\\Windows\\System32' })
  assert.equal(openerEnvironment('linux', '/usr/bin/xdg-open', { PATH: './node_modules/.bin:.' }).PATH,
    '/usr/bin:/bin:/usr/sbin:/sbin')
})

test('the report is never opened in CI or without an interactive terminal', () => {
  assert.equal(canOpen({}, true), true)
  assert.equal(canOpen({ CI: 'true' }, true), false)
  assert.equal(canOpen({}, false), false)
})

test('openReport passes an absolute system program and isolated working directory to spawn', () => {
  const expected = openerFor(process.platform, '/report with spaces.html')
  const calls: Array<{ command: string; args: readonly string[]; options: SpawnOptions }> = []
  const stub = mock.method(childProcess, 'spawn', (command: string, args: readonly string[], options: SpawnOptions) => {
    calls.push({ command, args, options })
    return new childProcess.ChildProcess()
  })
  syncBuiltinESMExports()
  try {
    openReport('/report with spaces.html', message => assert.fail(message))
    assert.equal(calls.length, 1)
    assert.equal(calls[0]!.command, expected.command)
    assert.deepEqual(calls[0]!.args, expected.args)
    assert.equal(calls[0]!.options.cwd, dirname(expected.command))
    assert.equal(calls[0]!.options.shell, false)
    assert.ok(!calls[0]!.options.env!.PATH!.includes('node_modules'))
  } finally { stub.mock.restore(); syncBuiltinESMExports() }
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
