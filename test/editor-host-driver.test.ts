/** 驱动器使用模拟进程检查启动边界，不启动编辑器、不写入用户配置。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { EventEmitter } from 'node:events'
import { runInNewContext } from 'node:vm'
import { win32 } from 'node:path'

const script = readFileSync(new URL('../scripts/run-editor-host.mjs', import.meta.url), 'utf8')
  .replace(/^import .*$/gm, '').replace('import.meta.url', "'synthetic-driver'")
const temporary = 'C:\\synthetic-temp'
const session = win32.join(temporary, 'canship-editor-host-sample')
async function driver(option?: string, scenario: { linked?: boolean; existingResult?: boolean; launchFails?: boolean; exitEarly?: boolean; signalExit?: boolean; result?: 'failed' | 'blocked' } = {}) {
  const writes: string[] = [], logs: string[] = [], launches: Array<{ args: string[]; options: any }> = []
  let spawned = false, stopped = 0
  const process = { argv: ['node', 'script', 'C:\\synthetic-editor\\Code.exe', ...(option === undefined ? [] : [option])],
    env: { ELECTRON_RUN_AS_NODE: '1', VSCODE_IPC_HOOK_CLI: 'synthetic' }, exitCode: 0 }
  class Child extends EventEmitter {
    pid = 123; exitCode: number | null = null
    kill() { this.exitCode = 0; stopped++ }
  }
  let childForClose: Child | undefined
  const run = runInNewContext(`(async () => { ${script} })()`, {
    ...win32, process, console: { log: (line: string) => {
      logs.push(line)
      if (JSON.parse(line).status === 'awaiting-close') {
        assert.equal(stopped, 0)
        queueMicrotask(() => { childForClose!.exitCode = 1; childForClose!.emit('exit', 1) })
      }
    } },
    fileURLToPath: () => 'C:\\synthetic-repository\\scripts\\run-editor-host.mjs', tmpdir: () => temporary,
    mkdtempSync: () => { writes.push('new-directory'); return session }, mkdirSync: (path: string) => writes.push(path),
    writeFileSync: (path: string) => writes.push(path), realpathSync: (path: string) => path,
    lstatSync: () => ({ isSymbolicLink: () => Boolean(scenario.linked) }),
    existsSync: (path: string) => path.endsWith('extension.cjs') ||
      (path.endsWith('result.json') && (scenario.existingResult || (spawned && !scenario.exitEarly && !scenario.signalExit))),
    readFileSync: (path: string) => JSON.stringify(path.endsWith('marker.json') ? { kind: 'canship-editor-host-test' }
      : { status: scenario.result ?? 'passed', ...(scenario.result ? { stage: scenario.result === 'blocked' ? 'trust' : 'actions' } : {}) }),
    spawn: (_code: string, args: string[], options: unknown) => {
      launches.push({ args, options }); const child = new Child(); childForClose = child; spawned = true
      queueMicrotask(() => {
        if (scenario.launchFails) child.emit('error', new Error('synthetic launch failure'))
        else { child.emit('spawn'); if (!scenario.result) queueMicrotask(() => {
          child.exitCode = scenario.signalExit ? null : 0; child.emit('exit', child.exitCode, scenario.signalExit ? 'SIGTERM' : null)
        }) }
      })
      return child
    },
    setTimeout: (callback: () => void) => { queueMicrotask(callback); return 0 },
  })
  try { await run } catch (error) { return { error, writes, launches, logs, process, stopped } }
  return { error: undefined, writes, launches, logs, process, stopped }
}
test('prepare launches a visible isolated host without automated tests or trust bypass', async () => {
  const result = await driver('--prepare')
  assert.equal(result.error, undefined)
  assert.equal(result.launches.length, 1)
  const launch = result.launches[0]!
  assert.equal(launch.options.windowsHide, false)
  assert.ok(launch.args.includes(`--user-data-dir=${session}\\profile`))
  assert.ok(launch.args.includes(`--extensions-dir=${session}\\extensions`))
  assert.ok(launch.args.includes('--disable-extensions'))
  assert.ok(!launch.args.some(value => /extensionTestsPath|disable-workspace-trust/.test(value)))
  assert.equal(launch.options.env.ELECTRON_RUN_AS_NODE, undefined)
  assert.equal(launch.options.env.VSCODE_IPC_HOOK_CLI, undefined)
  assert.equal(JSON.parse(result.logs[0]!).status, 'prepared')
  assert.equal(result.stopped, 0)
})
test('empty, relative or unrelated sessions fail before writing or launching', async () => {
  for (const option of ['--session=', '--session=relative', '--session=C:\\unrelated\\canship-editor-host-sample', '--unsupported']) {
    const result = await driver(option)
    assert.ok(result.error, option); assert.equal(result.writes.length, 0, option); assert.equal(result.launches.length, 0, option)
  }
})
test('linked sessions and prior results cannot be reused or overwritten', async () => {
  for (const scenario of [{ linked: true }, { existingResult: true }]) {
    const result = await driver(`--session=${session}`, scenario)
    assert.ok(result.error); assert.equal(result.writes.length, 0); assert.equal(result.launches.length, 0)
  }
})
test('a verified session preserves files and runs the host tests in its own profile', async () => {
  const result = await driver(`--session=${session}`)
  assert.equal(result.error, undefined); assert.equal(result.writes.length, 0)
  assert.equal(result.launches[0]!.options.windowsHide, false)
  assert.ok(result.launches[0]!.args.some(value => value.startsWith('--extensionTestsPath=')))
  assert.equal(JSON.parse(result.logs[0]!).status, 'passed')
  assert.equal(result.process.exitCode, 0)
})
test('launch failure and early host exit never report a successful scan', async () => {
  const failed = await driver('--prepare', { launchFails: true })
  assert.equal(JSON.parse(failed.logs[0]!).stage, 'launch'); assert.equal(failed.process.exitCode, 3)
  const early = await driver(`--session=${session}`, { exitEarly: true })
  assert.equal(JSON.parse(early.logs[0]!).stage, 'host-exit'); assert.equal(early.process.exitCode, 3)
})

test('failed or blocked results keep the host alive until the user closes it', async () => {
  for (const status of ['failed', 'blocked'] as const) {
    const result = await driver(`--session=${session}`, { result: status })
    assert.equal(result.error, undefined)
    assert.deepEqual(result.logs.map(line => JSON.parse(line).status), [status, 'awaiting-close'])
    assert.equal(result.process.exitCode, status === 'blocked' ? 2 : 3)
    assert.equal(result.stopped, 0)
  }
})

test('a host terminated by signal is an exit failure, not a hanging trust timeout', async () => {
  const result = await driver(`--session=${session}`, { signalExit: true })
  assert.equal(JSON.parse(result.logs[0]!).stage, 'host-exit')
  assert.equal(result.process.exitCode, 3)
  assert.equal(result.stopped, 0)
})
