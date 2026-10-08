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
const workflowWorkspace = { folders: [
  { name: 'Synthetic One', path: 'one' }, { name: 'Synthetic Two', path: 'two' },
] }
type Scenario = {
  linked?: boolean; linkedPaths?: string[]; escapedPaths?: string[]
  pathTypes?: Record<string, 'file' | 'directory' | 'other'>
  existingResult?: boolean; launchFails?: boolean; exitEarly?: boolean; signalExit?: boolean
  result?: 'failed' | 'blocked'; marker?: Record<string, unknown>; workspace?: unknown
}
async function driver(option?: string, scenario: Scenario = {}) {
  const writes: string[] = [], logs: string[] = [], launches: Array<{ args: string[]; options: any }> = []
  const files: Array<{ path: string; content: string; flag: string | undefined }> = []
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
    writeFileSync: (path: string, content: string, options?: { flag?: string }) => {
      writes.push(path); files.push({ path, content, flag: options?.flag })
    }, realpathSync: (path: string) => scenario.escapedPaths?.includes(win32.relative(session, path))
      ? win32.join(temporary, 'unrelated-project', win32.basename(path)) : path,
    lstatSync: (path: string) => {
      const type = scenario.pathTypes?.[win32.relative(session, path)] ?? (win32.extname(path) === '' ? 'directory' : 'file')
      return {
        isSymbolicLink: () => Boolean(scenario.linked || scenario.linkedPaths?.includes(win32.relative(session, path))),
        isDirectory: () => type === 'directory', isFile: () => type === 'file',
      }
    },
    existsSync: (path: string) => path.endsWith('extension.cjs') ||
      (path.endsWith('result.json') && (scenario.existingResult || (spawned && !scenario.exitEarly && !scenario.signalExit))),
    readFileSync: (path: string) => {
      if (path.endsWith('marker.json')) return JSON.stringify(scenario.marker ?? { kind: 'canship-editor-host-test' })
      if (path.endsWith('canship.code-workspace')) return JSON.stringify(scenario.workspace === undefined ? workflowWorkspace : scenario.workspace)
      if (path.endsWith('canship.config.json')) return JSON.stringify({ only: [path.includes('\\one\\') ? 'cors' : 'firebase'] })
      if (path.endsWith('server.ts')) return 'app.use(cors({origin:true,credentials:true}));'
      if (path.endsWith('firestore.rules')) return 'match /items/{id} { allow write: if true; }'
      return JSON.stringify({ status: scenario.result ?? 'passed', ...(scenario.result ? { stage: scenario.result === 'blocked' ? 'trust' : 'actions' } : {}) })
    },
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
  try { await run } catch (error) { return { error, writes, files, launches, logs, process, stopped } }
  return { error: undefined, writes, files, launches, logs, process, stopped }
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

test('workflow fixtures contain only two synthetic roots with separate rule configurations', async () => {
  const result = await driver('--workflows')
  assert.equal(result.error, undefined)
  const files = new Map(result.files.map(file => [win32.relative(session, file.path), file.content]))
  assert.deepEqual([...files.keys()].sort(), [
    'marker.json', 'project\\canship.code-workspace', 'project\\one\\canship.config.json',
    'project\\one\\server.ts', 'project\\two\\canship.config.json', 'project\\two\\firestore.rules',
    'project\\two\\server.ts',
  ].sort())
  assert.deepEqual(JSON.parse(files.get('marker.json')!), { kind: 'canship-editor-host-test', suite: 'workflows' })
  assert.deepEqual(JSON.parse(files.get('project\\canship.code-workspace')!), { folders: [
    { name: 'Synthetic One', path: 'one' }, { name: 'Synthetic Two', path: 'two' },
  ] })
  assert.deepEqual(JSON.parse(files.get('project\\one\\canship.config.json')!), { only: ['cors'] })
  assert.deepEqual(JSON.parse(files.get('project\\two\\canship.config.json')!), { only: ['firebase'] })
  assert.equal(files.get('project\\one\\server.ts'), 'app.use(cors({origin:true,credentials:true}));')
  assert.equal(files.get('project\\two\\server.ts'), files.get('project\\one\\server.ts'))
  assert.equal(files.get('project\\two\\firestore.rules'), 'match /items/{id} { allow write: if true; }')
  assert.ok(result.files.every(file => file.flag === 'wx'))
  assert.ok(result.writes.filter(path => path !== 'new-directory').every(path => {
    const relative = win32.relative(session, path)
    return relative !== '' && !relative.startsWith('..') && !win32.isAbsolute(relative)
  }))
})

test('workflow launch uses the generated workspace and isolated profile without granting trust', async () => {
  const result = await driver('--workflows')
  assert.equal(result.error, undefined); assert.equal(result.launches.length, 1)
  const launch = result.launches[0]!
  assert.equal(launch.args[0], win32.join(session, 'project', 'canship.code-workspace'))
  assert.equal(launch.options.cwd, session)
  assert.equal(launch.options.windowsHide, false)
  assert.ok(launch.args.includes(`--user-data-dir=${session}\\profile`))
  assert.ok(launch.args.includes(`--extensions-dir=${session}\\extensions`))
  assert.ok(launch.args.includes('--disable-extensions'))
  assert.ok(launch.args.some(value => value.endsWith('test\\host.cjs')))
  assert.ok(!launch.args.some(value => /disable-workspace-trust|accept.*trust/i.test(value)))
  assert.ok(!result.files.some(file => /profile|settings\.json|storage\.json/i.test(file.path)))
  assert.equal(launch.options.env.ELECTRON_RUN_AS_NODE, undefined)
  assert.equal(launch.options.env.VSCODE_IPC_HOOK_CLI, undefined)
  assert.equal(launch.options.env.CANSHIP_EDITOR_TEST_DIR, session)
  assert.equal(JSON.parse(result.logs.at(-1)!).status, 'passed')
  assert.equal(result.process.exitCode, 0)
})

test('fresh basic and prepare fixtures remain single-root without workflow configuration', async () => {
  for (const option of [undefined, '--prepare']) {
    const result = await driver(option)
    assert.equal(result.error, undefined)
    assert.deepEqual(result.files.map(file => win32.relative(session, file.path)).sort(), ['marker.json', 'project\\server.ts'])
    assert.deepEqual(JSON.parse(result.files.find(file => file.path.endsWith('marker.json'))!.content), {
      kind: 'canship-editor-host-test', suite: 'basic',
    })
    assert.equal(result.launches[0]!.args[0], win32.join(session, 'project'))
    assert.ok(result.files.every(file => file.flag === 'wx'))
    assert.equal(result.launches[0]!.args.some(value => value.startsWith('--extensionTestsPath=')), option !== '--prepare')
  }
})

test('session markers select workflow or legacy basic mode without rewriting fixtures', async () => {
  for (const suite of ['workflows', 'basic', undefined]) {
    const marker = { kind: 'canship-editor-host-test', ...(suite ? { suite } : {}) }
    const result = await driver(`--session=${session}`, { marker })
    assert.equal(result.error, undefined)
    assert.equal(result.writes.length, 0); assert.equal(result.files.length, 0)
    assert.equal(result.launches.length, 1)
    assert.equal(result.launches[0]!.args[0], win32.join(session, 'project', ...(suite === 'workflows' ? ['canship.code-workspace'] : [])))
    assert.equal(result.process.exitCode, 0)
  }
})

test('invalid workflow marker and existing workflow results fail before writes or launch', async () => {
  for (const scenario of [
    { marker: { kind: 'unrelated-session', suite: 'workflows' } },
    { marker: { kind: 'canship-editor-host-test', suite: 'workflows' }, existingResult: true },
    { marker: { kind: 'canship-editor-host-test', suite: 'workflows' }, linked: true },
  ]) {
    const result = await driver(`--session=${session}`, scenario)
    assert.ok(result.error); assert.equal(result.writes.length, 0); assert.equal(result.launches.length, 0)
  }
})

test('reused workflows reject linked roots, fixture files and workspace documents', async () => {
  for (const path of ['project\\one', 'project\\two', 'project\\canship.code-workspace',
    'project\\one\\server.ts', 'project\\two\\server.ts', 'project\\two\\firestore.rules',
    'project\\one\\canship.config.json', 'project\\two\\canship.config.json']) {
    const result = await driver(`--session=${session}`, {
      marker: { kind: 'canship-editor-host-test', suite: 'workflows' }, linkedPaths: [path],
    })
    assert.ok(result.error, path); assert.equal(result.writes.length, 0, path); assert.equal(result.launches.length, 0, path)
  }
})

test('reused workflow targets must resolve inside their isolated project', async () => {
  for (const path of ['project\\one', 'project\\two', 'project\\canship.code-workspace',
    'project\\one\\server.ts', 'project\\two\\server.ts', 'project\\two\\firestore.rules',
    'project\\one\\canship.config.json', 'project\\two\\canship.config.json']) {
    const result = await driver(`--session=${session}`, {
      marker: { kind: 'canship-editor-host-test', suite: 'workflows' }, escapedPaths: [path],
    })
    assert.ok(result.error, path); assert.equal(result.writes.length, 0, path); assert.equal(result.launches.length, 0, path)
  }
})

test('reused workflows reject altered roots and extra workspace configuration', async () => {
  const first = { name: 'Synthetic One', path: 'one' }, second = { name: 'Synthetic Two', path: 'two' }
  for (const workspace of [null, false, 0, '', [], {}, { folders: null }, { folders: {} },
    { folders: [] }, { folders: [first] }, { folders: [null, second] }, { folders: [first, null] },
    { folders: [second, first] }, { folders: [{ ...first, extra: true }, second] },
    { folders: [first, second, { name: 'Extra', path: '../extra' }] },
    { folders: [first, { ...second, path: '../outside' }] },
    { folders: [first, { ...second, path: 'C:\\unrelated-project' }] },
    { folders: [first, { ...second, name: 'Different' }] },
    { folders: [first, first] },
    { folders: [first, { ...second, uri: 'file:///C:/unrelated-project' }] },
    { folders: [first, second], settings: {} },
    { folders: [first, second], extensions: { recommendations: ['synthetic.extension'] } },
  ]) {
    const result = await driver(`--session=${session}`, {
      marker: { kind: 'canship-editor-host-test', suite: 'workflows' }, workspace,
    })
    assert.ok(result.error, JSON.stringify(workspace))
    assert.equal(result.writes.length, 0); assert.equal(result.launches.length, 0)
  }
})

test('reused workflows reject swapped fixture types and non-regular filesystem nodes', async () => {
  for (const path of ['project\\one', 'project\\two', 'project\\canship.code-workspace',
    'project\\one\\server.ts', 'project\\two\\server.ts', 'project\\two\\firestore.rules',
    'project\\one\\canship.config.json', 'project\\two\\canship.config.json']) {
    for (const type of ['other', win32.extname(path) === '' ? 'file' : 'directory'] as const) {
      const result = await driver(`--session=${session}`, {
        marker: { kind: 'canship-editor-host-test', suite: 'workflows' }, pathTypes: { [path]: type },
      })
      assert.ok(result.error, `${path}: ${type}`)
      assert.equal(result.writes.length, 0, path); assert.equal(result.launches.length, 0, path)
    }
  }
})
