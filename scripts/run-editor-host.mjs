/** 使用独立测试配置启动已安装编辑器，不安装扩展或修改正常用户配置。 */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync, lstatSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, dirname, basename, isAbsolute, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'

const code = process.argv[2]
if (!code || !isAbsolute(code)) throw new Error('Pass the absolute path of an installed VS Code executable.')
const option = process.argv[3]
if (process.argv.length > 4 || (option && !['--prepare', '--workflows'].includes(option) && !option.startsWith('--session='))) throw new Error('Use --prepare, --workflows or --session=<test-directory>.')
const prepare = option === '--prepare'
let workflows = option === '--workflows'
const existing = option?.startsWith('--session=') ? option.slice('--session='.length) : null
if (existing !== null && !isAbsolute(existing)) throw new Error('Pass an absolute isolated test directory.')
const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const extension = join(repository, 'extensions/vscode')
if (!existsSync(join(extension, 'dist/extension.cjs'))) throw new Error('Build the extension first.')
const directory = existing ?? mkdtempSync(join(tmpdir(), 'canship-editor-host-'))
const project = join(directory, 'project')
if (existing !== null) {
  if (!isAbsolute(directory) || !/^canship-editor-host-[\w-]+$/.test(basename(directory)) ||
    realpathSync(dirname(directory)) !== realpathSync(tmpdir())) throw new Error('Not an isolated test directory.')
  for (const path of [directory, project, join(directory, 'profile'), join(directory, 'marker.json')]) {
    if (lstatSync(path).isSymbolicLink()) throw new Error('Linked test sessions are not accepted.')
  }
  const marker = JSON.parse(readFileSync(join(directory, 'marker.json'), 'utf8'))
  if (marker.kind !== 'canship-editor-host-test') throw new Error('Invalid test marker.')
  workflows = marker.suite === 'workflows'
  if (workflows) {
    const inputs = ['one', 'two', 'one/server.ts', 'two/server.ts', 'one/canship.config.json',
      'two/canship.config.json', 'two/firestore.rules', 'canship.code-workspace']
    const projectReal = realpathSync(project)
    for (const input of inputs) {
      const path = join(project, input), info = lstatSync(path)
      const suffix = relative(projectReal, realpathSync(path))
      if (info.isSymbolicLink() || suffix === '..' || suffix.startsWith('..' + sep) || isAbsolute(suffix) ||
        (input.includes('/') || input.endsWith('.code-workspace') ? !info.isFile() : !info.isDirectory())) throw new Error('Invalid workflow test input.')
    }
    const workspace = JSON.parse(readFileSync(join(project, 'canship.code-workspace'), 'utf8'))
    if (!workspace || Object.keys(workspace).length !== 1 || !Array.isArray(workspace.folders) || workspace.folders.length !== 2 ||
      workspace.folders.some((folder, index) => !folder || Object.keys(folder).length !== 2 ||
        folder.name !== ['Synthetic One', 'Synthetic Two'][index] || folder.path !== ['one', 'two'][index])) throw new Error('Invalid workflow workspace layout.')
  }
  if (existsSync(join(directory, 'result.json')) || existsSync(join(directory, 'waiting.json'))) throw new Error('This session already has test results; prepare a new session.')
} else {
  mkdirSync(project)
  writeFileSync(join(directory, 'marker.json'), JSON.stringify({ kind: 'canship-editor-host-test', suite: workflows ? 'workflows' : 'basic' }), { flag: 'wx' })
  if (workflows) {
    for (const name of ['one', 'two']) {
      mkdirSync(join(project, name))
      writeFileSync(join(project, name, 'server.ts'), 'app.use(cors({origin:true,credentials:true}));', { flag: 'wx' })
      writeFileSync(join(project, name, 'canship.config.json'), JSON.stringify({ only: [name === 'one' ? 'cors' : 'firebase'] }), { flag: 'wx' })
    }
    writeFileSync(join(project, 'two', 'firestore.rules'), 'match /items/{id} { allow write: if true; }', { flag: 'wx' })
    writeFileSync(join(project, 'canship.code-workspace'), JSON.stringify({ folders: [
      { name: 'Synthetic One', path: 'one' }, { name: 'Synthetic Two', path: 'two' },
    ] }), { flag: 'wx' })
  } else writeFileSync(join(project, 'server.ts'), 'app.use(cors({origin:true,credentials:true}));', { flag: 'wx' })
}
const env = { ...process.env, CANSHIP_EDITOR_TEST_DIR: directory, CANSHIP_EDITOR_EXTENSION: extension }
delete env.ELECTRON_RUN_AS_NODE
delete env.VSCODE_IPC_HOOK_CLI
const child = spawn(realpathSync(code), [workflows ? join(project, 'canship.code-workspace') : project, '--new-window', '--disable-extensions', '--skip-welcome', '--skip-release-notes',
  `--user-data-dir=${join(directory, 'profile')}`, `--extensions-dir=${join(directory, 'extensions')}`,
  `--extensionDevelopmentPath=${extension}`, ...(prepare ? [] : [`--extensionTestsPath=${join(extension, 'test/host.cjs')}`])],
{ cwd: resolve(directory), env, stdio: 'ignore', windowsHide: false })
let launchFailed = false
let hostExited = false
child.on('error', () => { launchFailed = true })
child.on('exit', () => { hostExited = true })
if (prepare) {
  await new Promise(resolve => child.once('spawn', resolve).once('error', resolve))
  if (launchFailed) { console.log(JSON.stringify({ status: 'failed', stage: 'launch' })); process.exitCode = 3 }
  else {
    console.log(JSON.stringify({ status: 'prepared', directory, project, pid: child.pid }))
    // 保留驱动进程，避免受控终端结束时连带关闭开发窗口。
    if (!hostExited) await new Promise(resolve => child.once('exit', resolve))
  }
} else {
  const deadline = Date.now() + (workflows ? 900_000 : 360_000)
  let waiting = false
  while (!launchFailed && !hostExited && !existsSync(join(directory, 'result.json')) && Date.now() < deadline) {
    if (!waiting && existsSync(join(directory, 'waiting.json'))) {
      waiting = true
      console.log(JSON.stringify({ status: 'waiting', stage: 'trust', project, timeoutSeconds: 300 }))
    }
    await new Promise(resolve => setTimeout(resolve, 500))
  }
  const result = existsSync(join(directory, 'result.json')) ? JSON.parse(readFileSync(join(directory, 'result.json'), 'utf8'))
    : { status: 'failed', stage: launchFailed ? 'launch' : hostExited ? 'host-exit' : 'timeout' }
  console.log(JSON.stringify(result))
  process.exitCode = result.status === 'passed' ? 0 : result.status === 'blocked' ? 2 : 3
  // 失败或阻塞保留宿主，由用户阅读提示后关闭；不得在结果刚写出时抢先关窗。
  if (!launchFailed && !hostExited && result.status !== 'passed') {
    console.log(JSON.stringify({ status: 'awaiting-close', stage: result.stage, directory }))
    await new Promise(resolve => child.once('exit', resolve))
  }
  // 通过后仅停止本次隔离宿主，不触及其他编辑器实例。
  if (!launchFailed && !hostExited && result.status === 'passed') child.kill()
}
