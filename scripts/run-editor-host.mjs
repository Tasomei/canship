/** 使用独立测试配置启动已安装编辑器，不安装扩展或修改正常用户配置。 */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, dirname, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'

const code = process.argv[2]
if (!code || !isAbsolute(code)) throw new Error('Pass the absolute path of an installed VS Code executable.')
const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const extension = join(repository, 'extensions/vscode')
if (!existsSync(join(extension, 'dist/extension.cjs'))) throw new Error('Build the extension first.')
const directory = mkdtempSync(join(tmpdir(), 'canship-editor-host-'))
const project = join(directory, 'project'); mkdirSync(project)
writeFileSync(join(directory, 'marker.json'), JSON.stringify({ kind: 'canship-editor-host-test' }), { flag: 'wx' })
writeFileSync(join(project, 'server.ts'), 'app.use(cors({origin:true,credentials:true}));', { flag: 'wx' })
const env = { ...process.env, CANSHIP_EDITOR_TEST_DIR: directory, CANSHIP_EDITOR_EXTENSION: extension }
delete env.ELECTRON_RUN_AS_NODE
delete env.VSCODE_IPC_HOOK_CLI
const child = spawn(realpathSync(code), [project, '--new-window', '--disable-extensions', '--skip-welcome', '--skip-release-notes',
  `--user-data-dir=${join(directory, 'profile')}`, `--extensions-dir=${join(directory, 'extensions')}`,
  `--extensionDevelopmentPath=${extension}`, `--extensionTestsPath=${join(extension, 'test/host.cjs')}`],
{ cwd: resolve(directory), env, stdio: 'ignore', windowsHide: true })
let launchFailed = false
child.on('error', () => { launchFailed = true })
const deadline = Date.now() + 120_000
while (!launchFailed && !existsSync(join(directory, 'result.json')) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 500))
const result = existsSync(join(directory, 'result.json')) ? JSON.parse(readFileSync(join(directory, 'result.json'), 'utf8'))
  : { status: 'failed', stage: launchFailed ? 'launch' : 'timeout' }
console.log(JSON.stringify(result))
process.exitCode = result.status === 'passed' ? 0 : result.status === 'blocked' ? 2 : 3
// 仅停止此驱动器启动的独立宿主，不触及其他编辑器实例。
if (child.exitCode === null) child.kill()
