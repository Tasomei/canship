/** 钩子模板只调用显式指定的外部扫描器，不安装依赖或读取项目命令。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, chmodSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { renderInit } from '../src/init.js'
import { execGitSync, resolveGitExecutable } from '../src/git.js'

const root = mkdtempSync(join(tmpdir(), 'canship-hook-'))
after(() => rmSync(root, { recursive: true, force: true }))
const project = join(root, 'project'), installed = join(root, 'scanner installation')
mkdirSync(project); mkdirSync(installed)
const hook = join(project, 'pre-commit'), scanner = join(installed, 'cli.cjs')
writeFileSync(hook, renderInit('pre-commit', '0.7.1'))
function fakeScanner(code = 0, version = '0.7.1') {
  writeFileSync(scanner, `if(process.argv.includes('--version'))console.log(${JSON.stringify(version)});else{console.log(JSON.stringify(process.argv.slice(2)));process.exitCode=${code};}`)
}
function run(path: string | undefined = scanner) {
  const env = { ...process.env }; delete env.CANSHIP_CLI
  if (path !== undefined) env.CANSHIP_CLI = path
  return spawnSync(process.execPath, [hook], { cwd: project, env, encoding: 'utf8', timeout: 15_000 })
}
test('preview is a cross-module Node script with fixed scanner arguments and no downloads', () => {
  const template = renderInit('pre-commit', '0.7.1')
  assert.match(template, /^#!\/usr\/bin\/env node\n/)
  assert.doesNotMatch(template, /npm |npx |shell: true|process\.env\.(?:NPM_TOKEN|NODE_AUTH_TOKEN)/)
  fakeScanner()
  for (const type of ['commonjs', 'module']) {
    writeFileSync(join(project, 'package.json'), JSON.stringify({ type }))
    const result = run()
    assert.equal(result.status, 0, result.stderr)
    assert.deepEqual(JSON.parse(result.stdout), ['.', '--all', '--no-config', '--no-ignore-markers', '--no-excerpts'])
    assert.match(result.stderr, /not the staged snapshot/)
  }
})
test('missing, relative and in-worktree scanners fail before executing a project file', () => {
  const dangerous = join(project, 'private-scanner.cjs')
  writeFileSync(dangerous, "require('node:fs').writeFileSync('EXECUTED', 'unexpected');")
  for (const path of ['', './private-scanner.cjs', dangerous, join(installed, 'PRIVATE_MISSING.cjs')]) {
    const result = run(path)
    assert.equal(result.status, 3)
    assert.doesNotMatch(result.stderr, /PRIVATE_MISSING|private-scanner/)
    assert.equal(existsSync(join(project, 'EXECUTED')), false)
  }
})
test('version mismatches fail closed and all scanner exit codes are preserved', () => {
  fakeScanner(0, '0.7.0')
  assert.equal(run().status, 3)
  for (const code of [0, 1, 2, 3, 130, 143]) {
    fakeScanner(code)
    assert.equal(run().status, code)
  }
})
test('Git invokes the reviewed hook and blocks a nonzero scan without changing user settings', () => {
  const executable = resolveGitExecutable(project); assert.ok(executable)
  const git = (...args: string[]) => execGitSync(executable, project, args)
  git('init')
  const hooks = join(project, '.git', 'hooks')
  const actualHook = join(hooks, 'pre-commit')
  writeFileSync(actualHook, renderInit('pre-commit', '0.7.1')); chmodSync(actualHook, 0o755)
  writeFileSync(join(project, 'index.ts'), 'export const ok=true;'); git('add', 'index.ts')
  // 仅为当前测试子进程传入配置，不写入仓库或系统环境。
  const env = { ...process.env, CANSHIP_CLI: scanner, GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }
  const args = ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', '-c', `core.hooksPath=${hooks}`, 'commit', '-m', 'hook fixture']
  fakeScanner(2)
  const blocked = spawnSync(executable, args, { cwd: project, env, encoding: 'utf8', timeout: 15_000 })
  assert.notEqual(blocked.status, 0)
  assert.match(blocked.stderr, /not the staged snapshot/)
  assert.throws(() => git('rev-parse', '--verify', 'HEAD'))
  fakeScanner(0)
  const accepted = spawnSync(executable, args, { cwd: project, env, encoding: 'utf8', timeout: 15_000 })
  assert.equal(accepted.status, 0, accepted.stderr)
  assert.match(git('rev-parse', '--verify', 'HEAD').trim(), /^[a-f0-9]{40}$/)
  assert.equal(readFileSync(actualHook, 'utf8'), renderInit('pre-commit', '0.7.1'))
})
