/** 工作区隔离、配置优先级、汇总退出码和只读边界。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { spawnSync } from 'node:child_process'
import { scan } from '../src/index.js'
import { buildBaseline } from '../src/baseline.js'
import { resolveWorkspaces, scanWorkspaces, WorkspaceError } from '../src/workspaces.js'
import type { WorkspaceOptions } from '../src/workspaces.js'
import { execGitSync, resolveGitExecutable } from '../src/git.js'
import { ScanCancelledError, ScanProgressError } from '../src/scan-control.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
function workspace() {
  const root = mkdtempSync(join(tmpdir(), 'canship-workspaces-')); roots.push(root)
  put(root, 'apps/first/index.ts', 'export const ok = true;')
  put(root, 'apps/second/index.ts', 'export const ok = true;')
  return root
}
function put(root: string, file: string, text: string) {
  mkdirSync(dirname(join(root, file)), { recursive: true }); writeFileSync(join(root, file), text)
}
const defaults: WorkspaceOptions = { all: false, noConfig: false, noExcerpts: true, noIgnoreMarkers: false,
  bestEffort: false, baselineDefault: false, only: [], skip: [], exclude: [] }
const selected = ['apps/first', 'apps/second']
const openRule = 'match /items/{id} { allow write: if true; }'
function cli(root: string, ...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, ...selected.map(p => `--workspace=${p}`), ...args],
    { encoding: 'utf8', timeout: 30_000 })
}

test('selection is explicit, literal, non-overlapping and rejects linked directory components', () => {
  const root = workspace()
  assert.deepEqual(resolveWorkspaces(root, selected).map(p => p.path), selected)
  for (const paths of [[], ['.'], ['../outside'], ['/absolute'], ['apps/*'], Array(33).fill('apps/first'),
    ['apps/first', 'apps/first/'], ['apps', 'apps/first'], ['apps/first', 'apps'], ['missing'], ['apps/first/index.ts']]) {
    assert.throws(() => resolveWorkspaces(root, paths), WorkspaceError)
  }
  if (process.platform === 'win32') assert.throws(() => resolveWorkspaces(root, ['apps/first', 'apps/FIRST']), WorkspaceError)
  symlinkSync(join(root, 'apps'), join(root, 'linked'), process.platform === 'win32' ? 'junction' : 'dir')
  assert.throws(() => resolveWorkspaces(root, ['linked/first']), WorkspaceError)
  put(root, 'apps/中文 空格/index.ts', 'export const ok=true;')
  assert.equal(resolveWorkspaces(root, ['apps\\中文 空格/'])[0]!.path, 'apps/中文 空格')
})

test('parent configuration and unselected sources are not read as project inputs', async () => {
  const root = workspace()
  put(root, 'canship.config.json', 'PRIVATE_INVALID_PARENT_CONFIG')
  put(root, 'firestore.rules', openRule)
  const result = await scanWorkspaces(root, selected, defaults)
  assert.equal(result.exitCode, 0)
  assert.equal(result.partial, false)
  assert.equal(result.counts.projects, 2)
  assert.equal(result.counts.findings, 0)
  assert.ok(result.projects.every(p => p.report?.filesScanned === 1 && p.config?.status === 'absent'))
  assert.ok(!JSON.stringify(result).includes(root))
  assert.match(result.scope, /Only explicitly selected/)
})

test('configuration selection and CLI overrides stay independent for each project', async () => {
  const root = workspace()
  for (const path of selected) put(root, `${path}/firestore.rules`, openRule)
  put(root, 'apps/first/canship.config.json', JSON.stringify({ only: ['cors'], exclude: ['index.ts'] }))
  const result = await scanWorkspaces(root, selected, defaults)
  assert.equal(result.projects[0]!.exitCode, 0)
  assert.equal(result.projects[1]!.exitCode, 1)
  assert.deepEqual(result.projects[0]!.config?.sources, { all: 'default', rules: 'config', exclude: 'config', baseline: 'default' })
  assert.equal(result.projects[1]!.config?.sources.rules, 'default')
  const overridden = await scanWorkspaces(root, selected, { ...defaults, only: ['firebase'], exclude: ['absent'] })
  assert.ok(overridden.projects.every(p => p.exitCode === 1 && p.config?.sources.rules === 'cli' && p.config.sources.exclude === 'cli'))
  const ignored = await scanWorkspaces(root, selected, { ...defaults, noConfig: true })
  assert.ok(ignored.projects.every(p => p.exitCode === 1 && p.config?.status === 'disabled'))
})

test('one invalid config does not drop the other project or echo private diagnostic values', async () => {
  const root = workspace()
  put(root, 'apps/first/canship.config.json', JSON.stringify({ PRIVATE_UNKNOWN_SETTING: 'PRIVATE_CONTENT' }))
  put(root, 'apps/second/firestore.rules', openRule)
  const result = await scanWorkspaces(root, selected, defaults)
  assert.equal(result.exitCode, 3)
  assert.equal(result.partial, true)
  assert.equal(result.counts.failed, 1)
  assert.equal(result.counts.blocking, 1)
  assert.equal(result.projects[0]!.error?.code, 'CONFIG_INVALID')
  assert.equal(result.projects[1]!.exitCode, 1)
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_/)
})

test('hidden likely results and incomplete scans retain independent scope and policy', async () => {
  const root = workspace()
  put(root, 'apps/first/firestore.rules', 'match /items/{id} { allow read: if true; }')
  put(root, 'apps/second/large.ts', ' '.repeat(2 * 1024 * 1024 + 1))
  const result = await scanWorkspaces(root, selected, defaults)
  assert.equal(result.exitCode, 2)
  assert.equal(result.partial, true)
  assert.equal(result.counts.hiddenLikely, 1)
  assert.equal(result.counts.findings, 1)
  assert.equal(result.projects[0]!.report?.findings.length, 0)
  const accepted = await scanWorkspaces(root, selected, { ...defaults, bestEffort: true })
  assert.equal(accepted.exitCode, 2)
  assert.equal(accepted.projects[1]!.exitCode, 0)
  assert.equal(accepted.partial, true)
})

test('baseline decisions apply only inside their own workspace and cannot reach siblings', async () => {
  const root = workspace()
  for (const path of selected) put(root, `${path}/firestore.rules`, openRule)
  const baseline = JSON.stringify(buildBaseline((await scan(join(root, 'apps/first'))).findings))
  put(root, 'apps/first/canship-baseline.json', baseline)
  put(root, 'apps/first/canship.config.json', JSON.stringify({ baseline: 'canship-baseline.json' }))
  const result = await scanWorkspaces(root, selected, defaults)
  assert.equal(result.projects[0]!.report?.baselineSuppressed, 1)
  assert.equal(result.projects[0]!.exitCode, 0)
  assert.equal(result.projects[1]!.exitCode, 1)
  assert.equal(readFileSync(join(root, 'apps/first/canship-baseline.json'), 'utf8'), baseline)
  put(root, 'apps/second/canship.config.json', JSON.stringify({ baseline: '../first/canship-baseline.json' }))
  const invalid = await scanWorkspaces(root, selected, defaults)
  assert.equal(invalid.projects[1]!.error?.code, 'BASELINE_INVALID')
  assert.equal(invalid.exitCode, 3)
})

test('middleware from a sibling app never protects an unguarded route', async () => {
  const root = workspace()
  const route = `import {createClient} from '@supabase/supabase-js';
const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);
export async function DELETE(){await db.from('items').delete();return new Response('ok');}`
  for (const path of selected) put(root, `${path}/app/api/items/route.ts`, route)
  put(root, 'apps/first/middleware.ts', `export function middleware(req){if(!req.user)return new Response(null,{status:401});}
export const config={matcher:['/api/:path*']};`)
  const result = await scanWorkspaces(root, selected, { ...defaults, all: true })
  assert.equal(result.projects[0]!.report?.findings.filter(f => f.ruleId.startsWith('api/')).length, 0)
  assert.ok(result.projects[1]!.report?.findings.some(f => f.ruleId.startsWith('api/')))
})

test('local Git environment history is scoped to each selected directory', async () => {
  const root = workspace(), executable = resolveGitExecutable(root); assert.ok(executable)
  const git = (...args: string[]) => execGitSync(executable, root, args)
  const simulatedKey = ['sk', 'proj', 'Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s'].join('-')
  git('init'); put(root, 'apps/first/.env', 'KEY=' + simulatedKey)
  git('add', 'apps/first/.env')
  git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'workspace fixture')
  const result = await scanWorkspaces(root, selected, { ...defaults, all: true })
  assert.ok(result.projects[0]!.report?.findings.some(f => f.ruleId === 'gitleak/env-tracked'), JSON.stringify(result.projects[0]))
  assert.equal(result.projects[1]!.report?.findings.length, 0)
})

test('cancellation and progress errors abort the whole operation instead of becoming partial success', async () => {
  for (const error of [new ScanCancelledError(), new ScanProgressError(new Error('PRIVATE_CALLBACK'))]) {
    let calls = 0
    await assert.rejects(scanWorkspaces(workspace(), selected, defaults, async () => { calls++; throw error }), error.constructor)
    assert.equal(calls, 1)
  }
})

test('CLI supports isolated JSON and context-preserving single-project followups', () => {
  const root = workspace(); put(root, 'apps/second/firestore.rules', openRule)
  const output = cli(root, '--json', '--no-excerpts')
  assert.equal(output.status, 1, output.stderr)
  const report = JSON.parse(output.stdout)
  assert.equal(report.kind, 'workspace-report')
  assert.equal(report.projects.length, 2)
  assert.equal(report.projects[1].report.findings[0].excerpt, null)
  const terminal = cli(root, '--no-excerpts')
  assert.match(terminal.stdout, /Workspace: apps\/first/)
  assert.match(terminal.stdout, /Workspace: apps\/second/)
  assert.ok(terminal.stdout.includes(join(root, 'apps', 'second')))
  assert.match(terminal.stdout, /--no-excerpts/)
  assert.doesNotMatch(terminal.stdout, /--workspace=/)
})

test('CLI refuses ambiguous global outputs, other modes and invalid selectors before scanning', () => {
  const root = workspace()
  for (const option of ['--report', '--sarif', '--baseline-write', '--baseline=outside.json', '--explain-config', '--doctor',
    '--compare=old.json', '--init', '--changed-since=HEAD', '--share-summary', '--only=missing-rule', '--fix-prompt']) {
    const result = cli(root, option)
    assert.equal(result.status, 3, option)
    assert.equal(result.stdout, '', option)
    assert.match(result.stderr, /\[INVALID_ARGUMENT\]/)
  }
})
