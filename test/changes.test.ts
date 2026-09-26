/** 验证变更视图保留全项目判定，不把隐藏结果或比较失败当成通过。 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFileSync, spawnSync } from 'node:child_process'
import { Ajv } from 'ajv'
import { changedFilesSince } from '../src/changes.js'
import { summarize } from '../src/index.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const openCors = 'app.use(cors({ origin: true, credentials: true }));'
function git(root: string, ...args: string[]): string {
  return execFileSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.com',
    '-c', 'core.hooksPath=', '-c', 'commit.gpgsign=false', ...args], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
}
function write(root: string, file: string, content: string): void {
  mkdirSync(dirname(join(root, file)), { recursive: true })
  writeFileSync(join(root, file), content)
}
function project(files: Record<string, string> = { 'old.ts': openCors }): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-changes-')); roots.push(root)
  for (const [path, content] of Object.entries(files)) write(root, path, content)
  git(root, 'init', '-q'); git(root, 'add', '.'); git(root, 'commit', '-qm', 'base')
  return root
}
function cli(root: string, ...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', join(repository, 'src/cli.ts'), root, ...args],
    { cwd: repository, encoding: 'utf8', timeout: 30_000 })
}

test('hidden unchanged findings keep their exit code in every format', () => {
  const root = project()
  write(root, 'new.ts', 'export const ok = true')
  const html = join(root, 'out.html'); const sarif = join(root, 'out.sarif')
  const output = cli(root, '--changed-since=HEAD', '--json', `--report=${html}`, `--sarif=${sarif}`)
  assert.equal(output.status, 1, output.stderr)
  const report = JSON.parse(output.stdout)
  assert.equal(report.partial, false)
  assert.equal(report.findings.length, 0)
  assert.equal(report.changeView.hiddenFindings, 1)
  assert.equal(report.changeView.totalBlocking, 1)
  assert.equal(summarize(report).exitCode, 1)
  const schema = JSON.parse(readFileSync(join(repository, 'schemas/scan-report-v1.schema.json'), 'utf8'))
  const validate = new Ajv().compile(schema)
  assert.equal(validate(report), true, JSON.stringify(validate.errors))
  for (const text of [readFileSync(html, 'utf8'), readFileSync(sarif, 'utf8'),
    cli(root, '--changed-since=HEAD').stdout, cli(root, '--changed-since=HEAD', '--fix-prompt').stdout]) {
    assert.match(text, /Changed-file view/)
    assert.doesNotMatch(text, /No exposed credentials found|Nothing to fix/)
  }
  assert.equal(cli(root, '--changed-since=HEAD', '--best-effort').status, 1)
})

test('working tree, staged, committed and untracked changes are included', () => {
  const root = project({ 'base.ts': 'export const ok = true' })
  const base = git(root, 'rev-parse', 'HEAD')
  write(root, 'committed.ts', openCors); git(root, 'add', '.'); git(root, 'commit', '-qm', 'change')
  write(root, 'staged.ts', openCors); git(root, 'add', 'staged.ts')
  write(root, 'base.ts', openCors); write(root, 'new space ü.ts', openCors)
  const result = cli(root, `--changed-since=${base}`, '--json')
  assert.equal(result.status, 1, result.stderr)
  assert.equal(JSON.parse(result.stdout).findings.length, 4)
})

test('a changed dependency retains a finding in an unchanged route', () => {
  const root = project({
    'app/api/data/route.ts': "import { db } from '../../../lib/admin'; export async function GET(){return db.from('items').select('*')}",
    'lib/admin.ts': "import { createClient } from '@supabase/supabase-js'; export const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);",
  })
  write(root, 'lib/admin.ts', readFileSync(join(root, 'lib/admin.ts'), 'utf8') + '\n// changed')
  const result = cli(root, '--changed-since=HEAD', '--json')
  assert.equal(result.status, 1, result.stderr)
  assert.equal(JSON.parse(result.stdout).findings[0].file, 'app/api/data/route.ts')
})

test('comparison uses the merge base and paths stay relative to a scanned subdirectory', () => {
  const root = project({ 'apps/web/a.ts': 'export const ok = true' })
  const branch = git(root, 'symbolic-ref', '--short', 'HEAD')
  git(root, 'checkout', '-qb', 'target'); write(root, 'target-only.ts', openCors)
  git(root, 'add', '.'); git(root, 'commit', '-qm', 'target change'); git(root, 'checkout', branch)
  write(root, 'apps/web/a.ts', openCors)
  const changed = changedFilesSince(join(root, 'apps/web'), 'target')
  assert.deepEqual([...changed.paths], ['a.ts'])
})

test('invalid references and incompatible write modes fail without writing a baseline', () => {
  const root = project()
  for (const args of [['--changed-since=missing'], ['--changed-since='], ['--changed-since=HEAD', '--baseline-write'],
    ['--changed-since=HEAD', '--changed-since=HEAD'], ['--changed-since=HEAD', '--list-rules']]) {
    assert.equal(cli(root, ...args).status, 3)
  }
  assert.equal(existsSync(join(root, 'canship-baseline.json')), false)
  const plain = mkdtempSync(join(tmpdir(), 'canship-no-git-')); roots.push(plain)
  write(plain, 'index.ts', 'export const ok = true')
  assert.equal(cli(plain, '--changed-since=HEAD').status, 3)
})

test('renames use the current path and deleted files do not create false results', () => {
  const root = project({ 'old.ts': openCors, 'keep.ts': 'export const ok = true' })
  git(root, 'mv', 'old.ts', 'renamed.ts')
  const renamed = cli(root, '--changed-since=HEAD', '--json')
  assert.equal(renamed.status, 1)
  assert.equal(JSON.parse(renamed.stdout).findings[0].file, 'renamed.ts')
  rmSync(join(root, 'renamed.ts'))
  assert.equal(cli(root, '--changed-since=HEAD', '--json').status, 0)
})

test('likely findings and incomplete coverage survive display filtering', () => {
  const root = project({ 'firestore.rules': 'match /items/{id} { allow read: if true; }' })
  const hidden = cli(root, '--changed-since=HEAD', '--all', '--json')
  assert.equal(hidden.status, 2)
  assert.equal(JSON.parse(hidden.stdout).changeView.totalLikely, 1)
  assert.deepEqual(JSON.parse(hidden.stdout).findings, [])
  const partial = project({ 'index.ts': 'export const ok = true' })
  write(partial, 'large.ts', ' '.repeat(2 * 1024 * 1024 + 1))
  const result = cli(partial, '--changed-since=HEAD', '--json')
  assert.equal(result.status, 3)
  assert.equal(JSON.parse(result.stdout).partial, true)
  assert.equal(cli(partial, '--changed-since=missing', '--best-effort').status, 3)
})
