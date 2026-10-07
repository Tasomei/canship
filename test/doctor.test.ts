/** 环境诊断只读且独立于扫描；失败不回显项目内容或环境数据。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { diagnose } from '../src/doctor.js'
import { execGitSync, resolveGitExecutable } from '../src/git.js'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const parent = mkdtempSync(join(tmpdir(), 'canship-doctor-'))
let sequence = 0
after(() => rmSync(parent, { recursive: true, force: true }))
function project(config?: object): string {
  const root = join(parent, `project-${sequence++}`)
  mkdirSync(root)
  if (config) writeFileSync(join(root, 'canship.config.json'), JSON.stringify(config))
  return root
}
function run(root: string, args: string[] = [], env: NodeJS.ProcessEnv = process.env) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, '--doctor', ...args], {
    cwd: repository, env, encoding: 'utf8', timeout: 30_000,
  })
}
function report(root: string, args: string[] = [], env?: NodeJS.ProcessEnv) {
  const result = run(root, ['--json', ...args], env)
  assert.equal(result.stderr, '')
  assert.equal(result.error, undefined)
  const body = JSON.parse(result.stdout) as ReturnType<typeof diagnose>
  assert.equal(body.kind, 'doctor')
  assert.equal(body.scanPerformed, false)
  assert.equal(body.exitCode, result.status)
  assert.ok(!result.stdout.includes(root))
  return body
}
const check = (body: ReturnType<typeof diagnose>, id: string) => body.checks.find(item => item.id === id)!
function withoutGit(): NodeJS.ProcessEnv {
  const env = { ...process.env }
  for (const name of Object.keys(env)) if (name.toUpperCase() === 'PATH') delete env[name]
  env.PATH = ''
  return env
}
function baseline(root: string, version = 4, name = 'canship-baseline.json'): string {
  const path = join(root, name)
  writeFileSync(path, JSON.stringify({ version, generatedAt: '2026-01-01T00:00:00.000Z', entries: [] }))
  return path
}
function git(root: string, ...args: string[]): string {
  const executable = resolveGitExecutable(root)
  assert.ok(executable, 'A system Git installation is required for repository diagnostics tests')
  return execGitSync(executable, root, args, { stderr: 'pipe' })
}

test('an empty directory passes preflight without claiming scan coverage', () => {
  const root = project()
  const body = report(root)
  assert.equal(body.exitCode, 0)
  assert.equal(check(body, 'node').code, 'NODE_SUPPORTED')
  assert.equal(check(body, 'config').code, 'CONFIG_ABSENT')
  assert.equal(check(body, 'git').code, 'GIT_NOT_APPLICABLE')
  assert.equal(check(body, 'baseline').code, 'BASELINE_DISABLED')
  assert.equal('findings' in body, false)
  assert.match(run(root).stdout, /not that the project is safe or scan coverage is complete/)
  assert.deepEqual(readdirSync(root), [])
})

test('missing roots are structured failures, not empty scans', () => {
  const body = report(join(project(), 'missing'))
  assert.equal(body.exitCode, 3)
  assert.equal(check(body, 'root').code, 'SCAN_ROOT_UNAVAILABLE')
  assert.equal(check(body, 'git').status, 'skipped')
})

test('configuration errors retain line information without exposing values', () => {
  const root = project()
  writeFileSync(join(root, 'canship.config.json'), '{\n  "all": "PRIVATE_CONFIG_VALUE"\n}')
  const body = report(root)
  assert.equal(body.exitCode, 3)
  assert.equal(check(body, 'config').code, 'CONFIG_INVALID')
  assert.match(check(body, 'config').message, /line 2, column 3/)
  assert.ok(!JSON.stringify(body).includes('PRIVATE_CONFIG_VALUE'))
  assert.equal(check(body, 'baseline').status, 'skipped')
  assert.equal(report(root, ['--no-config']).exitCode, 0)
})

test('baseline paths honor CLI overrides, scan-root defaults and configuration containment', () => {
  const root = project({ baseline: '../outside.json' })
  const selected = baseline(root)
  assert.equal(check(report(root), 'baseline').code, 'BASELINE_INVALID')
  assert.equal(check(report(root, ['--baseline']), 'baseline').code, 'BASELINE_VALID')
  assert.equal(check(report(root, [`--baseline=${selected}`]), 'baseline').code, 'BASELINE_VALID')
  assert.equal(check(report(root, ['--no-config']), 'baseline').code, 'BASELINE_DISABLED')
})

test('legacy and invalid baselines are distinguished without outputting entries', () => {
  const root = project()
  baseline(root, 2)
  const legacy = report(root, ['--baseline'])
  assert.equal(legacy.exitCode, 0)
  assert.equal(check(legacy, 'baseline').code, 'BASELINE_LEGACY')
  assert.equal(check(legacy, 'baseline').status, 'warning')
  assert.match(check(legacy, 'baseline').message, /matching and stale entries require a scan/)
  writeFileSync(join(root, 'canship-baseline.json'), '{"version":"PRIVATE_BASELINE_VALUE"}')
  const invalid = report(root, ['--baseline'])
  assert.equal(invalid.exitCode, 3)
  assert.ok(!JSON.stringify(invalid).includes('PRIVATE_BASELINE_VALUE'))
})

test('configuration and baseline directories fail without being read as files', () => {
  const root = project()
  mkdirSync(join(root, 'canship.config.json'))
  assert.equal(check(report(root), 'config').code, 'CONFIG_INVALID')
  mkdirSync(join(root, 'canship-baseline.json'))
  assert.equal(check(report(root, ['--no-config', '--baseline']), 'baseline').code, 'BASELINE_INVALID')
})

test('missing Git is optional outside a repository and an error inside one', () => {
  const plain = report(project(), [], withoutGit())
  assert.equal(plain.exitCode, 0)
  assert.equal(check(plain, 'git').status, 'warning')
  const root = project()
  git(root, 'init')
  const repositoryReport = report(root, [], withoutGit())
  assert.equal(repositoryReport.exitCode, 3)
  assert.equal(check(repositoryReport, 'git').code, 'GIT_UNAVAILABLE')
})

test('local Git metadata and shallow history have distinct diagnoses', () => {
  const root = project()
  git(root, 'init')
  assert.equal(check(report(root), 'git').code, 'GIT_METADATA_READABLE')
  git(root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-m', 'fixture')
  writeFileSync(join(root, '.git', 'shallow'), git(root, 'rev-parse', 'HEAD').trim() + '\n')
  const shallow = report(root)
  assert.equal(shallow.exitCode, 0)
  assert.equal(check(shallow, 'git').code, 'GIT_SHALLOW')
  assert.equal(check(shallow, 'git').status, 'warning')
})

test('invalid and redirected Git metadata fail without echoing raw Git errors', () => {
  const root = project()
  mkdirSync(join(root, '.git'))
  assert.equal(check(report(root), 'git').code, 'GIT_CHECK_FAILED')
  const redirected = project()
  writeFileSync(join(redirected, '.git'), 'gitdir: ../PRIVATE_METADATA_PATH')
  const body = report(redirected)
  assert.equal(body.exitCode, 3)
  assert.equal(check(body, 'git').code, 'GIT_METADATA_UNSAFE')
  assert.ok(!JSON.stringify(body).includes('PRIVATE_METADATA_PATH'))
})

test('output preflight accepts new and owned destinations but never writes them', () => {
  const root = project()
  const html = join(root, 'owned.html')
  const original = '<!doctype html><html><head><title>canship report</title></head><body><script id="canship-data"></script></body></html>'
  writeFileSync(html, original)
  const sarif = join(root, 'new.sarif')
  const body = report(root, [`--report=${html}`, `--sarif=${sarif}`])
  assert.equal(body.exitCode, 0)
  assert.equal(check(body, 'html').code, 'OUTPUT_PREFLIGHT_OK')
  assert.equal(check(body, 'sarif').code, 'OUTPUT_PREFLIGHT_OK')
  assert.match(check(body, 'html').message, /actual write success is not guaranteed/)
  assert.deepEqual(readdirSync(root), ['owned.html'])
  assert.equal(readFileSync(html, 'utf8'), original)
})

test('unrelated, missing-parent, conflicting and linked output paths are refused', () => {
  const root = project()
  const source = join(root, 'source.ts')
  writeFileSync(source, 'PRIVATE_SOURCE_CONTENT')
  for (const target of [source, join(root, 'missing', 'report.html')]) {
    assert.equal(check(report(root, [`--report=${target}`]), 'html').code, 'OUTPUT_PATH_INVALID')
  }
  assert.equal(readFileSync(source, 'utf8'), 'PRIVATE_SOURCE_CONTENT')
  const target = join(root, 'report.json')
  assert.equal(check(report(root, [`--report=${target}`, `--sarif=${target}`]), 'sarif').code, 'OUTPUT_PATH_CONFLICT')
  const link = join(root, 'linked')
  symlinkSync(parent, link, process.platform === 'win32' ? 'junction' : 'dir')
  assert.equal(check(report(root, [`--report=${link}`]), 'html').code, 'OUTPUT_PATH_INVALID')
})

test('doctor cannot silently accept scan, write, or competing information modes', () => {
  const root = project()
  for (const flag of ['--all', '--best-effort', '--only=firebase', '--skip=cors', '--no-excerpts', '--no-ignore-markers',
    '--baseline-write', '--baseline-migrate', '--changed-since=HEAD', '--open', '--verbose', '--fix-prompt', '--list-rules', '--explain-config', '--build-info']) {
    const result = run(root, [flag])
    assert.equal(result.status, 3, flag)
    assert.match(result.stderr, /\[INVALID_ARGUMENT\]/)
    assert.equal(result.stdout, '')
  }
})

test('diagnosis makes no network calls, scans no source and writes no files', () => {
  const root = project({ baseline: 'canship-baseline.json' })
  baseline(root)
  writeFileSync(join(root, 'index.ts'), 'throw new Error("PROJECT_CODE_MUST_NOT_EXECUTE");')
  const before = readdirSync(root).map(name => [name, readFileSync(join(root, name), 'utf8')])
  const source = `
    import {diagnose} from './src/doctor.ts';
    import fs from 'node:fs';import cp from 'node:child_process';
    import http from 'node:http';import https from 'node:https';import net from 'node:net';import dns from 'node:dns';
    import {syncBuiltinESMExports} from 'node:module';import {join} from 'node:path';
    const root=process.argv[1];let denied=0;const deny=()=>{denied++;throw new Error('FORBIDDEN_DIAGNOSTIC_OPERATION')};
    const read=fs.readFileSync;fs.readFileSync=(file,...args)=>String(file)===join(root,'index.ts')?deny():read(file,...args);
    for(const name of ['readdirSync','writeFileSync','appendFileSync','renameSync','unlinkSync','mkdirSync','rmSync'])fs[name]=deny;
    for(const name of ['exec','execSync','execFile','spawn','spawnSync'])cp[name]=deny;
    const execute=cp.execFileSync;cp.execFileSync=(file,args,...rest)=>{
      if(!args.some(arg=>['--version','rev-parse'].includes(arg)))return deny();
      return execute(file,args,...rest);
    };
    globalThis.fetch=deny;http.request=deny;http.get=deny;https.request=deny;https.get=deny;net.connect=deny;net.createConnection=deny;dns.lookup=deny;
    syncBuiltinESMExports();
    const result=diagnose({root,noConfig:false,baseline:null,report:join(root,'new.html'),sarif:join(root,'new.sarif')});
    if(denied||result.exitCode!==0)process.exitCode=1;
    console.log(JSON.stringify({denied,exitCode:result.exitCode}));`
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source, root], {
    cwd: repository, encoding: 'utf8', timeout: 30_000,
  })
  assert.equal(result.status, 0, result.stderr + result.stdout)
  assert.deepEqual(JSON.parse(result.stdout), { denied: 0, exitCode: 0 })
  assert.deepEqual(readdirSync(root).map(name => [name, readFileSync(join(root, name), 'utf8')]), before)
})
