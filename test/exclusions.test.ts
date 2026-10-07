/** 路径排除必须在内容读取前生效，并在所有输出中披露。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { Ajv } from 'ajv'
import { scan } from '../src/index.js'
import { createExclusions, EXCLUSION_PATH_PATTERN, isExclusionPath } from '../src/exclusions.js'
import { parseConfig } from '../src/config.js'
import { renderHtml } from '../src/report/html.js'
import { execGitSync, resolveGitExecutable } from '../src/git.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
function project(): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-exclude-')); roots.push(root)
  writeFileSync(join(root, 'index.ts'), 'export const ok=true;')
  return root
}
function cli(root: string, ...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, ...args], { encoding: 'utf8', timeout: 30_000 })
}
const schema = JSON.parse(readFileSync(new URL('../schemas/config-v1.schema.json', import.meta.url), 'utf8'))
const validate = new Ajv().compile(schema)

test('literal matching is bounded, separator-aware and case-sensitive', () => {
  const paths = createExclusions(['generated/', 'generated', 'test fixtures\\private'])
  assert.deepEqual(paths.requested, ['generated', 'test fixtures/private'])
  assert.equal(paths.matches('generated/nested/file.ts'), true)
  assert.equal(paths.matches('generated-more/file.ts'), false)
  assert.equal(paths.matches('Generated/file.ts'), false)
  assert.equal(paths.matches('test fixtures/private/a.ts'), true)
  assert.deepEqual(paths.matched(), ['generated', 'test fixtures/private'])
  assert.equal(schema.properties.exclude.items.pattern, EXCLUSION_PATH_PATTERN)
})

test('schema and runtime reject ambiguous paths rather than guessing glob or traversal semantics', async () => {
  for (const path of ['', '.', '..', '../outside', 'a/../b', '/absolute', 'C:\\outside', '\\\\server\\share',
    'a//b', 'a/./b', 'a/*', '**/test', '!keep', 'a?b', 'a[b]', ' leading', 'trailing ', 'a /b', 'a\nb',
    'a\u2028b/../outside', 'a\u2029b:*', 'x'.repeat(513)]) {
    assert.equal(isExclusionPath(path), false, path)
    assert.equal(validate({ exclude: [path] }), false, path)
    assert.throws(() => parseConfig(JSON.stringify({ exclude: [path] }), 'config'))
    await assert.rejects(scan(project(), { exclude: [path] }), TypeError)
  }
  for (const path of ['.env', 'test fixtures/', 'src/生成目录', 'a\\b']) {
    assert.equal(validate({ exclude: [path] }), true, path)
    assert.deepEqual(parseConfig(JSON.stringify({ exclude: [path] }), 'config').exclude, [path])
  }
  assert.equal(validate({ exclude: Array(65).fill('a') }), false)
})

test('excluded directories, oversized inputs and links are not scanned or marked as accidental gaps', async () => {
  const root = project(); mkdirSync(join(root, 'private'))
  writeFileSync(join(root, 'private', 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  writeFileSync(join(root, 'private', 'large.ts'), ' '.repeat(2 * 1024 * 1024 + 1))
  symlinkSync(root, join(root, 'private', 'loop'), process.platform === 'win32' ? 'junction' : 'dir')
  const result = await scan(root, { exclude: ['private/'] })
  assert.equal(result.filesScanned, 1)
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings, [])
  assert.deepEqual(result.exclusions, { requested: ['private'], matched: ['private'] })
})

test('excluding every source file remains a zero-file incomplete scan with disclosed exclusions', async () => {
  const root = project()
  const result = await scan(root, { exclude: ['index.ts'] })
  assert.equal(result.filesScanned, 0)
  assert.equal(result.partial, true)
  const terminal = cli(root, '--exclude=index.ts')
  assert.equal(terminal.status, 3)
  assert.match(terminal.stdout, /Path exclusions in force: index.ts/)
})

test('CLI exclusion lists override config, and no-config disables project-provided exclusions', () => {
  const root = project()
  writeFileSync(join(root, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  writeFileSync(join(root, 'canship.config.json'), JSON.stringify({ exclude: ['firestore.rules'] }))
  assert.equal(cli(root, '--json').status, 0)
  assert.equal(cli(root, '--json', '--no-config').status, 1)
  assert.equal(cli(root, '--json', '--exclude=index.ts').status, 1)
  const preview = JSON.parse(cli(root, '--explain-config', '--exclude=other/','--json').stdout)
  assert.deepEqual(preview.exclusions, { source: 'cli', paths: ['other'] })
  assert.equal(cli(root, '--baseline-prune').status, 3)
})

test('HTML, JSON, SARIF, prompts and share summaries retain scope without reading excluded content', () => {
  const root = project()
  writeFileSync(join(root, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  const html = join(root, 'report.html'); const sarif = join(root, 'report.sarif')
  const report = cli(root, '--exclude=firestore.rules', '--json', `--report=${html}`, `--sarif=${sarif}`)
  assert.equal(report.status, 0, report.stderr)
  assert.deepEqual(JSON.parse(report.stdout).exclusions.matched, ['firestore.rules'])
  for (const output of [readFileSync(html, 'utf8'), readFileSync(sarif, 'utf8'), cli(root, '--exclude=firestore.rules', '--fix-prompt').stdout]) {
    assert.match(output, /[Pp]ath exclusions/)
    assert.match(output, /firestore.rules/)
  }
  const summary = JSON.parse(cli(root, '--exclude=firestore.rules', '--share-summary', '--json').stdout)
  assert.equal(summary.scope.pathsRestricted, true)
  assert.equal(summary.counts.excludedPaths, 1)
  assert.ok(!JSON.stringify(summary).includes('firestore.rules'))
})

test('excluded current and deleted env paths never produce Git findings', async () => {
  const root = project(); const executable = resolveGitExecutable(root); assert.ok(executable)
  const git = (...args: string[]) => execGitSync(executable, root, args)
  git('init')
  const token = ['sk', 'proj', 'Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s'].join('-')
  writeFileSync(join(root, '.env.private'), 'KEY=' + token)
  git('add', '.env.private'); git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture')
  assert.ok((await scan(root)).findings.some(finding => finding.ruleId === 'gitleak/env-tracked'))
  assert.deepEqual((await scan(root, { exclude: ['.env.private'] })).findings, [])
  git('rm', '.env.private'); git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'remove fixture')
  assert.ok((await scan(root)).findings.some(finding => finding.ruleId === 'gitleak/env-in-history'))
  const result = await scan(root, { exclude: ['.env.private'] })
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings, [])
  assert.deepEqual(result.exclusions?.matched, ['.env.private'])
  const code = `
    import {scan} from './src/index.ts';import cp from 'node:child_process';import {syncBuiltinESMExports} from 'node:module';
    let objects=0;const execute=cp.execFileSync;cp.execFileSync=(file,args,...rest)=>{
      if(args.includes('cat-file')){objects++;throw new Error('EXCLUDED_HISTORY_READ')}return execute(file,args,...rest)};
    syncBuiltinESMExports();const result=await scan(process.argv[1],{exclude:['.env.private']});
    console.log(JSON.stringify({objects,partial:result.partial}));if(objects||result.partial)process.exitCode=1;`
  const checked = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code, root], { encoding: 'utf8', timeout: 30_000 })
  assert.equal(checked.status, 0, checked.stderr)
  assert.deepEqual(JSON.parse(checked.stdout), { objects: 0, partial: false })
})

test('excluded source content is never opened, including probe candidates', () => {
  const root = project(); mkdirSync(join(root, 'private'))
  writeFileSync(join(root, 'private', 'unknown-file'), 'PRIVATE_CONTENT')
  const code = `
    import {scan} from './src/index.ts';import fs from 'node:fs';import {join} from 'node:path';import {syncBuiltinESMExports} from 'node:module';
    const root=process.argv[1],target=join(root,'private','unknown-file');let reads=0;
    for(const method of ['openSync','readFileSync']){const original=fs[method];fs[method]=(path,...args)=>{if(String(path)===target){reads++;throw new Error('EXCLUDED_CONTENT_READ')}return original(path,...args)}}
    syncBuiltinESMExports();const result=await scan(root,{exclude:['private']});
    console.log(JSON.stringify({reads,partial:result.partial}));if(reads||result.partial)process.exitCode=1;`
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code, root], { encoding: 'utf8', timeout: 30_000 })
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(JSON.parse(result.stdout), { reads: 0, partial: false })
})

test('copied HTML fix prompts retain exclusion scope as well as the visible report', async () => {
  const root = project()
  writeFileSync(join(root, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  writeFileSync(join(root, 'cors.ts'), 'app.use(cors({origin:true,credentials:true}));')
  const result = await scan(root, { exclude: ['firestore.rules'] })
  assert.ok(result.findings.length > 0)
  const html = renderHtml(result, { root: 'sample', generatedAt: '' })
  const data = JSON.parse(/<script type="application\/json" id="canship-data">([\s\S]*?)<\/script>/.exec(html)![1]!)
  assert.match(data.prompts.all, /explicit path exclusions were active: firestore.rules/)
  assert.match(data.prompts['1'], /explicit path exclusions were active: firestore.rules/)
})
