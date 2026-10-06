/** 配置预览复用扫描优先级，且不扫描源码或写入结果。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { RULE_CATALOG } from '../src/rules/catalog.js'
import { explainConfig, renderConfigExplanation } from '../src/report/config.js'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const parent = mkdtempSync(join(tmpdir(), 'canship-explain-config-'))
let sequence = 0
after(() => rmSync(parent, { recursive: true, force: true }))

function project(config?: object | string): string {
  const root = join(parent, `project-${sequence++}`)
  mkdirSync(root)
  if (config !== undefined) writeFileSync(join(root, 'canship.config.json'), typeof config === 'string' ? config : JSON.stringify(config))
  return root
}

function cli(root: string, ...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, ...args], {
    cwd: repository, encoding: 'utf8', timeout: 30_000,
  })
}

function preview(root: string, ...args: string[]) {
  const result = cli(root, '--explain-config', '--json', ...args)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stderr, '')
  return JSON.parse(result.stdout) as ReturnType<typeof explainConfig>
}

test('an empty project can explain defaults without claiming a completed scan', () => {
  const root = project()
  const result = preview(root)
  assert.equal(result.kind, 'effective-config')
  assert.equal(result.schemaVersion, 1)
  assert.equal(result.scanPerformed, false)
  assert.deepEqual(result.config, { status: 'absent', path: null })
  assert.equal(result.rules.source, 'default')
  assert.deepEqual(result.rules.enabled, RULE_CATALOG.map(rule => rule.id))
  assert.deepEqual(result.rules.excluded, [])
  assert.deepEqual(result.settings.all, { value: false, source: 'default' })
  assert.deepEqual(result.settings.baseline, { value: null, source: 'default' })
  assert.equal('findings' in result, false)
  assert.equal('partial' in result, false)
  assert.equal(cli(root, '--json').status, 3)
})

test('configuration sources and resolved baseline paths are disclosed without reading a baseline', () => {
  const root = project({ only: ['firebase'], all: true, baseline: 'missing.json' })
  const result = preview(root)
  assert.deepEqual(result.config, { status: 'loaded', path: join(root, 'canship.config.json') })
  assert.equal(result.rules.source, 'config')
  assert.deepEqual(result.rules.enabled, ['firebase/open-rules', 'firebase/test-mode-rules'])
  assert.deepEqual(result.settings.all, { value: true, source: 'config' })
  assert.deepEqual(result.settings.baseline, { value: join(root, 'missing.json'), source: 'config' })
  assert.ok(result.warnings.some(warning => warning.includes('validity have not been checked')))
  assert.equal(cli(root, '--json').status, 3)
})

test('CLI overrides the whole rule selection group, with deduplicated displayed selectors', () => {
  const root = project({ only: ['firebase'], all: false, baseline: 'old.json' })
  const result = preview(root, '--skip=cors', '--skip=cors', '--all', '--baseline=new.json',
    '--no-ignore-markers', '--no-excerpts', '--best-effort')
  assert.equal(result.rules.source, 'cli')
  assert.deepEqual(result.rules.only, [])
  assert.deepEqual(result.rules.skip, ['cors'])
  assert.deepEqual(result.rules.excluded, ['cors/reflected-origin-with-credentials', 'cors/wildcard-with-credentials'])
  assert.ok(result.rules.enabled.includes('firebase/open-rules'))
  assert.deepEqual(result.settings.all, { value: true, source: 'cli' })
  assert.deepEqual(result.settings.baseline, { value: join(repository, 'new.json'), source: 'cli' })
  assert.deepEqual(result.settings.honorIgnoreMarkers, { value: false, source: 'cli' })
  assert.deepEqual(result.settings.noExcerpts, { value: true, source: 'cli' })
  assert.deepEqual(result.settings.bestEffort, { value: true, source: 'cli' })
  assert.ok(result.warnings.some(warning => warning.includes('findings still exit 1 or 2')))
})

test('bare baseline paths use the scan root and explicit configuration false values keep their source', () => {
  const root = project({ all: false, skip: [] })
  const result = preview(root, '--baseline')
  assert.deepEqual(result.settings.baseline, { value: join(root, 'canship-baseline.json'), source: 'cli' })
  assert.deepEqual(result.settings.all, { value: false, source: 'config' })
  assert.equal(result.rules.source, 'config')
})

test('invalid config is rejected but no-config bypasses it without claiming absence', () => {
  const root = project('{broken')
  const failed = cli(root, '--explain-config', '--json')
  assert.equal(failed.status, 3)
  assert.match(failed.stderr, /\[CONFIG_INVALID\]/)
  assert.equal(failed.stdout, '')
  assert.deepEqual(preview(root, '--no-config').config, { status: 'disabled', path: null })
})

test('unavailable roots and invalid selectors fail instead of generating a preview', () => {
  const root = project()
  assert.match(cli(join(root, 'missing'), '--explain-config').stderr, /\[SCAN_ROOT_UNAVAILABLE\]/)
  for (const args of [['--only=unknown'], ['--only=cors', '--skip=firebase']]) {
    const result = cli(root, '--explain-config', ...args)
    assert.equal(result.status, 3)
    assert.match(result.stderr, /\[INVALID_ARGUMENT\]/)
    assert.equal(result.stdout, '')
  }
})

test('configured baseline containment is enforced in preview as in scanning', () => {
  const root = project({ baseline: '../outside.json' })
  for (const args of [['--explain-config'], ['--json']]) {
    const result = cli(root, ...args)
    assert.equal(result.status, 3)
    assert.match(result.stderr, /must stay inside the project/)
  }
})

test('enabled and excluded rule IDs agree with actual selected findings', () => {
  const root = project({ only: ['firebase'] })
  writeFileSync(join(root, 'firestore.rules'), 'match /items/{id} { allow write: if true; }')
  writeFileSync(join(root, 'cors.ts'), 'app.use(cors({origin:true,credentials:true}));')
  for (const flags of [[], ['--skip=firebase'], ['--only=cors'], ['--no-config']]) {
    const explanation = preview(root, ...flags)
    const scan = cli(root, '--json', '--all', ...flags)
    assert.equal(scan.status, 1)
    const findings = JSON.parse(scan.stdout).findings as Array<{ ruleId: string }>
    assert.ok(findings.length > 0)
    for (const finding of findings) {
      assert.ok(explanation.rules.enabled.includes(finding.ruleId))
      assert.ok(!explanation.rules.excluded.includes(finding.ruleId))
    }
    const expected = flags[0] === '--no-config' ? ['firebase/open-rules', 'cors/reflected-origin-with-credentials']
      : flags.length === 0 ? ['firebase/open-rules'] : ['cors/reflected-origin-with-credentials']
    assert.deepEqual(findings.map(finding => finding.ruleId).sort(), expected.sort())
  }
})

test('non-reporting public identifiers are distinguished from finding-producing rules', () => {
  const result = preview(project(), '--only=secrets/hardcoded/google-api-key')
  assert.deepEqual(result.rules.nonReporting, ['secrets/hardcoded/google-api-key'])
  assert.ok(result.warnings.includes('No finding-producing rules are enabled.'))
  assert.match(renderConfigExplanation(result), /public identifier; not reported/)
})

test('terminal explanation shows sources and does not present a clean-scan verdict', () => {
  const result = cli(project({ skip: ['firebase'] }), '--explain-config')
  assert.equal(result.status, 0)
  assert.match(result.stdout, /No scan performed/)
  assert.match(result.stdout, /Rules \[config\]/)
  assert.match(result.stdout, /- firebase\/open-rules/)
  assert.match(result.stdout, /Likely findings are hidden, but still affect scan status/)
  assert.match(result.stdout, /Paths remain visible/)
  assert.doesNotMatch(result.stdout, /No findings in enabled checks/)
})

test('incompatible modes are rejected before any output file or Git operation', () => {
  const root = project()
  for (const flag of ['--report', '--sarif', '--baseline-write', '--baseline-migrate', '--fix-prompt',
    '--list-rules', '--build-info', '--changed-since=HEAD', '--open', '--verbose']) {
    const result = cli(root, '--explain-config', flag)
    assert.equal(result.status, 3, flag)
    assert.match(result.stderr, /\[INVALID_ARGUMENT\]/)
    assert.equal(result.stdout, '')
  }
  assert.deepEqual(readdirSync(root), [])
})

test('all displayed paths redact recognised credentials and control characters', () => {
  const token = ['sk', 'proj', 'Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s'].join('-')
  const path = `/${token}/\u001b[31mfile`
  const result = explainConfig({
    root: path, configPath: path, configDisabled: false, only: [], skip: [], ruleSource: 'default',
    settings: {
      all: { value: false, source: 'default' }, baseline: { value: path, source: 'cli' },
      honorIgnoreMarkers: { value: true, source: 'default' }, noExcerpts: { value: false, source: 'default' },
      bestEffort: { value: false, source: 'default' },
    },
  })
  for (const text of [JSON.stringify(result), renderConfigExplanation(result)]) {
    assert.ok(!text.includes(token))
    assert.ok(!text.includes('\u001b'))
    assert.ok(!text.includes('\\u001b'))
  }
})

test('preview reads configuration but neither enumerates project files nor starts subprocesses', () => {
  const root = project({ baseline: 'baseline.json' })
  writeFileSync(join(root, 'baseline.json'), '{invalid')
  writeFileSync(join(root, 'index.ts'), 'throw new Error("SOURCE_MUST_NOT_EXECUTE");')
  const before = readdirSync(root).map(name => [name, readFileSync(join(root, name), 'utf8')])
  const source = `
    import './src/report/config.ts';
    import fs from 'node:fs';import cp from 'node:child_process';
    import {syncBuiltinESMExports} from 'node:module';import {resolve,relative} from 'node:path';
    const root=process.argv[1];let denied=0;
    const deny=()=>{denied++;throw new Error('UNEXPECTED_PROJECT_ACCESS')};
    const originalRead=fs.readFileSync;
    fs.readFileSync=(file,...args)=>{
      const path=String(file);const local=relative(root,resolve(path));
      if(!local.startsWith('..')&&!local.includes(':')&&local!=='canship.config.json')return deny();
      return originalRead(file,...args);
    };
    for(const name of ['readdirSync','writeFileSync','appendFileSync','renameSync','unlinkSync'])fs[name]=deny;
    for(const name of ['exec','execSync','execFile','execFileSync','spawn','spawnSync'])cp[name]=deny;
    syncBuiltinESMExports();
    process.argv=[process.execPath,'src/cli.ts',root,'--explain-config','--json'];
    await import('./src/cli.ts');
    if(denied)process.exitCode=1;
  `
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source, root], {
    cwd: repository, encoding: 'utf8', timeout: 30_000,
  })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(JSON.parse(result.stdout).kind, 'effective-config')
  assert.deepEqual(readdirSync(root).map(name => [name, readFileSync(join(root, name), 'utf8')]), before)
})
