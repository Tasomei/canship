/** 验证 CI 契约、输入边界和不完整扫描判定。
 * canship-ignore-file */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { ActionError, assessReport, describeActionError, parseInputs, rebaseSarif, runAction } from '../action/run.mjs'
import { createJsonReport } from '../src/report/json.js'
import type { Finding, ScanResult } from '../src/types.js'
import { scan } from '../src/engine.js'
import { buildBaseline, serializeBaseline } from '../src/baseline.js'

const sandbox = mkdtempSync(join(tmpdir(), 'canship-action-test-'))
after(() => rmSync(sandbox, { recursive: true, force: true }))
const workspace = join(sandbox, 'workspace')
const runner = join(sandbox, 'runner')
mkdirSync(workspace)
mkdirSync(runner)
writeFileSync(join(workspace, 'baseline.json'), '{}')
writeFileSync(join(sandbox, 'outside.json'), '{}')
const finding: Finding = {
  ruleId: 'firebase/open-rules', severity: 'P1', confidence: 'certain', title: 'PRIVATE_TITLE',
  file: 'PRIVATE_FILE.rules', line: 1, excerpt: 'PRIVATE_SOURCE', why: [], fix: [],
}
function result(over: Partial<ScanResult> = {}): ScanResult {
  return { findings: [], filesScanned: 1, durationMs: 0, partial: false, errors: [], skipped: [],
    ignored: [], ignoredFindings: [], ruleSelection: null, vendored: 0, ...over }
}
function report(over: Partial<ScanResult> = {}, version = '0.3.2') {
  return createJsonReport(result(over), {
    version, root: workspace, hiddenLikely: 0, baselineSuppressed: 0, baselineStale: 0,
  })
}
function environment(over: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const outputs = mkdtempSync(join(runner, 'outputs-'))
  return { GITHUB_WORKSPACE: workspace, RUNNER_TEMP: runner,
    GITHUB_OUTPUT: join(outputs, 'output'), GITHUB_STEP_SUMMARY: join(outputs, 'summary'), ...over }
}

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
/** 集成测试使用本地扫描器，不联网安装；样本仅作为读取对象。 */
const sourceDependencies = {
  installScanner: () => join(repository, 'src', 'cli.ts'),
  execute: (command: string, args: string[]) => spawnSync(command, ['--import', 'tsx', ...args], {
    cwd: repository, encoding: 'utf8', timeout: 30_000,
  }),
}
function project(name: string, files: Record<string, string>): string {
  const root = join(workspace, name)
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return root
}
const openRules = 'service cloud.firestore { match /documents/{id} { allow write: if true; } }'

test('the JSON schema version is independent of the package version and keeps completeness and suppression counts', () => {
  const r = report({ partial: true, findings: [finding] }, '0.2.1')
  assert.equal(r.schemaVersion, 1)
  assert.equal(r.version, '0.2.1')
  assert.equal(r.partial, true)
  assert.equal(r.findings.length, 1)
  assert.equal(r.hiddenLikely, 0)
  assert.equal(r.baselineSuppressed, 0)
})

test('JSON does not serialize new internal fields automatically', () => {
  const source = { ...result(), internal: 'PRIVATE_INTERNAL_DATA' }
  const json = createJsonReport(source, {
    version: '0.2.1', root: '.', hiddenLikely: 0, baselineSuppressed: 0, baselineStale: 0,
  })
  assert.doesNotMatch(JSON.stringify(json), /PRIVATE_INTERNAL_DATA|internal/)
})

for (const policy of ['blocking', 'any', 'none']) {
  test(`a complete empty scan passes ${policy}`, () => assert.equal(assessReport(report(), 0, policy).failed, false))
  for (const exit of [1, 2, 3]) {
    test(`an incomplete scan exiting ${exit} is not let through by ${policy}`, () => {
      const findings = exit === 1 ? [finding] : exit === 2 ? [{ ...finding, confidence: 'likely' as const }] : []
      assert.equal(assessReport(report({ partial: true, findings }), exit, policy).failed, true)
    })
  }
}
test('finding policies separate certain blockers, likely findings and report-only', () => {
  assert.equal(assessReport(report({ findings: [finding] }), 1, 'blocking').failed, true)
  assert.equal(assessReport(report({ findings: [finding] }), 1, 'none').failed, false)
  const likely = report({ findings: [{ ...finding, confidence: 'likely' }] })
  assert.equal(assessReport(likely, 2, 'blocking').failed, false)
  assert.equal(assessReport(likely, 2, 'any').failed, true)
  assert.equal(assessReport({ ...report(), hiddenLikely: 1 }, 2, 'any').failed, true)
})
test('published output without schemaVersion is still accepted', () => {
  const { schemaVersion: _, ...legacy } = report({}, '0.2.1')
  assert.equal(assessReport(legacy, 0, 'blocking').failed, false)
})
for (const patch of [
  { schemaVersion: 2 }, { partial: 'false' }, { filesScanned: -1 }, { hiddenLikely: null },
  { findings: {} }, { errors: undefined }, { baselineSuppressed: NaN }, { ruleSelection: {} },
  { findings: [{ ...finding, severity: 'unknown' }] },
]) {
  test(`a corrupt report field is rejected: ${Object.keys(patch)[0]}`, () => {
    assert.throws(() => assessReport({ ...report(), ...patch }, 0, 'blocking'))
  })
}
test('an exit code that contradicts the findings is rejected; tool errors and empty scans always fail', () => {
  assert.throws(() => assessReport(report({ findings: [finding] }), 0, 'none'))
  assert.throws(() => assessReport(report(), 9, 'none'))
  assert.equal(assessReport(report(), 3, 'none').failed, true)
  assert.equal(assessReport(report({ filesScanned: 0 }), 3, 'none').failed, true)
  assert.equal(assessReport(report({ skipped: [{ path: 'large.ts', reason: 'too-large' }] }), 3, 'none').partial, true)
})

for (const version of ['latest', '^0.2.1', '0.2.1 & echo unsafe', 'file:../package', 'https://example.com/pkg.tgz']) {
  test(`a non-exact version is rejected: ${version}`, () => assert.throws(() => parseInputs(environment({ INPUT_VERSION: version }))))
}
test('the Action defaults match the documented defaults and README examples select the package version', () => {
  const packageVersion = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8')).version
  const version = parseInputs(environment()).version
  assert.equal(version, '0.3.2')
  assert.equal(parseInputs(environment({ INPUT_VERSION: '' })).version, version)
  const metadata = readFileSync(join(repository, 'action.yml'), 'utf8')
  const versionInput = /^  version:\r?\n(?:(?: {4}[^\r\n]*|)\r?\n)*/m.exec(metadata)?.[0]
  assert.ok(versionInput, 'missing version input')
  assert.ok(versionInput.includes(`default: '${version}'`), 'the Action config and runtime default versions differ')
  for (const name of ['README.md', 'README-zh-CN.md']) {
    const readme = readFileSync(join(repository, name), 'utf8')
    const workflow = /^```yaml\r?\n([\s\S]*?)^```/m.exec(readme)?.[1]
    assert.ok(workflow, `${name} lacks a workflow example`)
    assert.ok(workflow.includes(`version: '${packageVersion}'`), `${name} example version differs`)
    assert.match(workflow, /^      - uses: Tasomei\/canship@[a-f0-9]{40}\r?$/m)
    assert.ok(readme.includes(`| \`version\` | \`${version}\` |`), `${name} default version differs`)
  }
})
test('an explicit release version accepts only reports from that version', () => {
  const version = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8')).version
  for (const actual of [version, '0.0.0-test']) {
    const execute = () => runAction(environment({ INPUT_VERSION: version }), {
      installScanner: options => {
        assert.equal(options.version, version)
        return 'trusted-cli.js'
      },
      execute: () => ({ status: 0, stdout: JSON.stringify(report({}, actual)) }),
    })
    if (actual === version) assert.equal(execute().failed, false)
    else assert.throws(execute, (error: unknown) => {
      assert.equal(describeActionError(error).stage, 'report')
      return true
    })
  }
})

test('explicitly choosing 0.2.1 still works with the old report format', () => {
  const env = environment({ INPUT_VERSION: '0.2.1' })
  const { schemaVersion: _, ...legacy } = report({}, '0.2.1')
  let installed = false
  const outcome = runAction(env, {
    installScanner: options => {
      assert.equal(options.version, '0.2.1')
      installed = true
      return 'trusted-cli.js'
    },
    execute: () => ({ status: 0, stdout: JSON.stringify(legacy) }),
  })
  assert.equal(installed, true)
  assert.deepEqual(outcome, { findings: 0, blocking: 0, partial: false, failed: false })
})
test('the default install and report must both be 0.3.2; other report versions are rejected', () => {
  let installs = 0
  for (const version of ['0.3.2', '0.3.1']) {
    const execute = () => runAction(environment(), {
      installScanner: options => {
        assert.equal(options.version, '0.3.2')
        installs++
        return 'trusted-cli.js'
      },
      execute: () => ({ status: 0, stdout: JSON.stringify(report({}, version)) }),
    })
    if (version === '0.3.2') assert.equal(execute().failed, false)
    else assert.throws(execute, (error: unknown) => {
      assert.equal(describeActionError(error).stage, 'report')
      return true
    })
  }
  assert.equal(installs, 2)
})
test('config is ignored and upload is off by default; an explicit baseline stays inside the project', () => {
  const options = parseInputs(environment({ INPUT_BASELINE: 'baseline.json' }))
  assert.equal(options.useConfig, false)
  assert.equal(options.uploadSarif, false)
  assert.equal(options.baseline, join(workspace, 'baseline.json'))
})

test('a directory link cannot redirect the scan target outside the checkout', () => {
  const target = join(sandbox, 'outside-directory')
  const link = join(workspace, 'linked-directory')
  mkdirSync(target)
  symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir')
  assert.throws(() => parseInputs(environment({ INPUT_PATH: 'linked-directory' })), /must stay inside/)
})
for (const input of [
  { INPUT_PATH: '..' }, { INPUT_BASELINE: '../outside.json' },
  { INPUT_ONLY: 'api', INPUT_SKIP: 'firebase' }, { INPUT_ONLY: 'api; echo unsafe' },
  { INPUT_USE_CONFIG: 'yes' }, { INPUT_UPLOAD_SARIF: '1' }, { INPUT_FAIL_ON: 'unknown' },
  { INPUT_CATEGORY: 'x\n::error::injected' },
]) {
  test(`an invalid input is rejected: ${Object.keys(input)[0]}`, () => assert.throws(() => parseInputs(environment(input))))
}
test('SARIF URIs from a subdirectory are rooted at the repository and keep their encoding', () => {
  const log = { version: '2.1.0', runs: [{ results: [{ locations: [
    { physicalLocation: { artifactLocation: { uri: 'src/a%20b.ts' } } },
  ] }] }] }
  const rebased = rebaseSarif(log, join('apps', 'web app'))
  assert.equal(rebased.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'apps/web%20app/src/a%20b.ts')
})
for (const uri of ['../outside.ts', '%2e%2e/outside.ts', '/etc/passwd', 'https://example.com/file', 'a%2fb.ts']) {
  test(`a SARIF path outside the repository is rejected: ${uri}`, () => assert.throws(() => rebaseSarif({
    version: '2.1.0', runs: [{ results: [{ locations: [{ physicalLocation: { artifactLocation: { uri } } }] }] }],
  }, '')))
}
test('arguments bypass the shell, and the summary and outputs contain no source or paths', () => {
  const env = environment()
  const assessment = runAction(env, {
    installScanner: () => 'trusted-cli.js',
    execute: (command, args, options) => {
      assert.equal(command, process.execPath)
      assert.deepEqual(args, ['trusted-cli.js', workspace, '--json', '--all', '--no-config'])
      assert.equal(options.shell, undefined)
      return { status: 1, stdout: JSON.stringify(report({ findings: [finding] })) }
    },
  })
  assert.equal(assessment.failed, true)
  const output = readFileSync(env.GITHUB_OUTPUT!, 'utf8')
  const summary = readFileSync(env.GITHUB_STEP_SUMMARY!, 'utf8')
  assert.match(output, /failed=true/)
  assert.doesNotMatch(output + summary, /PRIVATE_|workspace|artifactLocation/)
  assert.doesNotMatch(output, /sarif-file=/)
})
test('a timeout, an abnormal exit or truncated JSON never produces a passing result', () => {
  for (const execution of [
    { error: new Error('PRIVATE_ERROR'), status: null },
    { signal: 'SIGTERM', status: null }, { status: 0, stdout: '{' },
  ]) {
    const env = environment()
    assert.throws(() => runAction(env, { installScanner: () => 'cli.js', execute: () => execution }))
    assert.equal(existsSync(env.GITHUB_OUTPUT!), false)
  }
})
test('the real CLI scans through the Action adapter without running project scripts, with config off by default', () => {
  const root = join(workspace, 'source-app')
  mkdirSync(root)
  writeFileSync(join(root, 'firestore.rules'), 'service cloud.firestore { match /documents/{id} { allow write: if true; } }')
  writeFileSync(join(root, 'canship.config.json'), JSON.stringify({ skip: ['firebase'] }))
  writeFileSync(join(root, 'package.json'), JSON.stringify({ scripts: { preinstall: 'exit 77', test: 'exit 88' } }))
  const env = environment({ INPUT_PATH: 'source-app', INPUT_VERSION: '0.0.0-dev', INPUT_UPLOAD_SARIF: 'true' })
  assert.equal(runAction(env, sourceDependencies).failed, true)
  const output = readFileSync(env.GITHUB_OUTPUT!, 'utf8')
  const sarifFile = /^sarif-file=(.+)$/m.exec(output)![1]!
  const sarif = JSON.parse(readFileSync(sarifFile, 'utf8'))
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'source-app/firestore.rules')
  assert.equal(runAction(environment({ ...env, INPUT_USE_CONFIG: 'true' }), sourceDependencies).findings, 0)
})

test('a baseline suppresses only existing findings; new ones still block and counts are kept', async () => {
  const root = project('baseline-app', { 'firestore.rules': openRules })
  writeFileSync(join(root, 'baseline.json'), serializeBaseline(buildBaseline((await scan(root)).findings)))
  const settings = { INPUT_PATH: 'baseline-app', INPUT_VERSION: '0.0.0-dev', INPUT_BASELINE: 'baseline.json' }
  const accepted = environment(settings)
  assert.equal(runAction(accepted, sourceDependencies).failed, false)
  assert.match(readFileSync(accepted.GITHUB_STEP_SUMMARY!, 'utf8'), /Baseline-suppressed findings \| 1/)
  writeFileSync(join(root, 'storage.rules'), openRules)
  const added = environment(settings)
  const outcome = runAction(added, sourceDependencies)
  assert.equal(outcome.failed, true)
  assert.equal(outcome.findings, 1)
  assert.equal(outcome.blocking, 1)
  assert.match(readFileSync(added.GITHUB_STEP_SUMMARY!, 'utf8'), /Baseline-suppressed findings \| 1/)
})

test('a corrupt baseline fails the report and is not let through by the none policy', () => {
  project('broken-baseline-app', { 'index.ts': 'export const ok = true;', 'baseline.json': '{' })
  const env = environment({ INPUT_PATH: 'broken-baseline-app', INPUT_VERSION: '0.0.0-dev',
    INPUT_BASELINE: 'baseline.json', INPUT_FAIL_ON: 'none' })
  assert.throws(() => runAction(env, sourceDependencies), (error: unknown) => {
    assert.equal(describeActionError(error).stage, 'report')
    return true
  })
  assert.equal(existsSync(env.GITHUB_OUTPUT!), false)
})

test('the none policy still fails a real scan with findings and incomplete coverage', () => {
  project('partial-app', { 'firestore.rules': openRules, 'large.ts': ' '.repeat(2 * 1024 * 1024 + 1) })
  const env = environment({ INPUT_PATH: 'partial-app', INPUT_VERSION: '0.0.0-dev', INPUT_FAIL_ON: 'none' })
  const outcome = runAction(env, sourceDependencies)
  assert.deepEqual(outcome, { findings: 1, blocking: 1, partial: true, failed: true })
  assert.match(readFileSync(env.GITHUB_OUTPUT!, 'utf8'), /exit-code=1/)
  assert.match(readFileSync(env.GITHUB_STEP_SUMMARY!, 'utf8'), /Coverage: \*\*incomplete\*\*/)
})

test('each sub-application produces its own SARIF with encoded repository paths and line numbers', () => {
  const paths: string[] = []
  for (const name of ['apps/first app', 'apps/second app']) {
    project(name, { 'firestore.rules': openRules })
    const env = environment({ INPUT_PATH: name, INPUT_VERSION: '0.0.0-dev', INPUT_UPLOAD_SARIF: 'true',
      INPUT_CATEGORY: name.replaceAll(' ', '-') })
    assert.equal(runAction(env, sourceDependencies).blocking, 1)
    const sarifPath = /^sarif-file=(.+)$/m.exec(readFileSync(env.GITHUB_OUTPUT!, 'utf8'))![1]!
    paths.push(sarifPath)
    const log = JSON.parse(readFileSync(sarifPath, 'utf8'))
    const location = log.runs[0].results[0].locations[0].physicalLocation
    assert.equal(location.artifactLocation.uri, `${name.replaceAll(' ', '%20')}/firestore.rules`)
    assert.equal(location.region.startLine, 1)
  }
  assert.notEqual(paths[0], paths[1])
})

test('diagnostics accept no forged messages or unapproved stage text', () => {
  const error = new ActionError('install')
  error.message = 'PRIVATE_RAW_ERROR'
  for (const value of [error, new Error('PRIVATE_RAW_ERROR'), { stage: 'PRIVATE_STAGE', message: 'PRIVATE_RAW_ERROR' }, new ActionError('PRIVATE_STAGE')]) {
    assert.doesNotMatch(JSON.stringify(describeActionError(value)), /PRIVATE_/)
  }
  assert.equal(describeActionError(error).stage, 'install')
})

test('install, run, report, SARIF and output failures each give a fixed stage diagnostic', () => {
  const executed = { status: 0, stdout: JSON.stringify(report()) }
  const cases = [
    { stage: 'install', env: environment(), dependencies: { installScanner: () => { throw new Error('PRIVATE_INSTALL') } } },
    { stage: 'scan', env: environment(), dependencies: { installScanner: () => 'cli.js', execute: () => ({ status: null, error: new Error('PRIVATE_SCAN') }) } },
    { stage: 'report', env: environment(), dependencies: { installScanner: () => 'cli.js', execute: () => ({ status: 0, stdout: 'PRIVATE_REPORT' }) } },
    { stage: 'sarif', env: environment({ INPUT_UPLOAD_SARIF: 'true' }), dependencies: { installScanner: () => 'cli.js', execute: () => executed } },
    { stage: 'output', env: environment({ GITHUB_OUTPUT: workspace }), dependencies: { installScanner: () => 'cli.js', execute: () => executed } },
  ]
  for (const item of cases) {
    assert.throws(() => runAction(item.env, item.dependencies), (error: unknown) => {
      const diagnostic = describeActionError(error)
      assert.equal(diagnostic.stage, item.stage)
      assert.doesNotMatch(JSON.stringify(diagnostic), /PRIVATE_|workspace|canship-action-test/)
      return true
    })
  }
})

test('an input error at the real Action entry fails and writes a summary without echoing the input', () => {
  const env = environment({ INPUT_VERSION: 'PRIVATE_INVALID_VERSION' })
  const execution = spawnSync(process.execPath, [join(repository, 'action', 'run.mjs')], {
    cwd: repository, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 10_000,
  })
  assert.equal(execution.status, 1)
  assert.match(execution.stderr, /canship \[input\]/)
  const summary = readFileSync(env.GITHUB_STEP_SUMMARY!, 'utf8')
  assert.match(summary, /Status: \*\*failed\*\*/)
  assert.doesNotMatch(execution.stdout + execution.stderr + summary, /PRIVATE_INVALID_VERSION/)
  assert.equal(existsSync(env.GITHUB_OUTPUT!), false)
})
