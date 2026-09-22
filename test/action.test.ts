/** 验证 CI 契约、输入边界和不完整扫描判定。
 * canship-ignore-file */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { assessReport, parseInputs, rebaseSarif, runAction } from '../action/run.mjs'
import { createJsonReport } from '../src/report/json.js'
import type { Finding, ScanResult } from '../src/types.js'

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
function report(over: Partial<ScanResult> = {}) {
  return createJsonReport(result(over), {
    version: '0.2.1', root: workspace, hiddenLikely: 0, baselineSuppressed: 0, baselineStale: 0,
  })
}
function environment(over: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const outputs = mkdtempSync(join(runner, 'outputs-'))
  return { GITHUB_WORKSPACE: workspace, RUNNER_TEMP: runner,
    GITHUB_OUTPUT: join(outputs, 'output'), GITHUB_STEP_SUMMARY: join(outputs, 'summary'), ...over }
}

test('JSON 结构版本独立于软件包版本，保留完整性和抑制统计', () => {
  const r = report({ partial: true, findings: [finding] })
  assert.equal(r.schemaVersion, 1)
  assert.equal(r.version, '0.2.1')
  assert.equal(r.partial, true)
  assert.equal(r.findings.length, 1)
  assert.equal(r.hiddenLikely, 0)
  assert.equal(r.baselineSuppressed, 0)
})

test('JSON 不自动序列化新增的内部字段', () => {
  const source = { ...result(), internal: 'PRIVATE_INTERNAL_DATA' }
  const json = createJsonReport(source, {
    version: '0.2.1', root: '.', hiddenLikely: 0, baselineSuppressed: 0, baselineStale: 0,
  })
  assert.doesNotMatch(JSON.stringify(json), /PRIVATE_INTERNAL_DATA|internal/)
})

for (const policy of ['blocking', 'any', 'none']) {
  test(`完整空扫描通过 ${policy}`, () => assert.equal(assessReport(report(), 0, policy).failed, false))
  for (const exit of [1, 2, 3]) {
    test(`不完整扫描退出 ${exit} 时不能被 ${policy} 放行`, () => {
      const findings = exit === 1 ? [finding] : exit === 2 ? [{ ...finding, confidence: 'likely' as const }] : []
      assert.equal(assessReport(report({ partial: true, findings }), exit, policy).failed, true)
    })
  }
}
test('结果策略准确区分确定阻断、疑似结果和仅报告', () => {
  assert.equal(assessReport(report({ findings: [finding] }), 1, 'blocking').failed, true)
  assert.equal(assessReport(report({ findings: [finding] }), 1, 'none').failed, false)
  const likely = report({ findings: [{ ...finding, confidence: 'likely' }] })
  assert.equal(assessReport(likely, 2, 'blocking').failed, false)
  assert.equal(assessReport(likely, 2, 'any').failed, true)
  assert.equal(assessReport({ ...report(), hiddenLikely: 1 }, 2, 'any').failed, true)
})
test('兼容已发布的无 schemaVersion 输出', () => {
  const { schemaVersion: _, ...legacy } = report()
  assert.equal(assessReport(legacy, 0, 'blocking').failed, false)
})
for (const patch of [
  { schemaVersion: 2 }, { partial: 'false' }, { filesScanned: -1 }, { hiddenLikely: null },
  { findings: {} }, { errors: undefined }, { baselineSuppressed: NaN }, { ruleSelection: {} },
  { findings: [{ ...finding, severity: 'unknown' }] },
]) {
  test(`拒绝损坏的报告字段 ${Object.keys(patch)[0]}`, () => {
    assert.throws(() => assessReport({ ...report(), ...patch }, 0, 'blocking'))
  })
}
test('拒绝退出码与结果矛盾；工具错误及空扫描始终失败', () => {
  assert.throws(() => assessReport(report({ findings: [finding] }), 0, 'none'))
  assert.throws(() => assessReport(report(), 9, 'none'))
  assert.equal(assessReport(report(), 3, 'none').failed, true)
  assert.equal(assessReport(report({ filesScanned: 0 }), 3, 'none').failed, true)
  assert.equal(assessReport(report({ skipped: [{ path: 'large.ts', reason: 'too-large' }] }), 3, 'none').partial, true)
})

for (const version of ['latest', '^0.2.1', '0.2.1 & echo unsafe', 'file:../package', 'https://example.com/pkg.tgz']) {
  test(`拒绝非固定版本 ${version}`, () => assert.throws(() => parseInputs(environment({ INPUT_VERSION: version }))))
}
test('默认忽略配置和关闭上传，显式基线限定在项目内', () => {
  const options = parseInputs(environment({ INPUT_BASELINE: 'baseline.json' }))
  assert.equal(options.useConfig, false)
  assert.equal(options.uploadSarif, false)
  assert.equal(options.baseline, join(workspace, 'baseline.json'))
})

test('目录链接不能将扫描目标重定向至检出目录之外', () => {
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
  test(`拒绝无效输入 ${Object.keys(input)[0]}`, () => assert.throws(() => parseInputs(environment(input))))
}
test('子目录 SARIF URI 以仓库为根，保留编码', () => {
  const log = { version: '2.1.0', runs: [{ results: [{ locations: [
    { physicalLocation: { artifactLocation: { uri: 'src/a%20b.ts' } } },
  ] }] }] }
  const rebased = rebaseSarif(log, join('apps', 'web app'))
  assert.equal(rebased.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'apps/web%20app/src/a%20b.ts')
})
for (const uri of ['../outside.ts', '%2e%2e/outside.ts', '/etc/passwd', 'https://example.com/file', 'a%2fb.ts']) {
  test(`拒绝非仓库 SARIF 路径 ${uri}`, () => assert.throws(() => rebaseSarif({
    version: '2.1.0', runs: [{ results: [{ locations: [{ physicalLocation: { artifactLocation: { uri } } }] }] }],
  }, '')))
}
test('调用参数不经过 shell，摘要及输出不包含源码或路径', () => {
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
test('超时、异常退出和截断 JSON 均不能产生成功输出', () => {
  for (const execution of [
    { error: new Error('PRIVATE_ERROR'), status: null },
    { signal: 'SIGTERM', status: null }, { status: 0, stdout: '{' },
  ]) {
    const env = environment()
    assert.throws(() => runAction(env, { installScanner: () => 'cli.js', execute: () => execution }))
    assert.equal(existsSync(env.GITHUB_OUTPUT!), false)
  }
})
test('真实 CLI 经 Action 适配器扫描，不执行项目脚本，配置默认关闭', () => {
  const root = join(workspace, 'source-app')
  mkdirSync(root)
  writeFileSync(join(root, 'firestore.rules'), 'service cloud.firestore { match /documents/{id} { allow write: if true; } }')
  writeFileSync(join(root, 'canship.config.json'), JSON.stringify({ skip: ['firebase'] }))
  writeFileSync(join(root, 'package.json'), JSON.stringify({ scripts: { preinstall: 'exit 77', test: 'exit 88' } }))
  const repository = dirname(dirname(fileURLToPath(import.meta.url)))
  const entry = join(repository, 'src', 'cli.ts')
  const dependencies = {
    installScanner: () => entry,
    execute: (command: string, args: string[]) => spawnSync(command, ['--import', 'tsx', ...args], {
      cwd: repository, encoding: 'utf8', timeout: 30_000,
    }),
  }
  const env = environment({ INPUT_PATH: 'source-app', INPUT_VERSION: '0.0.0-dev', INPUT_UPLOAD_SARIF: 'true' })
  assert.equal(runAction(env, dependencies).failed, true)
  const output = readFileSync(env.GITHUB_OUTPUT!, 'utf8')
  const sarifFile = /^sarif-file=(.+)$/m.exec(output)![1]!
  const sarif = JSON.parse(readFileSync(sarifFile, 'utf8'))
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'source-app/firestore.rules')
  assert.equal(runAction(environment({ ...env, INPUT_USE_CONFIG: 'true' }), dependencies).findings, 0)
})
