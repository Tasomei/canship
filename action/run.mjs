/** 隔离安装扫描器；不执行被扫描项目的脚本。 */
import { appendFileSync, mkdtempSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const EXACT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/
const POLICIES = ['blocking', 'any', 'none']
const invalidReport = () => new Error('Invalid or incompatible scanner report.')
const count = value => Number.isSafeInteger(value) && value >= 0
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)

/** 仅公开固定诊断文本，不透传底层异常、输入或子进程日志。 */
const STAGE_MESSAGES = Object.freeze({
  input: 'Invalid inputs or inaccessible paths. Check path, baseline, version, selectors, and boolean inputs.',
  install: 'Scanner installation failed. Check the exact npm version and runner access to registry.npmjs.org.',
  scan: 'The scanner process failed or exceeded its limits. Run the same scan locally to inspect coverage.',
  report: 'The scanner report is invalid or incompatible. Check the version, rule selectors, and project configuration.',
  sarif: 'SARIF preparation failed. No report was marked ready for upload.',
  output: 'Could not write GitHub outputs or the job summary. Check the runner environment.',
  internal: 'An unexpected Action error occurred. No successful completion was confirmed.',
})

export class ActionError extends Error {
  constructor(stage) {
    const key = Object.hasOwn(STAGE_MESSAGES, stage) ? stage : 'internal'
    super(STAGE_MESSAGES[key])
    this.stage = key
  }
}

/** 不信任异常的 message 属性，即使它来自已知错误类型。 */
export function describeActionError(error) {
  const stage = error instanceof ActionError && Object.hasOwn(STAGE_MESSAGES, error.stage) ? error.stage : 'internal'
  return { stage, message: STAGE_MESSAGES[stage] }
}

/** 保留失败阶段，丢弃可能包含敏感内容的原始异常。 */
function inStage(stage, operation) {
  try { return operation() } catch { throw new ActionError(stage) }
}

/** 仅接受明确枚举值，拒绝模糊布尔值。 */
function boolean(value, fallback = 'false') {
  if (!['true', 'false'].includes(value || fallback)) throw new Error('Invalid boolean input.')
  return (value || fallback) === 'true'
}

/** 路径按真实位置校验，拒绝越界及符号链接逃逸。 */
function inside(root, input, directory) {
  if (isAbsolute(input) || /[\r\n\0]/.test(input)) throw new Error('Invalid scan or baseline path.')
  const target = realpathSync(resolve(root, input))
  const rel = relative(root, target)
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new Error('Scan and baseline paths must stay inside their parent directory.')
  }
  const stat = statSync(target)
  if (directory ? !stat.isDirectory() : !stat.isFile()) throw new Error('Invalid path type.')
  return target
}

export function parseInputs(env) {
  const version = env.INPUT_VERSION || '0.3.0'
  if (!EXACT_VERSION.test(version)) throw new Error('version must be an exact npm version.')
  const failOn = env.INPUT_FAIL_ON || 'blocking'
  if (!POLICIES.includes(failOn)) throw new Error('fail-on must be blocking, any, or none.')
  const selectors = name => {
    const value = env[name] || ''
    if (value && !/^[a-z][a-z0-9/-]*(?:,[a-z][a-z0-9/-]*)*$/.test(value)) {
      throw new Error('Invalid rule selector input.')
    }
    return value
  }
  const only = selectors('INPUT_ONLY')
  const skip = selectors('INPUT_SKIP')
  if (only && skip) throw new Error('only and skip are mutually exclusive.')
  const category = env.INPUT_CATEGORY || 'canship'
  if (!/^[a-zA-Z0-9_./-]{1,128}$/.test(category)) throw new Error('Invalid SARIF category.')
  if (!env.GITHUB_WORKSPACE || !env.RUNNER_TEMP) throw new Error('Missing runner directories.')
  const workspace = realpathSync(env.GITHUB_WORKSPACE)
  const root = inside(workspace, env.INPUT_PATH || '.', true)
  const baseline = env.INPUT_BASELINE ? inside(root, env.INPUT_BASELINE, false) : null
  return {
    version, failOn, only, skip, category, workspace, root, baseline,
    temp: realpathSync(env.RUNNER_TEMP),
    useConfig: boolean(env.INPUT_USE_CONFIG),
    uploadSarif: boolean(env.INPUT_UPLOAD_SARIF),
  }
}

/** 同时验证结构与退出码；不允许不完整扫描通过任何结果策略。 */
export function assessReport(report, exitCode, failOn) {
  if (!POLICIES.includes(failOn)) throw new Error('Invalid finding policy.')
  if (!object(report) || ![undefined, 1].includes(report.schemaVersion) ||
      typeof report.version !== 'string' || typeof report.partial !== 'boolean' ||
      ![0, 1, 2, 3].includes(exitCode)) throw invalidReport()
  for (const name of ['findings', 'errors', 'skipped', 'ignored', 'ignoredFindings']) {
    if (!Array.isArray(report[name])) throw invalidReport()
  }
  for (const name of ['filesScanned', 'hiddenLikely', 'baselineSuppressed', 'baselineStale', 'vendored']) {
    if (!count(report[name])) throw invalidReport()
  }
  if (report.ruleSelection !== null && (!object(report.ruleSelection) ||
      !Array.isArray(report.ruleSelection.only) || !Array.isArray(report.ruleSelection.skip) ||
      !count(report.ruleSelection.removed))) throw invalidReport()
  for (const finding of report.findings) {
    if (!object(finding) || !['P0', 'P1', 'P2'].includes(finding.severity) ||
        !['certain', 'likely'].includes(finding.confidence) || typeof finding.ruleId !== 'string') {
      throw invalidReport()
    }
  }
  const blocking = report.findings.filter(f => f.confidence === 'certain' && f.severity !== 'P2').length
  const findings = report.findings.length + report.hiddenLikely
  const partial = report.partial || report.filesScanned === 0 || report.errors.length > 0 || report.skipped.length > 0
  const expectedExit = blocking > 0 ? 1 : findings > 0 ? 2 : partial ? 3 : 0
  // 退出 3 也可能来自报告写入失败，不能按空结果放行。
  if (exitCode !== 3 && exitCode !== expectedExit) throw invalidReport()
  return {
    findings, blocking, partial,
    failed: exitCode === 3 || partial || (failOn === 'blocking' ? blocking > 0 : failOn === 'any' && findings > 0),
  }
}

/** 安装位置与目标仓库隔离；固定包名、版本和 registry，禁用安装脚本。 */
export function installScanner(options, directory) {
  if (!EXACT_VERSION.test(options.version)) throw new Error('Invalid scanner version.')
  const userConfig = join(directory, 'user.npmrc')
  const globalConfig = join(directory, 'global.npmrc')
  writeFileSync(userConfig, '')
  writeFileSync(globalConfig, '')
  // 显式建立安装根目录，防止 npm 向上查找其他项目。
  writeFileSync(join(directory, 'package.json'), '{"name":"canship-action-runner","private":true}\n')
  const env = { ...process.env, NPM_CONFIG_USERCONFIG: userConfig, NPM_CONFIG_GLOBALCONFIG: globalConfig }
  // 移除继承的 npm 配置，避免重定向包来源或启用安装脚本。
  for (const key of Object.keys(env)) {
    if (/^npm_config_/i.test(key) && !['NPM_CONFIG_USERCONFIG', 'NPM_CONFIG_GLOBALCONFIG'].includes(key)) delete env[key]
  }
  // setup-node 的 Windows 发行包将 npm CLI 放在 node.exe 同级目录下。
  const npmEntry = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
  const installed = spawnSync(process.platform === 'win32' ? process.execPath : 'npm', [
    ...(process.platform === 'win32' ? [npmEntry] : []),
    'install', '--no-save', '--package-lock=false', '--ignore-scripts', '--no-audit', '--no-fund',
    '--registry=https://registry.npmjs.org/', `canship@${options.version}`,
  ], {
    cwd: directory, env, encoding: 'utf8', timeout: 180_000, maxBuffer: 4 * 1024 * 1024,
    shell: false, windowsHide: true,
  })
  if (installed.error || installed.status !== 0) throw new Error('Scanner installation failed.')
  const entry = join(directory, 'node_modules', 'canship', 'dist', 'cli.js')
  if (!statSync(entry).isFile()) throw new Error('Scanner entry point is missing.')
  return entry
}

/** 子目录扫描的位置转换为相对仓库路径，供 GitHub 定位。 */
export function rebaseSarif(log, prefix) {
  if (!object(log) || log.version !== '2.1.0' || !Array.isArray(log.runs) || log.runs.length !== 1) {
    throw new Error('Invalid SARIF report.')
  }
  const encodedPrefix = prefix.split(sep).filter(Boolean).map(encodeURIComponent).join('/')
  for (const run of log.runs) {
    if (!Array.isArray(run.results)) throw new Error('Invalid SARIF results.')
    for (const result of run.results) {
      for (const location of result.locations ?? []) {
        const artifact = location.physicalLocation?.artifactLocation
        if (!artifact || typeof artifact.uri !== 'string') throw new Error('Invalid SARIF location.')
        const parts = artifact.uri.split('/').map(decodeURIComponent)
        if (parts.some(part => !part || part === '.' || part === '..' || /[/\\:\r\n\0]/.test(part))) {
          throw new Error('SARIF locations must be relative paths.')
        }
        artifact.uri = [encodedPrefix, artifact.uri].filter(Boolean).join('/')
      }
    }
  }
  return log
}

/** 摘要只写统计，不包含源码、文件路径及发现标题。 */
function summary(report, assessment, options) {
  return [
    '## canship', '',
    `Status: **${assessment.failed ? 'failed' : 'passed'}**. Policy: \`${options.failOn}\`.`, '',
    '| Metric | Count |', '|---|---:|',
    `| Files scanned | ${report.filesScanned} |`,
    `| Findings | ${assessment.findings} |`,
    `| Certain P0/P1 | ${assessment.blocking} |`,
    `| Baseline-suppressed findings | ${report.baselineSuppressed} |`,
    `| Stale baseline entries | ${report.baselineStale} |`,
    `| Ignored files | ${report.ignored.length} |`,
    `| Line-suppressed findings | ${report.ignoredFindings.length} |`,
    `| Excluded third-party paths | ${report.vendored} |`,
    `| Errors / skipped paths | ${report.errors.length} / ${report.skipped.length} |`, '',
    `Coverage: **${assessment.partial ? 'incomplete' : 'complete within the selected scope'}**.`,
    `Rule selection: ${report.ruleSelection === null ? 'all rules' : 'restricted'}. Project configuration: ${options.useConfig ? 'enabled' : 'disabled'}.`,
    'Source ignore markers and built-in exclusions still apply. No findings does not prove security.', '',
  ].join('\n')
}

/** 以独立参数数组调用 CLI，随后输出可供组合 Action 使用的固定字段。 */
export function runAction(env, dependencies = {}) {
  const options = inStage('input', () => {
    if (!env.GITHUB_OUTPUT || !env.GITHUB_STEP_SUMMARY) throw new Error('Missing runner output files.')
    return parseInputs(env)
  })
  const { entry, directory } = inStage('install', () => {
    const directory = mkdtempSync(join(options.temp, 'canship-action-'))
    return { entry: (dependencies.installScanner ?? installScanner)(options, directory), directory }
  })
  const args = [entry, options.root, '--json', '--all']
  if (!options.useConfig) args.push('--no-config')
  if (options.only) args.push(`--only=${options.only}`)
  if (options.skip) args.push(`--skip=${options.skip}`)
  if (options.baseline) args.push(`--baseline=${options.baseline}`)
  const sarif = join(directory, 'canship.sarif')
  if (options.uploadSarif) args.push(`--sarif=${sarif}`)
  const execution = inStage('scan', () => {
    const result = (dependencies.execute ?? spawnSync)(process.execPath, args, {
      cwd: directory, encoding: 'utf8', timeout: 600_000, maxBuffer: 32 * 1024 * 1024, windowsHide: true,
    })
    if (result.error || result.signal || result.status === null) throw new Error('Scanner execution failed.')
    return result
  })
  const { report, assessment } = inStage('report', () => {
    const report = JSON.parse(execution.stdout)
    const assessment = assessReport(report, execution.status, options.failOn)
    if (report.version !== options.version) throw new Error('Scanner version mismatch.')
    return { report, assessment }
  })
  if (options.uploadSarif) inStage('sarif', () => {
    const log = rebaseSarif(JSON.parse(readFileSync(sarif, 'utf8')), relative(options.workspace, options.root))
    writeFileSync(sarif, `${JSON.stringify(log)}\n`)
  })
  const outputs = {
    'exit-code': execution.status, findings: assessment.findings, blocking: assessment.blocking,
    partial: assessment.partial, failed: assessment.failed, 'report-ready': options.uploadSarif,
    ...(options.uploadSarif ? { 'sarif-file': sarif } : {}),
  }
  inStage('output', () => {
    for (const [name, value] of Object.entries(outputs)) {
      if (/[\r\n]/.test(String(value))) throw new Error('Invalid output value.')
      appendFileSync(env.GITHUB_OUTPUT, `${name}=${value}\n`)
    }
    appendFileSync(env.GITHUB_STEP_SUMMARY, summary(report, assessment, options))
  })
  return assessment
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    runAction(process.env)
  } catch (error) {
    // 原始异常和子进程输出可能包含路径或凭据，不写入工作流日志。
    const diagnostic = describeActionError(error)
    process.stderr.write(`::error::canship [${diagnostic.stage}]: ${diagnostic.message}\n`)
    if (process.env.GITHUB_STEP_SUMMARY) {
      try {
        appendFileSync(process.env.GITHUB_STEP_SUMMARY,
          `## canship\n\nStatus: **failed**. Stage: \`${diagnostic.stage}\`.\n\n${diagnostic.message}\n`)
      } catch {
        // 摘要写入失败不覆盖已记录的错误，进程仍返回失败。
      }
    }
    process.exitCode = 1
  }
}
