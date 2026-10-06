/** 命令行入口：解析选项、生成报告并计算退出码。 */

import { isAbsolute, relative as relative_, resolve } from 'node:path'
import { existsSync, realpathSync, statSync } from 'node:fs'
import { writeOutput } from './output.js'
import { scan, cleanForOutput } from './engine.js'
import type { RuleSelection } from './types.js'
import { renderReport } from './report/terminal.js'
import { renderFixPrompt } from './report/prompt.js'
import { renderHtml } from './report/html.js'
import { renderSarif } from './report/sarif.js'
import { createJsonReport } from './report/json.js'
import { bold, cyan, dim, red, yellow } from './colors.js'
import { scanExitCode } from './summary.js'
import { followupArgs } from './report/commands.js'
import {
  applyBaseline,
  buildBaseline,
  migrateBaseline,
  serializeBaseline,
  readBaseline,
  writeBaseline,
  BaselineError,
  DEFAULT_BASELINE_PATH,
} from './baseline.js'
import { ConfigError, CONFIG_FILENAME, loadConfig } from './config.js'
import { isKnownSelector, ruleMatches } from './rules/index.js'
import { RULE_CATALOG, renderRuleCatalog } from './rules/catalog.js'
import { changedFilesSince, changedFileView, ChangeViewError } from './changes.js'
import { canOpen, openReport } from './open.js'

/** 构建时从包信息注入版本；源码运行使用开发版本。 */
declare const __CANSHIP_VERSION__: string | undefined
const VERSION = typeof __CANSHIP_VERSION__ === 'string' ? __CANSHIP_VERSION__ : '0.0.0-dev'

interface Args {
  baselineMigrate: string | null
  root: string
  showAll: boolean
  json: boolean
  fixPrompt: boolean
  /** HTML 报告路径；空值表示不生成。 */
  report: string | null
  /** 允许无发现的不完整扫描退出成功。 */
  bestEffort: boolean
  /** 显式基线路径相对工作目录；裸参数使用扫描目录中的默认文件。 */
  baseline: string | null
  baselineDefault: boolean
  /** 基线写入路径。 */
  baselineWrite: string | null
  baselineWriteDefault: boolean
  /** 命令行规则选择器；未指定时为空。 */
  only: string[]
  skip: string[]
  /** SARIF 输出路径。 */
  sarif: string | null
  /** 忽略目标项目的配置文件，防止其改变扫描范围。 */
  noConfig: boolean
  /** 不遵从目标项目中的忽略标记，防止其隐藏结果；仅限命令行设置。 */
  noIgnoreMarkers: boolean
  help: boolean
  version: boolean
  listRules: boolean
  noExcerpts: boolean
  changedSince: string | null
  /** 终端报告展开每条结果的详情。 */
  verbose: boolean
  /** 生成 HTML 报告后用系统浏览器打开。 */
  open: boolean
}

/** 保留退出码，等待标准输出和错误输出写完后自然结束。 */
function finish(code: number): void {
  process.exitCode = code
}

/** 参数错误由入口统一输出，避免提前终止异步写入。 */
class ArgumentError extends Error {}

/** 清理参数错误并中止当前处理流程。 */
function argumentError(message: string): never {
  throw new ArgumentError(cleanForOutput(message))
}

/** 解析可选参数值，拒绝空路径。 */
function optionalValue(arg: string, name: string, fallback: string): string | null {
  if (arg === name) return fallback
  if (!arg.startsWith(`${name}=`)) return null
  const value = arg.slice(name.length + 1)
  if (!value) argumentError(`${name}= needs a file path`)
  return value
}

/** 配置中的基线路径必须位于扫描目录内。 */
function insideProject(root: string, relative: string): string {
  const target = resolve(root, relative)
  // 解析符号链接后检查边界，避免路径绕过。
  const inside = relative_(realPathOf(root), realPathOf(target))
  if (inside === '' || inside.startsWith('..') || isAbsolute(inside)) {
    argumentError(
      `${CONFIG_FILENAME}: "baseline" must stay inside the project, and ${relative} does not`,
    )
  }
  return target
}

/** 向上查找最近存在的祖先并解析真实路径。 */
function realPathOf(path: string): string {
  let at = path
  const rest: string[] = []
  // 限制祖先查找深度，避免异常路径产生过多系统调用。
  for (let depth = 0; depth < MAX_REAL_PATH_DEPTH; depth++) {
    try {
      const real = realpathSync(at)
      return rest.length === 0 ? real : resolve(real, ...rest)
    } catch {
      const parent = resolve(at, '..')
      if (parent === at) return path
      rest.unshift(relative_(parent, at))
      at = parent
    }
  }
  return path
}

/** 真实路径解析的最大祖先层数。 */
const MAX_REAL_PATH_DEPTH = 64

/** 裸参数已提前处理，此默认值不会返回。 */
const UNREACHABLE_DEFAULT = ''

/** 生成各报告共用的规则选择说明。 */
function selectionPhrase(selection: RuleSelection | null): string | null {
  if (selection === null) return null
  const which =
    selection.only.length > 0
      ? `only ${selection.only.join(', ')}`
      : `everything except ${selection.skip.join(', ')}`
  return `${which}, hiding ${selection.removed}`
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    root: process.cwd(),
    showAll: false,
    json: false,
    fixPrompt: false,
    report: null,
    bestEffort: false,
    baseline: null,
    baselineDefault: false,
    baselineWrite: null,
    baselineWriteDefault: false,
    only: [],
    skip: [],
    sarif: null,
    noConfig: false,
    noIgnoreMarkers: false,
    help: false,
    version: false,
    listRules: false,
    baselineMigrate: null,
    noExcerpts: false,
    changedSince: null,
    verbose: false,
    open: false,
  }
  const positional: string[] = []

  for (const arg of argv) {
    if (arg === '--baseline-migrate' || arg.startsWith('--baseline-migrate=')) {
      const value = arg === '--baseline-migrate' ? DEFAULT_BASELINE_PATH : arg.slice('--baseline-migrate='.length)
      if (!value || args.baselineMigrate !== null) argumentError('--baseline-migrate requires one baseline file')
      args.baselineMigrate = arg === '--baseline-migrate' ? '' : value
      continue
    }
    if (arg.startsWith('--changed-since=')) {
      if (args.changedSince !== null || arg === '--changed-since=') argumentError('--changed-since requires one non-empty reference')
      args.changedSince = arg.slice('--changed-since='.length)
      continue
    }
    // 支持逗号分隔及重复参数；移除空条目。
    const list = (name: string): string[] | null => {
      if (!arg.startsWith(`${name}=`)) return null
      const value = arg.slice(name.length + 1)
      if (!value) argumentError(`${name}= needs at least one rule id`)
      const values = value
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      if (values.length === 0) argumentError(`${name}= needs at least one rule id`)
      return values
    }
    const only = list('--only')
    if (only !== null) {
      args.only.push(...only)
      continue
    }
    const skip = list('--skip')
    if (skip !== null) {
      args.skip.push(...skip)
      continue
    }

    const report = optionalValue(arg, '--report', 'canship-report.html')
    if (report !== null) {
      args.report = report
      continue
    }
    // 裸参数以扫描目录为基准，显式路径以工作目录为基准。
    if (arg === '--baseline') {
      args.baselineDefault = true
      continue
    }
    // 此处仅处理显式基线路径。
    const baseline = optionalValue(arg, '--baseline', UNREACHABLE_DEFAULT)
    if (baseline !== null) {
      args.baseline = baseline
      continue
    }
    if (arg === '--baseline-write') {
      args.baselineWriteDefault = true
      continue
    }
    const baselineWrite = optionalValue(arg, '--baseline-write', UNREACHABLE_DEFAULT)
    if (baselineWrite !== null) {
      args.baselineWrite = baselineWrite
      continue
    }
    const sarif = optionalValue(arg, '--sarif', 'canship.sarif')
    if (sarif !== null) {
      args.sarif = sarif
      continue
    }

    switch (arg) {
      case '--all':
      case '-a':
        args.showAll = true
        break
      case '--json':
        args.json = true
        break
      case '--fix-prompt':
        args.fixPrompt = true
        break
      case '--best-effort':
        args.bestEffort = true
        break
      case '--no-config':
        args.noConfig = true
        break
      case '--no-ignore-markers':
        args.noIgnoreMarkers = true
        break
      case '--list-rules':
        args.listRules = true
        break
      case '--no-excerpts':
        args.noExcerpts = true
        break
      case '--verbose':
        args.verbose = true
        break
      case '--open':
        args.open = true
        break
      case '--help':
      case '-h':
        args.help = true
        break
      case '--version':
      case '-v':
        args.version = true
        break
      default:
        if (arg.startsWith('-')) {
          argumentError(`unknown option ${arg}`)
        }
        positional.push(arg)
    }
  }

  if (positional.length > 1) {
    argumentError(`expected at most one path, received ${positional.length}`)
  }
  if (positional[0]) args.root = resolve(positional[0])
  return args
}

const HELP = `
  ${bold('canship')} — static scanner for exposed credentials and open access rules in JS/TS apps

  ${bold('Usage')}
    npx canship [path]

  ${bold('Options')}
    -a, --all         Show likely findings
        --verbose     Show each finding's excerpt, explanation, trace and fix steps
        --fix-prompt  Output instructions to paste into a coding assistant
        --report[=F]  Write a self-contained HTML report (default canship-report.html)
        --open        With --report, open the report in the default browser
                      (skipped in CI and non-interactive shells)
        --json        Output raw JSON (for CI or tooling)
        --best-effort Allow exit 0 for an incomplete scan with no findings;
                      findings still exit 1 or 2
        --baseline[=F]       Hide findings already recorded in F, so only new
                             ones are reported (default ${DEFAULT_BASELINE_PATH})
        --baseline-write[=F] Record the current findings as a new baseline and exit
        --baseline-migrate[=F] Print an upgraded baseline as JSON; leave F unchanged
        --only=IDS    Run matching rules (comma-separated, repeatable)
        --skip=IDS    Exclude matching rules
        --sarif[=F]   Write a SARIF 2.1.0 log for CI code scanning
                      (default canship.sarif)
        --no-config   Ignore canship.config.json in the scanned directory
        --no-ignore-markers
                      Disregard canship-ignore-file and canship-ignore-next-line
                      markers; use with --no-config for untrusted projects
        --list-rules  List rule IDs, scope, and limits; supports --only/--skip and --json
        --no-excerpts Omit source excerpts from every report; paths and descriptions remain
        --changed-since=REF  Show changed-file findings since the local merge base;
                             scan scope and exit status remain unchanged
    -h, --help        Show this help
    -v, --version     Show version

  ${bold('Exit codes')}
    0  no findings; scan complete, or partial accepted with --best-effort
    1  at least one certain P0/P1 finding
    2  findings exist, but no certain P0/P1 blocker
    3  invalid arguments, tool error, or incomplete scan without --best-effort

  ${dim('--json and --fix-prompt are alternative stdout modes; --report may be combined with either.')}

  ${dim('A baseline hides real findings. Every output says how many it hid.')}

  ${dim(`Settings may also be committed to ${CONFIG_FILENAME}. A flag always wins over the file.`)}

  ${dim('Scanned files stay local: no project-code execution, network requests, or uploads.')}
`

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2))

  if (args.help) {
    process.stdout.write(`${HELP}\n`)
    return finish(0)
  }
  if (args.version) {
    process.stdout.write(`${VERSION}\n`)
    return finish(0)
  }

  if (args.listRules) {
    if (process.argv.slice(2).some(arg => arg !== '--list-rules' && arg !== '--json' && !/^--(?:only|skip)=/.test(arg))) {
      argumentError('--list-rules only supports --only, --skip, and --json; scan options and paths cannot be combined with it')
    }
    // 目录查询不读取项目配置，但选择器仍须校验，避免拼写错误返回空目录。
    for (const selector of [...args.only, ...args.skip]) {
      if (!isKnownSelector(selector)) argumentError(`unknown rule selector: ${selector}`)
    }
    if (args.only.length > 0 && args.skip.length > 0) argumentError('rule selection cannot use both only and skip')
    const rules = RULE_CATALOG.filter(rule =>
      (args.only.length === 0 || args.only.some(selector => ruleMatches(selector, rule.id))) &&
      !args.skip.some(selector => ruleMatches(selector, rule.id)))
    process.stdout.write(args.json
      ? `${JSON.stringify({ schemaVersion: 1, kind: 'rule-catalog', version: VERSION, rules }, null, 2)}\n`
      : renderRuleCatalog(rules))
    return
  }

  if (args.json && args.fixPrompt) {
    argumentError('--json and --fix-prompt are mutually exclusive')
  }
  if (args.baselineMigrate !== null && (args.baseline !== null || args.baselineDefault || args.baselineWrite !== null || args.baselineWriteDefault ||
      args.report !== null || args.sarif !== null || args.json || args.fixPrompt || args.open || args.changedSince !== null || args.bestEffort || args.only.length || args.skip.length)) {
    argumentError('--baseline-migrate cannot be combined with baseline, output, view, best-effort, or rule-selection options')
  }
  // 读取和写入基线互斥，避免将已抑制的结果遗漏出新基线。
  if (
    (args.baseline !== null || args.baselineDefault) &&
    (args.baselineWrite !== null || args.baselineWriteDefault)
  ) {
    argumentError('--baseline and --baseline-write are mutually exclusive')
  }

  if (!existsSync(args.root) || !statSync(args.root).isDirectory()) {
    process.stderr.write(`${red('canship:')} not a directory: ${cleanForOutput(args.root)}\n`)
    return finish(3)
  }
  if (args.open && args.report === null) argumentError('--open requires --report')
  if (args.changedSince !== null && (args.baselineWrite !== null || args.baselineWriteDefault)) {
    argumentError('--changed-since cannot be combined with --baseline-write')
  }
  const changed = args.changedSince === null ? null : changedFilesSince(args.root, args.changedSince)

  // 从扫描目录加载配置。
  let config
  try {
    config = args.noConfig ? {} : loadConfig(args.root).config
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`${red('canship:')} ${cleanForOutput(err.message)}\n`)
      return finish(3)
    }
    throw err
  }

  // 命令行参数优先于配置文件。
  for (const [field, values] of [
    ['--only', args.only],
    ['--skip', args.skip],
  ] as const) {
    for (const selector of values) {
      if (!isKnownSelector(selector)) {
        argumentError(`${field} names no known rule: ${selector}`)
      }
    }
  }
  // only/skip 是一组互斥选择，命令行覆盖整组配置。
  const cliSelection = args.only.length > 0 || args.skip.length > 0
  const only = cliSelection ? args.only : (config.only ?? [])
  const skip = cliSelection ? args.skip : (config.skip ?? [])
  if (only.length > 0 && skip.length > 0) {
    argumentError('rule selection cannot use both only and skip')
  }
  const showAll = args.showAll || config.all === true
  // 仅调用方可通过命令行接受不完整扫描。
  const bestEffort = args.bestEffort
  // 显式路径相对工作目录；默认路径和配置路径相对扫描目录。
  const baselinePath =
    args.baseline !== null
      ? resolve(args.baseline)
      : args.baselineDefault
        ? resolve(args.root, DEFAULT_BASELINE_PATH)
        : config.baseline !== undefined
          ? insideProject(args.root, config.baseline)
          : null

  const scanned = await scan(args.root, { only, skip, honorIgnoreMarkers: !args.noIgnoreMarkers })

  if (args.baselineMigrate !== null) {
    if (scanned.partial || scanned.ruleSelection !== null) throw new BaselineError('Migration requires a complete scan without rule selection. No baseline was changed.')
    const source = args.baselineMigrate === '' ? resolve(args.root, DEFAULT_BASELINE_PATH) : resolve(args.baselineMigrate)
    const migrated = migrateBaseline(scanned.findings, readBaseline(source))
    process.stdout.write(serializeBaseline(migrated))
    const accepted = migrated.entries.reduce((total, entry) => total + entry.count, 0)
    process.stderr.write(`canship: migrated ${accepted} accepted findings; ${scanned.findings.length - accepted} current findings remain unaccepted. Source baseline unchanged.\n`)
    return finish(0)
  }

  // 写入基线后结束；成功表示记录完成，不表示问题已修复。
  if (args.baselineWrite !== null || args.baselineWriteDefault) {
    // 默认写入位置与默认读取位置一致。
    const target =
      args.baselineWrite !== null
        ? resolve(args.baselineWrite)
        : resolve(args.root, DEFAULT_BASELINE_PATH)
    const baseline = buildBaseline(scanned.findings)
    try {
      writeBaseline(target, baseline)
    } catch (err) {
      process.stderr.write(
        `${red('canship:')} could not write baseline to ${cleanForOutput(target)}\n${cleanForOutput(String(err))}\n`,
      )
      return finish(3)
    }
    const accepted = scanned.findings.length
    // 基线仍披露未修复问题的位置和类型，写入时提示审阅。
    process.stdout.write(
      `\n  ${bold('Baseline written to')} ${cyan(cleanForOutput(target))}\n` +
        `  ${dim(`${accepted} ${accepted === 1 ? 'finding is' : 'findings are'} now accepted and will not be reported.`)}\n` +
        `  ${yellow('These problems still exist.')}\n` +
        `  ${dim('The file names the path, rule and title of each one — including findings')}\n` +
        `  ${dim('in files git does not track, such as .env.local. It holds no credential')}\n` +
        `  ${dim('values. Commit it so the decision is reviewable; on a public repository,')}\n` +
        `  ${dim('weigh what that publishes first.')}\n\n`,
    )
    // 不完整扫描可能遗漏基线条目，必须提示。
    if (scanned.partial) {
      process.stderr.write(
        `${yellow('canship:')} the scan was incomplete, so this baseline may be missing findings.\n`,
      )
    }
    // 选择性扫描生成的基线仅覆盖本次执行的规则。
    if (scanned.ruleSelection !== null) {
      process.stderr.write(
        `${yellow('canship:')} rule selection was in force, so this baseline covers only the rules that ran.\n`,
      )
    }
    return finish(0)
  }

  // 应用基线并统计抑制数量。
  let baselineSuppressed = 0
  let baselineStale = 0
  let result = scanned
  if (baselinePath !== null) {
    const source = baselinePath
    try {
      const applied = applyBaseline(scanned.findings, readBaseline(source))
      result = { ...scanned, findings: applied.kept }
      baselineSuppressed = applied.suppressed
      baselineStale = applied.stale
    } catch (err) {
      if (err instanceof BaselineError) {
        process.stderr.write(`${red('canship:')} ${cleanForOutput(err.message)}\n`)
        return finish(3)
      }
      throw err
    }
  }

  // 仅清理展示路径，扫描仍使用原始路径。
  const displayRoot = cleanForOutput(args.root)

  // 基线计算完成后统一移除摘录，不改变结果身份、置信度或退出码。
  if (args.noExcerpts) result = { ...result, findings: result.findings.map(finding => ({ ...finding, excerpt: null })) }

  const fullResult = result
  if (changed) result = changedFileView(result, changed)
  const shown = showAll ? result.findings : result.findings.filter((f) => f.confidence === 'certain')
  const hiddenLikely = showAll ? 0 : result.findings.filter((f) => f.confidence === 'likely').length
  // 严重确定结果优先，其次为其他结果，最后判断完整性；报告写入失败时另行退出 3。
  const exitCode = scanExitCode(fullResult, bestEffort)

  if (args.fixPrompt) {
    const prompt = renderFixPrompt(shown, {
      ...(result.changeView ? { changeView: result.changeView } : {}),
      partial: result.partial,
      filesScanned: result.filesScanned,
      hiddenLikely,
      baselineSuppressed,
      silenced: result.ignoredFindings.map((f) => `${f.file}:${f.line} (${f.ruleId})`),
      ignoredFiles: result.ignored,
      ruleSelection: selectionPhrase(result.ruleSelection),
    })
    process.stdout.write(
      prompt === null ? 'Nothing to fix — no findings.\n' : `${prompt}\n`,
    )
  } else if (args.json) {
    process.stdout.write(
      `${JSON.stringify(
        createJsonReport({ ...result, findings: shown }, {
          version: VERSION,
          root: displayRoot,
          hiddenLikely,
          baselineSuppressed,
          baselineStale,
          excerptsOmitted: args.noExcerpts,
        }),
        null,
        2,
      )}\n`,
    )
  } else {
    process.stdout.write(
      `${renderReport(
        { ...result, findings: shown },
        {
          root: displayRoot,
          showingLikely: showAll,
          hiddenLikely,
          baselineSuppressed,
          baselineStale,
          baselinePath: baselinePath === null ? null : cleanForOutput(baselinePath),
          verbose: args.verbose,
          version: VERSION,
          exitCode,
          rerunArgs: followupArgs(process.argv.slice(2)),
        },
      )}\n`,
    )
  }

  // SARIF 文件可与标准输出模式组合。
  if (args.sarif) {
    const target = resolve(args.sarif)
    try {
      writeOutput(
        target,
        renderSarif(
          { ...result, findings: shown },
          {
            version: VERSION,
            baselineSuppressed,
            hiddenLikely,
            ruleSelection: selectionPhrase(result.ruleSelection),
          },
        ),
        'sarif',
      )
      if (!args.json && !args.fixPrompt) {
        process.stdout.write(`SARIF written to ${cleanForOutput(target)}\n`)
      }
    } catch (err) {
      process.stderr.write(
        `${red('canship:')} could not write SARIF to ${cleanForOutput(target)}\n${cleanForOutput(String(err))}\n`,
      )
      return finish(3)
    }
  }

  // HTML 报告独立写入文件。
  if (args.report) {
    const target = resolve(args.report)
    try {
      writeOutput(
        target,
        renderHtml(
          { ...result, findings: shown },
          {
            root: displayRoot,
            generatedAt: new Date().toISOString(),
            version: VERSION,
            hiddenLikely,
            baselineSuppressed,
            baselineStale,
            baselinePath: baselinePath === null ? null : cleanForOutput(baselinePath),
          },
        ),
        'html',
      )
      if (!args.json && !args.fixPrompt) {
        process.stdout.write(`Report written to ${cleanForOutput(target)}\n`)
      }
      // 提示写入标准错误，避免破坏 JSON 或修复指令输出。
      if (args.open) {
        if (canOpen(process.env, process.stdout.isTTY === true)) {
          openReport(target, message => process.stderr.write(`canship: ${cleanForOutput(message)}\n`), { root: args.root })
        } else {
          process.stderr.write('canship: not opening the report in CI or a non-interactive session\n')
        }
      }
    } catch (err) {
      process.stderr.write(
        `${red('canship:')} could not write report to ${cleanForOutput(target)}\n${cleanForOutput(String(err))}\n`,
      )
      return finish(3)
    }
  }

  return finish(exitCode)
}

main().catch((err: unknown) => {
  if (err instanceof ArgumentError || err instanceof ChangeViewError || err instanceof BaselineError) process.stderr.write(`canship: ${cleanForOutput(err.message)}\n`)
  else process.stderr.write(`${red('canship: unexpected error')}\n${cleanForOutput(String(err))}\n`)
  finish(3)
})
