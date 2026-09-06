/**
 * canship CLI entry point.
 *
 * Exit codes, chosen so this drops straight into CI or a git hook:
 *   0 — nothing found, and the whole project was examined
 *   1 — a confirmed issue serious enough not to ship: severity decides this,
 *       not confidence. A P2 that browsers reject on your behalf is a bug
 *       worth fixing, not a reason to stop a deploy.
 *   2 — findings exist, but none is a certain P0/P1. Lower-confidence details
 *       may still be hidden unless --all is present.
 *   3 — the tool failed, or could not finish: a rule crashed, a file was
 *       unreadable, something was skipped, or there was nothing to scan at
 *       all. "Found nothing" and "checked nothing" must not share an exit
 *       code, or a broken scan passes CI looking exactly like a clean one.
 *       Scanning zero files is the sharpest case of that, and the easiest to
 *       hit: the headline command takes no argument, so the wrong working
 *       directory is the ordinary mistake. --best-effort opts out.
 */

import { isAbsolute, relative as relative_, resolve } from 'node:path'
import { existsSync, realpathSync, statSync, writeFileSync } from 'node:fs'
import { scan, cleanForOutput } from './engine.js'
import { renderReport } from './report/terminal.js'
import { renderFixPrompt } from './report/prompt.js'
import { renderHtml } from './report/html.js'
import { renderSarif } from './report/sarif.js'
import { bold, cyan, dim, red, yellow } from './colors.js'
import { verdictOf } from './report/shared.js'
import {
  applyBaseline,
  buildBaseline,
  readBaseline,
  writeBaseline,
  BaselineError,
  DEFAULT_BASELINE_PATH,
} from './baseline.js'
import { ConfigError, CONFIG_FILENAME, loadConfig } from './config.js'
import { isKnownSelector } from './rules/index.js'

/**
 * Injected from package.json at build time, so the project holds one version
 * number rather than two that agree right up until a release.
 *
 * The fallback covers running from source with tsx, where nothing defines it.
 */
declare const __CANSHIP_VERSION__: string | undefined
const VERSION = typeof __CANSHIP_VERSION__ === 'string' ? __CANSHIP_VERSION__ : '0.0.0-dev'

interface Args {
  root: string
  showAll: boolean
  json: boolean
  fixPrompt: boolean
  /** Path to write the HTML report to, or null when not requested */
  report: string | null
  /** Treat an incomplete scan as acceptable and exit on the findings alone */
  bestEffort: boolean
  /**
   * Baseline to suppress already-accepted findings with, or null.
   *
   * `null` when the flag carried a value the user typed, so it is resolved
   * where they are standing; the bare flag leaves this null and sets the
   * `*Default` flag below, so the path is anchored to the scanned project
   * instead. A baseline belongs to the project, not to the working directory
   * somebody happened to run from — and `--baseline-write` has to put the file
   * where `--baseline` will look for it.
   */
  baseline: string | null
  baselineDefault: boolean
  /** Where to record the current findings as a new baseline, or null */
  baselineWrite: string | null
  baselineWriteDefault: boolean
  /** Rule selectors from --only / --skip; empty when not given */
  only: string[]
  skip: string[]
  /** Path to write a SARIF log to, or null when not requested */
  sarif: string | null
  /**
   * Ignore any canship.config.json in the scanned directory.
   *
   * The recourse for the case canship is built for: pointing it at code you do
   * not control. That file comes out of the tree being examined, so a project
   * can use it to turn off the rules that would report it. Its own maintainers
   * writing it is the intended use and stays the default; this is how someone
   * auditing a dependency, a fork or an unreviewed pull request says no.
   */
  noConfig: boolean
  help: boolean
  version: boolean
}

/** One place to clean the user input inside an argument error, and exit as a tool error */
function argumentError(message: string): never {
  process.stderr.write(`canship: ${cleanForOutput(message)}\n`)
  process.exit(3)
}

/**
 * A flag that may carry a value: `--flag` takes `fallback`, `--flag=value`
 * takes the value, and anything else is not this flag.
 *
 * Written once because there are three of these now. The first was hand-rolled
 * inline, and a second copy of "did the user write `--flag=` with nothing after
 * it" is where one of them eventually accepts the empty string and writes a
 * file named `""` into the project.
 */
function optionalValue(arg: string, name: string, fallback: string): string | null {
  if (arg === name) return fallback
  if (!arg.startsWith(`${name}=`)) return null
  const value = arg.slice(name.length + 1)
  if (!value) argumentError(`${name}= needs a file path`)
  return value
}

/**
 * Resolve a config-supplied path, refusing to leave the project.
 *
 * The path comes out of a file inside the directory being scanned, and that
 * directory is the thing canship is pointed at *because* it is not trusted —
 * config.ts says as much about why the format is JSON. So it is input, not
 * instruction. Without this, a `canship.config.json` in somebody else's
 * repository could aim the baseline read at `../../../../.ssh/config`: the
 * contents never reach the report, but the error message names the path and
 * says whether it parsed, which turns a scan into a file-existence probe.
 *
 * The flag form is deliberately not constrained. A path typed on the command
 * line is the user's own instruction, and a monorepo keeping its baselines in
 * one shared directory is a real thing to want.
 */
function insideProject(root: string, relative: string): string {
  const target = resolve(root, relative)
  // Compared after resolving symlinks. `resolve` is lexical, so a link inside
  // the project pointing out of it reads as an ordinary child and walks
  // straight past a check done on the written path.
  const inside = relative_(realPathOf(root), realPathOf(target))
  if (inside === '' || inside.startsWith('..') || isAbsolute(inside)) {
    argumentError(
      `${CONFIG_FILENAME}: "baseline" must stay inside the project, and ${relative} does not`,
    )
  }
  return target
}

/**
 * The path with every symlink resolved, as far as the filesystem can say.
 *
 * `realpathSync` throws when the path does not exist, which is the ordinary
 * case for a baseline nobody has written yet — so this walks up to the nearest
 * ancestor that does exist and reattaches the rest. Falling back to the lexical
 * path can only make the containment check stricter, never looser.
 */
function realPathOf(path: string): string {
  let at = path
  const rest: string[] = []
  // Bounded because each turn of this loop is a failed filesystem call, and the
  // path can come out of a config file in the tree being scanned: a baseline
  // named `a/a/a/…` two thousand levels deep spent 2.4 seconds here. Deeper
  // than this is not a path anyone meant, and giving up returns the lexical
  // form, which only makes the containment check stricter.
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

/** Comfortably past the deepest real directory tree, and far short of costly */
const MAX_REAL_PATH_DEPTH = 64

/**
 * The fallback for a flag whose bare form is handled before optionalValue sees
 * it. Never returned; named so that reading the call site does not suggest a
 * default this branch is able to produce.
 */
const UNREACHABLE_DEFAULT = ''

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
    help: false,
    version: false,
  }
  const positional: string[] = []

  for (const arg of argv) {
    // Comma-separated and repeatable, so --skip=a,b and --skip a --skip b both
    // work. An empty entry is dropped rather than passed on as a selector that
    // matches nothing and fails validation with a confusing message.
    const list = (name: string): string[] | null => {
      if (!arg.startsWith(`${name}=`)) return null
      const value = arg.slice(name.length + 1)
      if (!value) argumentError(`${name}= needs at least one rule id`)
      return value
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
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
    // The bare form is recorded as "default", not as the literal filename, so
    // main() can anchor it to the scanned project rather than to the working
    // directory. An explicitly typed path stays relative to where it was typed.
    if (arg === '--baseline') {
      args.baselineDefault = true
      continue
    }
    // The bare form is handled above, so only `--baseline=value` reaches here
    // and the fallback is unreachable. Passing one anyway would read as a
    // default this branch can produce, which it cannot.
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
        --fix-prompt  Output instructions to paste into a coding assistant
        --report[=F]  Write a self-contained HTML report (default canship-report.html)
        --json        Output raw JSON (for CI or tooling)
        --best-effort Allow exit 0 for an incomplete scan with no findings;
                      findings still exit 1 or 2
        --baseline[=F]       Hide findings already recorded in F, so only new
                             ones are reported (default ${DEFAULT_BASELINE_PATH})
        --baseline-write[=F] Record the current findings as a new baseline and exit
        --only=IDS    Report only these rules (comma-separated, repeatable)
        --skip=IDS    Report everything except these rules
        --sarif[=F]   Write a SARIF 2.1.0 log for CI code scanning
                      (default canship.sarif)
        --no-config   Ignore canship.config.json in the scanned directory
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
    return process.exit(0)
  }
  if (args.version) {
    process.stdout.write(`${VERSION}\n`)
    return process.exit(0)
  }

  if (args.json && args.fixPrompt) {
    argumentError('--json and --fix-prompt are mutually exclusive')
  }
  // Recording a baseline while another one is suppressing findings would write
  // down only what the old one did not already cover, so the accepted set
  // shrinks every time the pair is run. Refuse rather than pick a meaning.
  if (
    (args.baseline !== null || args.baselineDefault) &&
    (args.baselineWrite !== null || args.baselineWriteDefault)
  ) {
    argumentError('--baseline and --baseline-write are mutually exclusive')
  }

  if (!existsSync(args.root) || !statSync(args.root).isDirectory()) {
    process.stderr.write(`${red('canship:')} not a directory: ${cleanForOutput(args.root)}\n`)
    return process.exit(3)
  }

  // ── Configuration ──
  //
  // Loaded from the directory being scanned, not the working directory: the
  // settings belong to the project under examination, and `npx canship ./app`
  // has to mean the same thing as running it from inside ./app.
  let config
  try {
    config = args.noConfig ? {} : loadConfig(args.root).config
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`${red('canship:')} ${cleanForOutput(err.message)}\n`)
      return process.exit(3)
    }
    throw err
  }

  // A flag always beats the file. The reverse would let a setting committed a
  // year ago quietly override what somebody typed ten seconds ago.
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
  const only = args.only.length > 0 ? args.only : (config.only ?? [])
  const skip = args.skip.length > 0 ? args.skip : (config.skip ?? [])
  if (only.length > 0 && skip.length > 0) {
    argumentError('rule selection cannot use both only and skip')
  }
  const showAll = args.showAll || config.all === true
  // Not `|| config.bestEffort`. Accepting an incomplete scan is the one setting
  // the scanned project may not make on the caller's behalf — see REFUSED_KEYS
  // in config.ts. config.ts rejects the key outright; this line is the second
  // half of the same rule, so that re-adding the field cannot quietly work.
  const bestEffort = args.bestEffort
  // Where a path is resolved from depends on where it came from, and the two
  // answers are different on purpose:
  //
  //   --baseline=x       typed just now, so relative to where you are standing
  //   --baseline         no path given, so the project's own default location
  //   config "baseline"  written inside the project, so relative to the project
  //
  // Resolving the config value against the working directory was a real bug and
  // a quiet one: `npx canship ./app` read `./canship-baseline.json` from the
  // parent, which either failed with a confusing exit 3 or — worse — found a
  // different project's baseline and suppressed findings with it.
  const baselinePath =
    args.baseline !== null
      ? resolve(args.baseline)
      : args.baselineDefault
        ? resolve(args.root, DEFAULT_BASELINE_PATH)
        : config.baseline !== undefined
          ? insideProject(args.root, config.baseline)
          : null

  const scanned = await scan(args.root, { only, skip })

  // ── --baseline-write: record and stop ──
  //
  // Exits 0 on success because it succeeded at what was asked. The findings it
  // just accepted are not a reason to fail the run that accepted them — but
  // they are worth saying out loud, since this is the moment someone decides
  // to stop being told about a live credential.
  if (args.baselineWrite !== null || args.baselineWriteDefault) {
    // Same rule, and it has to be: a bare --baseline-write must put the file
    // where a bare --baseline will go looking for it.
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
      return process.exit(3)
    }
    const accepted = scanned.findings.length
    // The disclosure warning is not optional politeness. This file names the
    // location and nature of problems that are, by definition, still unfixed —
    // and canship deliberately searches gitignored credential files, so those
    // entries can describe a file the repository does not contain. Telling
    // someone to commit that without saying what it publishes would make
    // canship's own output the leak it exists to find.
    process.stdout.write(
      `\n  ${bold('Baseline written to')} ${cyan(cleanForOutput(target))}\n` +
        `  ${dim(`${accepted} ${accepted === 1 ? 'finding is' : 'findings are'} now accepted and will not be reported.`)}\n` +
        `  ${yellow('These problems still exist.')}\n` +
        `  ${dim('The file names the path, rule and title of each one — including findings')}\n` +
        `  ${dim('in files git does not track, such as .env.local. It holds no credential')}\n` +
        `  ${dim('values. Commit it so the decision is reviewable; on a public repository,')}\n` +
        `  ${dim('weigh what that publishes first.')}\n\n`,
    )
    // A baseline recorded from an incomplete scan accepts a state nobody saw
    // in full: the findings that were never produced are absent from the file,
    // so they will arrive later as new. Worth a warning, not a failure.
    if (scanned.partial) {
      process.stderr.write(
        `${yellow('canship:')} the scan was incomplete, so this baseline may be missing findings.\n`,
      )
    }
    // The other way a baseline gets written from a partial view of the project.
    // Findings a disabled rule never produced are absent from the file, so they
    // arrive as "new" the first time somebody runs without the selection —
    // which reads as a regression rather than as a bookkeeping gap.
    if (scanned.ruleSelection !== null) {
      process.stderr.write(
        `${yellow('canship:')} rule selection was in force, so this baseline covers only the rules that ran.\n`,
      )
    }
    return process.exit(0)
  }

  // ── --baseline: suppress what was already accepted ──
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
        return process.exit(3)
      }
      throw err
    }
  }

  // Redacted once, here, because every renderer prints it. The scan itself is
  // still run against the real path — this is only what gets shown.
  const displayRoot = cleanForOutput(args.root)

  const shown = showAll ? result.findings : result.findings.filter((f) => f.confidence === 'certain')
  const hiddenLikely = showAll ? 0 : result.findings.filter((f) => f.confidence === 'likely').length

  if (args.fixPrompt) {
    const prompt = renderFixPrompt(shown, {
      partial: result.partial,
      filesScanned: result.filesScanned,
      hiddenLikely,
    })
    process.stdout.write(
      prompt === null ? 'Nothing to fix — no findings.\n' : `${prompt}\n`,
    )
  } else if (args.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          version: VERSION,
          root: displayRoot,
          filesScanned: result.filesScanned,
          durationMs: result.durationMs,
          // Machine consumers need the same distinction humans get: an empty
          // findings array from a partial scan is not a pass.
          partial: result.partial,
          errors: result.errors,
          skipped: result.skipped,
          ignored: result.ignored,
          ignoredFindings: result.ignoredFindings,
          ruleSelection: result.ruleSelection,
          vendored: result.vendored,
          // The default view hides the detail, never the fact. A machine reading this
          // must not see "no findings" while lower-confidence ones exist.
          hiddenLikely,
          // Same reason, for the other thing that removes findings from this
          // array. A CI job reading `findings: []` is entitled to know whether
          // that means "nothing is wrong" or "a file in your repository says
          // not to mention it".
          baselineSuppressed,
          baselineStale,
          findings: shown,
        },
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
        },
      )}\n`,
    )
  }

  // Like --report, a file written beside whatever went to stdout. The two and
  // the stdout modes all compose: a CI job normally wants SARIF for the pull
  // request and a non-zero exit for the gate, from one run.
  if (args.sarif) {
    const target = resolve(args.sarif)
    try {
      writeFileSync(
        target,
        renderSarif(
          { ...result, findings: shown },
          {
            version: VERSION,
            baselineSuppressed,
            hiddenLikely,
            ruleSelection:
              result.ruleSelection === null
                ? null
                : result.ruleSelection.only.length > 0
                  ? `only ${result.ruleSelection.only.join(', ')}, hiding ${result.ruleSelection.removed}`
                  : `everything except ${result.ruleSelection.skip.join(', ')}, hiding ${result.ruleSelection.removed}`,
          },
        ),
        'utf8',
      )
      if (!args.json && !args.fixPrompt) {
        process.stdout.write(`  ${dim('SARIF written to')} ${cyan(cleanForOutput(target))}\n\n`)
      }
    } catch (err) {
      process.stderr.write(
        `${red('canship:')} could not write SARIF to ${cleanForOutput(target)}\n${cleanForOutput(String(err))}\n`,
      )
      return process.exit(3)
    }
  }

  // The HTML report is written in addition to whatever went to stdout, so
  // `--report` composes with the other output modes.
  if (args.report) {
    const target = resolve(args.report)
    try {
      writeFileSync(
        target,
        renderHtml(
          { ...result, findings: shown },
          {
            root: displayRoot,
            generatedAt: new Date().toISOString(),
            hiddenLikely,
            baselineSuppressed,
            baselineStale,
            baselinePath: baselinePath === null ? null : cleanForOutput(baselinePath),
          },
        ),
        'utf8',
      )
      if (!args.json && !args.fixPrompt) {
        process.stdout.write(`  ${dim('Report written to')} ${cyan(cleanForOutput(target))}\n\n`)
      }
    } catch (err) {
      process.stderr.write(
        `${red('canship:')} could not write report to ${cleanForOutput(target)}\n${cleanForOutput(String(err))}\n`,
      )
      return process.exit(3)
    }
  }

  // Precedence, stated rather than left to the order of these lines: a finding
  // outranks an incomplete scan. Exit 3 means "I could not tell you", and
  // answering "your admin key is in the browser bundle" with that would be a
  // worse misstatement than the imprecision it fixes. Nothing is lost by it —
  // the report prints what went unchecked above the findings either way, and
  // --json carries `partial` next to them, so a machine that needs the
  // distinction has it. Only the single exit code cannot hold both, and the
  // more urgent one wins.
  // The same count the banner uses. Three separate re-derivations of "is this
  // blocking" meant the terminal could say "do not deploy" while the process
  // exited 2; this was the last of them, and the one with teeth.
  if (verdictOf(result.findings).blocking > 0) return process.exit(1)
  if (result.findings.length > 0) return process.exit(2)
  // Nothing was found. Whether that means "clean" depends on whether the scan
  // actually finished.
  if (result.partial && !bestEffort) return process.exit(3)
  return process.exit(0)
}

main().catch((err: unknown) => {
  process.stderr.write(`${red('canship: unexpected error')}\n${cleanForOutput(String(err))}\n`)
  process.exit(3)
})
